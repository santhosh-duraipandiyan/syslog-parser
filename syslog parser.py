#!/usr/bin/env python3
"""
syslog_parser.py — A Python syslog parser for blue team learning.

Supports:
  - RFC 3164  (legacy BSD syslog — most Linux + network gear)
  - RFC 5424  (modern structured syslog — systemd, rsyslog)
  - Linux     /var/log/auth.log  (SSH, PAM, sudo events)
  - Linux     /var/log/kern.log  (kernel / iptables)
  - Cisco IOS (router/switch mnemonics)
  - Cisco ASA (firewall connection logs)
  - Palo Alto (CSV TRAFFIC / THREAT logs)
  - AWS VPC   (flow logs forwarded via syslog)

Usage:
  python3 syslog_parser.py sample.log
  python3 syslog_parser.py sample.log --format json
  python3 syslog_parser.py sample.log --format csv
  python3 syslog_parser.py sample.log --alerts
  cat /var/log/auth.log | python3 syslog_parser.py -
"""

import re
import sys
import json
import csv
import io
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


# ─── Syslog constants ─────────────────────────────────────────────────────────

FACILITIES = {
    0: "kern",     1: "user",     2: "mail",     3: "daemon",
    4: "auth",     5: "syslog",   6: "lpr",      7: "news",
    8: "uucp",     9: "cron",    10: "authpriv", 11: "ftp",
   16: "local0",  17: "local1",  18: "local2",  19: "local3",
   20: "local4",  21: "local5",  22: "local6",  23: "local7",
}

SEVERITIES = {
    0: "emergency", 1: "alert",   2: "critical", 3: "error",
    4: "warning",   5: "notice",  6: "info",     7: "debug",
}

# ─── Parsed log dataclass ─────────────────────────────────────────────────────

@dataclass
class ParsedLog:
    raw: str                          # original line
    format: str = "unknown"           # rfc3164 | rfc5424 | linux_auth | linux_kern
                                      # cisco_ios | cisco_asa | paloalto | aws_vpc
    timestamp: Optional[str] = None   # ISO-8601 UTC string
    hostname: Optional[str] = None
    app: Optional[str] = None
    pid: Optional[str] = None
    facility: Optional[str] = None
    severity: Optional[str] = None
    severity_num: Optional[int] = None
    message: Optional[str] = None

    # Extended fields — populated per-format
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    username: Optional[str] = None
    action: Optional[str] = None
    protocol: Optional[str] = None
    event_id: Optional[str] = None    # Windows EventID or Cisco MSGID
    structured_data: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d.pop("raw", None)
        return {k: v for k, v in d.items() if v not in (None, {}, [])}


# ─── PRI decoder ──────────────────────────────────────────────────────────────

def decode_pri(pri_val: int):
    """
    The PRI (Priority) field encodes both facility and severity.
    Formula:  PRI = (facility * 8) + severity
    Reverse:  facility = PRI // 8    severity = PRI % 8
    """
    facility_num = pri_val >> 3          # same as // 8
    severity_num = pri_val & 0x07        # same as % 8
    facility = FACILITIES.get(facility_num, f"local{facility_num}")
    severity = SEVERITIES.get(severity_num, str(severity_num))
    return facility, severity, severity_num


# ─── Timestamp normalisation ───────────────────────────────────────────────────

# BSD-style: "Oct 11 22:14:15" — no year, no timezone
_BSD_TS = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
)

# Cisco ASA: "Oct 11 2024 22:14:15"
_ASA_TS = re.compile(
    r'^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+'
    r'(?P<day>\d{1,2})\s+(?P<year>\d{4})\s+(?P<time>\d{2}:\d{2}:\d{2})'
)

# Palo Alto: "2024/10/11 22:14:15"
_PAN_TS = re.compile(r'(?P<year>\d{4})/(?P<mon>\d{2})/(?P<day>\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})')

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

def normalise_bsd_ts(s: str) -> Optional[str]:
    m = _BSD_TS.match(s.strip())
    if not m:
        return None
    year = datetime.now().year
    mon  = MONTH_MAP[m.group("mon")]
    day  = int(m.group("day"))
    h, mi, sec = map(int, m.group("time").split(":"))
    try:
        dt = datetime(year, mon, day, h, mi, sec, tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return None

def normalise_asa_ts(s: str) -> Optional[str]:
    m = _ASA_TS.match(s.strip())
    if not m:
        return None
    mon  = MONTH_MAP[m.group("mon")]
    day  = int(m.group("day"))
    year = int(m.group("year"))
    h, mi, sec = map(int, m.group("time").split(":"))
    try:
        dt = datetime(year, mon, day, h, mi, sec, tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return None

def normalise_iso_ts(s: str) -> Optional[str]:
    """Handle ISO-8601 variants: with Z, +00:00, .milliseconds etc."""
    s = s.strip().rstrip("Z") + "+00:00"
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f+00:00", "%Y-%m-%dT%H:%M:%S+00:00"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass
    return None


# ─── Format detectors & parsers ───────────────────────────────────────────────

# RFC 3164 pattern:  <PRI>Mon DD HH:MM:SS host app[pid]: msg
_RFC3164 = re.compile(
    r'^<(?P<pri>\d+)>'
    r'(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<msg>.*)'
)

# RFC 5424 pattern:  <PRI>1 ISO-TS host app pid msgid [SD] msg
_RFC5424 = re.compile(
    r'^<(?P<pri>\d+)>1\s+'
    r'(?P<ts>\S+)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>\S+)\s+'
    r'(?P<pid>\S+)\s+'
    r'(?P<msgid>\S+)\s+'
    r'(?P<sd>(?:\[.*?\]|-)+)\s*'
    r'(?P<msg>.*)'
)

# Linux auth.log (no PRI): Mon DD HH:MM:SS host app[pid]: msg
_LINUX_AUTH = re.compile(
    r'^(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<app>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<msg>.*)'
)

# Linux kern.log: timestamp host kernel: [uptime] msg (often same shape as auth)
# Cisco IOS:  <PRI>timestamp host %FACILITY-SEV-MNEMONIC: msg
_CISCO_IOS = re.compile(
    r'^<(?P<pri>\d+)>'
    r'(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<mnemonic>%[A-Z0-9_]+-\d-[A-Z0-9_]+):\s*'
    r'(?P<msg>.*)'
)

# Cisco ASA:  <PRI>Mon DD YYYY HH:MM:SS host : %ASA-sev-MSGID: msg
_CISCO_ASA = re.compile(
    r'^<(?P<pri>\d+)>'
    r'(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+:\s+'
    r'(?P<mnemonic>%ASA-\d-\d+):\s*'
    r'(?P<msg>.*)'
)

# Palo Alto CSV body: starts with <PRI>timestamp host 1,timestamp,serial,...
_PAN_PREFIX = re.compile(
    r'^<(?P<pri>\d+)>'
    r'(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'1,(?P<csv>.*)'
)

# AWS VPC Flow Log via syslog
_AWS_VPC = re.compile(
    r'^<(?P<pri>\d+)>'
    r'(?P<ts>\S+T\S+)\s+'           # ISO timestamp
    r'(?P<host>\S+)\s+'
    r'(?P<app>vpc-flowlog):\s+'
    r'(?P<fields>.*)'
)

# ─── Sub-parsers for message bodies ───────────────────────────────────────────

def parse_ssh_message(msg: str, log: ParsedLog):
    """Extract username and IP from SSH auth messages."""
    # Failed password for alice from 1.2.3.4 port 22 ssh2
    m = re.search(r'(?:for|from user)\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)', msg)
    if m:
        log.username = m.group("user")
        log.src_ip   = m.group("ip")
        log.src_port = int(m.group("port"))
    if "Failed" in msg or "failure" in msg.lower():
        log.action = "auth_failed"
    elif "Accepted" in msg or "success" in msg.lower():
        log.action = "auth_success"

def parse_sudo_message(msg: str, log: ParsedLog):
    """Extract sudo invocation details."""
    # alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
    m = re.search(r'(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)', msg)
    if m:
        log.username = m.group("user")
        log.extra["sudo_target"] = m.group("target")
        log.extra["sudo_cmd"]    = m.group("cmd").strip()

def parse_iptables_message(msg: str, log: ParsedLog):
    """Parse iptables kernel log key=value pairs."""
    fields = dict(re.findall(r'(\w+)=([\S]+)', msg))
    if "SRC" in fields:
        log.src_ip = fields["SRC"]
    if "DST" in fields:
        log.dst_ip = fields["DST"]
    if "SPT" in fields:
        log.src_port = int(fields["SPT"])
    if "DPT" in fields:
        log.dst_port = int(fields["DPT"])
    if "PROTO" in fields:
        log.protocol = fields["PROTO"]
    if "IN" in fields:
        log.extra["iface_in"] = fields["IN"]

def parse_windows_message(msg: str, log: ParsedLog):
    """Extract EventID and key fields from Windows syslog bridge format."""
    m = re.search(r'EventID=(\d+)', msg)
    if m:
        log.event_id = m.group(1)
    m = re.search(r'AccountName=(\S+)', msg)
    if m:
        log.username = m.group(1)
    m = re.search(r'IpAddress=([\d.]+)', msg)
    if m:
        log.src_ip = m.group(1)

def parse_cisco_asa_message(msg: str, log: ParsedLog):
    """
    Parse Cisco ASA connection messages.
    Example: Built outbound TCP connection 12345 for outside:8.8.8.8/443 to inside:10.0.0.5/55421
    """
    m = re.search(
        r'(?:Built|Teardown)\s+(?P<dir>inbound|outbound)\s+(?P<proto>\w+)\s+connection'
        r'\s+\d+\s+for\s+\S+:(?P<dst>[\d.]+)/(?P<dport>\d+).*?to\s+\S+:(?P<src>[\d.]+)/(?P<sport>\d+)',
        msg, re.IGNORECASE
    )
    if m:
        log.src_ip   = m.group("src")
        log.dst_ip   = m.group("dst")
        log.src_port = int(m.group("sport"))
        log.dst_port = int(m.group("dport"))
        log.protocol = m.group("proto").upper()
        log.action   = "Built" if "Built" in msg else "Teardown"

def parse_rfc5424_sd(sd_str: str) -> dict:
    """
    Parse RFC 5424 structured data block.
    Format:  [SD-ID param1="val1" param2="val2"][SD-ID2 ...]
    """
    result = {}
    for block in re.finditer(r'\[(\S+)((?:\s+\w+="[^"]*")*)\]', sd_str):
        sd_id = block.group(1)
        params = dict(re.findall(r'(\w+)="([^"]*)"', block.group(2)))
        result[sd_id] = params
    return result

# Palo Alto TRAFFIC field positions (0-indexed, from PAN-OS docs)
PAN_TRAFFIC_FIELDS = [
    "future_use", "receive_time", "serial_number", "type", "threat_content_type",
    "future_use2", "generated_time", "src_ip", "dst_ip", "nat_src_ip", "nat_dst_ip",
    "rule_name", "src_user", "dst_user", "app", "vsys", "src_zone", "dst_zone",
    "inbound_if", "outbound_if", "log_forwarding", "future_use3", "session_id",
    "repeat_count", "src_port", "dst_port", "nat_src_port", "nat_dst_port", "flags",
    "protocol", "action",
]

def parse_paloalto_csv(csv_str: str, log: ParsedLog):
    """Parse Palo Alto CSV body using positional field mapping."""
    reader = csv.reader(io.StringIO(csv_str))
    try:
        row = next(reader)
    except StopIteration:
        return
    for i, field_name in enumerate(PAN_TRAFFIC_FIELDS):
        if i < len(row):
            val = row[i].strip()
            if field_name == "src_ip":
                log.src_ip = val
            elif field_name == "dst_ip":
                log.dst_ip = val
            elif field_name == "src_port" and val.isdigit():
                log.src_port = int(val)
            elif field_name == "dst_port" and val.isdigit():
                log.dst_port = int(val)
            elif field_name == "protocol":
                log.protocol = val
            elif field_name == "action":
                log.action = val
            elif field_name == "app":
                log.extra["pan_app"] = val
            elif field_name == "rule_name":
                log.extra["rule"] = val
            elif field_name == "type":
                log.extra["pan_type"] = val

def parse_aws_vpc(fields_str: str, log: ParsedLog):
    """
    Parse AWS VPC Flow Log fields (space-delimited, positional).
    Fields: version account-id interface-id srcaddr dstaddr srcport dstport
            protocol packets bytes start end action log-status
    """
    parts = fields_str.split()
    if len(parts) >= 14:
        log.src_ip   = parts[3]
        log.dst_ip   = parts[4]
        log.src_port = int(parts[5]) if parts[5].isdigit() else None
        log.dst_port = int(parts[6]) if parts[6].isdigit() else None
        proto_map    = {"6": "TCP", "17": "UDP", "1": "ICMP"}
        log.protocol = proto_map.get(parts[7], parts[7])
        log.action   = parts[12]
        log.extra["packets"]    = parts[8]
        log.extra["bytes"]      = parts[9]
        log.extra["interface"]  = parts[2]


# ─── Main parser dispatcher ───────────────────────────────────────────────────

def parse_line(raw_line: str) -> ParsedLog:
    """
    Detect the format of a syslog line and dispatch to the right parser.
    Returns a ParsedLog with all extractable fields populated.
    """
    line = raw_line.strip()
    log  = ParsedLog(raw=line)

    # ── Try each format in priority order ─────────────────────────────────

    # 1. AWS VPC Flow Log (ISO timestamp + "vpc-flowlog" app marker)
    m = _AWS_VPC.match(line)
    if m:
        log.format   = "aws_vpc"
        pri          = int(m.group("pri"))
        log.facility, log.severity, log.severity_num = decode_pri(pri)
        log.timestamp = normalise_iso_ts(m.group("ts"))
        log.hostname  = m.group("host")
        log.app       = "vpc-flowlog"
        parse_aws_vpc(m.group("fields"), log)
        return log

    # 2. Cisco ASA (has year in timestamp and %ASA mnemonic)
    m = _CISCO_ASA.match(line)
    if m:
        log.format   = "cisco_asa"
        pri          = int(m.group("pri"))
        log.facility, log.severity, log.severity_num = decode_pri(pri)
        log.timestamp = normalise_asa_ts(m.group("ts"))
        log.hostname  = m.group("host")
        log.event_id  = m.group("mnemonic")
        log.message   = m.group("msg")
        log.app       = "ASA"
        parse_cisco_asa_message(log.message, log)
        return log

    # 3. Cisco IOS (%FACILITY-SEV-MNEMONIC pattern)
    m = _CISCO_IOS.match(line)
    if m:
        log.format   = "cisco_ios"
        pri          = int(m.group("pri"))
        log.facility, log.severity, log.severity_num = decode_pri(pri)
        log.timestamp = normalise_bsd_ts(m.group("ts"))
        log.hostname  = m.group("host")
        mnemonic      = m.group("mnemonic")   # e.g. %SEC_LOGIN-5-LOGIN_SUCCESS
        parts         = mnemonic.lstrip("%").split("-")
        if len(parts) >= 3:
            log.app      = parts[0]
            log.event_id = "-".join(parts[2:])
        log.message = m.group("msg")
        return log

    # 4. Palo Alto CSV (has "1," continuation after host)
    m = _PAN_PREFIX.match(line)
    if m:
        log.format   = "paloalto"
        pri          = int(m.group("pri"))
        log.facility, log.severity, log.severity_num = decode_pri(pri)
        log.timestamp = normalise_bsd_ts(m.group("ts"))
        log.hostname  = m.group("host")
        log.app       = "PAN-OS"
        parse_paloalto_csv(m.group("csv"), log)
        return log

    # 5. RFC 5424 (has "1" version field after PRI)
    m = _RFC5424.match(line)
    if m:
        log.format   = "rfc5424"
        pri          = int(m.group("pri"))
        log.facility, log.severity, log.severity_num = decode_pri(pri)
        log.timestamp = normalise_iso_ts(m.group("ts"))
        log.hostname  = m.group("host") if m.group("host") != "-" else None
        log.app       = m.group("app")  if m.group("app")  != "-" else None
        log.pid       = m.group("pid")  if m.group("pid")  != "-" else None
        log.structured_data = parse_rfc5424_sd(m.group("sd"))
        log.message   = m.group("msg")
        return log

    # 6. RFC 3164 (has PRI + BSD timestamp)
    m = _RFC3164.match(line)
    if m:
        log.format   = "rfc3164"
        pri          = int(m.group("pri"))
        log.facility, log.severity, log.severity_num = decode_pri(pri)
        log.timestamp = normalise_bsd_ts(m.group("ts"))
        log.hostname  = m.group("host")
        log.app       = m.group("app")
        log.pid       = m.group("pid")
        log.message   = m.group("msg")
        # Dispatch message body by app type
        _dispatch_message(log)
        return log

    # 7. Linux auth.log / kern.log (no PRI prefix)
    m = _LINUX_AUTH.match(line)
    if m:
        log.hostname  = m.group("host")
        log.timestamp = normalise_bsd_ts(m.group("ts"))
        log.app       = m.group("app")
        log.pid       = m.group("pid")
        log.message   = m.group("msg")
        log.facility  = "auth"
        log.severity  = "info"

        app_lower = (log.app or "").lower()
        if "sshd" in app_lower:
            log.format = "linux_auth"
            parse_ssh_message(log.message, log)
        elif "sudo" in app_lower:
            log.format = "linux_auth"
            parse_sudo_message(log.message, log)
        elif "kernel" in app_lower or "iptables" in log.message.lower():
            log.format   = "linux_kern"
            log.facility = "kern"
            parse_iptables_message(log.message, log)
        else:
            log.format = "linux_auth"

        return log

    # 8. Could not parse — return raw in message
    log.format  = "unknown"
    log.message = line
    return log


def _dispatch_message(log: ParsedLog):
    """Route RFC3164 message body to the right sub-parser based on app name."""
    app = (log.app or "").lower()
    msg = log.message or ""
    if "sshd" in app:
        parse_ssh_message(msg, log)
    elif "sudo" in app:
        parse_sudo_message(msg, log)
    elif "kernel" in app or "iptables" in msg.lower():
        parse_iptables_message(msg, log)
    elif "microsoft-windows" in app.lower():
        parse_windows_message(msg, log)


# ─── Alert engine ─────────────────────────────────────────────────────────────

class AlertEngine:
    """
    Simple rule-based alert engine.
    Each rule is a dict with a 'check' callable and a 'name' string.
    In a real system you'd load these from YAML/JSON config files.
    """

    def __init__(self):
        self.rules = [
            {
                "id":    "AUTH001",
                "name":  "SSH brute force — failed password",
                "check": lambda l: (
                    l.action == "auth_failed" and
                    l.app and "sshd" in l.app.lower()
                ),
                "severity": "high",
            },
            {
                "id":    "AUTH002",
                "name":  "Root login attempt via SSH",
                "check": lambda l: (
                    l.username == "root" and
                    l.app and "sshd" in l.app.lower()
                ),
                "severity": "critical",
            },
            {
                "id":    "PRIV001",
                "name":  "Sudo escalation to root",
                "check": lambda l: (
                    l.app and "sudo" in l.app.lower() and
                    l.extra.get("sudo_target") == "root"
                ),
                "severity": "medium",
            },
            {
                "id":    "NET001",
                "name":  "Outbound connection to port 443 (potential C2)",
                "check": lambda l: l.dst_port == 443 and l.src_ip is not None,
                "severity": "low",
            },
            {
                "id":    "NET002",
                "name":  "Firewall connection blocked",
                "check": lambda l: (
                    l.format in ("cisco_asa", "paloalto") and
                    l.action and l.action.lower() in ("deny", "drop", "blocked")
                ),
                "severity": "medium",
            },
            {
                "id":    "WIN001",
                "name":  "Windows failed logon (EventID 4625)",
                "check": lambda l: l.event_id == "4625",
                "severity": "high",
            },
            {
                "id":    "WIN002",
                "name":  "Windows account created (EventID 4720)",
                "check": lambda l: l.event_id == "4720",
                "severity": "critical",
            },
            {
                "id":    "IDS001",
                "name":  "Cisco IOS login success from external",
                "check": lambda l: (
                    l.format == "cisco_ios" and
                    l.event_id and "LOGIN_SUCCESS" in (l.event_id or "")
                ),
                "severity": "info",
            },
        ]

    def check(self, log: ParsedLog) -> list:
        triggered = []
        for rule in self.rules:
            try:
                if rule["check"](log):
                    triggered.append({
                        "rule_id":  rule["id"],
                        "rule":     rule["name"],
                        "severity": rule["severity"],
                    })
            except Exception:
                pass
        return triggered


# ─── Output formatters ────────────────────────────────────────────────────────

def print_table(logs, alerts_map):
    """Human-readable table for terminal output."""
    W = 140
    print("─" * W)
    print(f"{'Format':<14} {'Severity':<10} {'Timestamp':<26} {'Host':<18} {'App':<16} {'Src IP':<16} {'Message'}")
    print("─" * W)
    for log in logs:
        ts  = (log.timestamp or "")[:25]
        msg = (log.message or "")[:55]
        print(f"{log.format:<14} {(log.severity or ''):<10} {ts:<26} {(log.hostname or ''):<18} "
              f"{(log.app or ''):<16} {(log.src_ip or ''):<16} {msg}")
        for alert in alerts_map.get(id(log), []):
            print(f"  {'':>14} *** ALERT [{alert['severity'].upper()}] {alert['rule_id']}: {alert['rule']}")
    print("─" * W)

def print_json(logs, alerts_map):
    output = []
    for log in logs:
        d = log.to_dict()
        alts = alerts_map.get(id(log), [])
        if alts:
            d["alerts"] = alts
        output.append(d)
    print(json.dumps(output, indent=2, default=str))

def print_csv_output(logs, alerts_map):
    fields = ["format", "severity", "timestamp", "hostname", "app", "pid",
              "src_ip", "dst_ip", "src_port", "dst_port", "username",
              "action", "protocol", "event_id", "message"]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for log in logs:
        writer.writerow(log.to_dict())


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="syslog_parser.py — multi-format syslog parser for blue team work",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 syslog_parser.py sample.log
  python3 syslog_parser.py sample.log --format json
  python3 syslog_parser.py sample.log --format csv --alerts
  cat /var/log/auth.log | python3 syslog_parser.py -
        """
    )
    ap.add_argument("input", help="Log file path, or '-' to read from stdin")
    ap.add_argument("--format", choices=["table", "json", "csv"], default="table",
                    help="Output format (default: table)")
    ap.add_argument("--alerts", action="store_true",
                    help="Run alert rules and flag suspicious entries")
    ap.add_argument("--filter-format", metavar="FMT",
                    help="Only show logs matching this format (e.g. linux_auth)")
    ap.add_argument("--filter-severity", metavar="SEV",
                    help="Only show logs at or above this severity (e.g. error)")
    args = ap.parse_args()

    # Read input
    if args.input == "-":
        lines = sys.stdin.readlines()
    else:
        path = Path(args.input)
        if not path.exists():
            # If file not found, run with built-in sample logs for demo
            print(f"[!] File not found: {path}. Running with built-in sample logs.\n", file=sys.stderr)
            lines = SAMPLE_LOGS.strip().splitlines()
        else:
            lines = path.read_text(errors="replace").splitlines()

    # Parse
    parsed = [parse_line(line) for line in lines if line.strip()]

    # Filter by format
    if args.filter_format:
        parsed = [l for l in parsed if l.format == args.filter_format]

    # Filter by severity
    sev_order = list(SEVERITIES.values())  # emergency → debug
    if args.filter_severity:
        threshold = args.filter_severity.lower()
        if threshold in sev_order:
            thresh_idx = sev_order.index(threshold)
            parsed = [l for l in parsed if
                      l.severity_num is not None and l.severity_num <= thresh_idx]

    # Run alerts
    engine     = AlertEngine()
    alerts_map = {}
    if args.alerts:
        for log in parsed:
            alerts = engine.check(log)
            if alerts:
                alerts_map[id(log)] = alerts

    # Output
    if args.format == "json":
        print_json(parsed, alerts_map)
    elif args.format == "csv":
        print_csv_output(parsed, alerts_map)
    else:
        print_table(parsed, alerts_map)

    # Stats footer
    print(f"\nParsed {len(parsed)} log entries.", file=sys.stderr)
    total_alerts = sum(len(v) for v in alerts_map.values())
    if args.alerts:
        print(f"Alerts triggered: {total_alerts}", file=sys.stderr)
    fmt_counts = {}
    for l in parsed:
        fmt_counts[l.format] = fmt_counts.get(l.format, 0) + 1
    for fmt, count in sorted(fmt_counts.items()):
        print(f"  {fmt}: {count}", file=sys.stderr)


# ─── Built-in sample logs (for demo without a real log file) ─────────────────

SAMPLE_LOGS = """
<34>Oct 11 22:14:15 webserver01 sshd[29785]: Failed password for alice from 192.168.1.42 port 22 ssh2
<34>Oct 11 22:14:16 webserver01 sshd[29786]: Failed password for root from 192.168.1.42 port 22 ssh2
<34>Oct 11 22:14:17 webserver01 sshd[29790]: Accepted password for bob from 10.0.0.5 port 55321 ssh2
Oct 11 22:14:20 webserver01 sudo[29800]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
Oct 11 22:14:21 webserver01 kernel: [12345.678] iptables: IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP SPT=55421 DPT=22
<34>1 2024-10-11T22:14:25.003Z myhost su 1234 ID47 [exampleSDID@32473 iut="3" eventSource="App"] Bad su for root by alice
<166>Oct 11 2024 22:14:30 asa-fw01 : %ASA-6-302013: Built outbound TCP connection 12345 for outside:8.8.8.8/443 (8.8.8.8/443) to inside:10.0.0.5/55421
<189>Oct 11 22:14:35 router01 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.1.1.5] [localport: 22]
<14>Oct 11 22:14:40 WIN-DC01 Microsoft-Windows-Security-Auditing: EventID=4625 AccountName=badguy IpAddress=203.0.113.5 LogonType=3
<14>Oct 11 22:14:45 WIN-DC01 Microsoft-Windows-Security-Auditing: EventID=4720 AccountName=backdoor IpAddress=10.0.0.99
<14>2024-10-11T22:14:50Z aws-collector vpc-flowlog: 2 123456789012 eni-abc123 10.0.1.5 8.8.8.8 54321 443 6 20 4096 1697040000 1697040060 ACCEPT OK
<14>Oct 11 22:14:55 PA-FW01 1,2024/10/11 22:14:55,013201001234,TRAFFIC,end,2048,2024/10/11 22:14:55,10.0.0.5,1.2.3.4,10.0.0.5,1.2.3.4,block-rule,alice,,ssl,vsys1,trust,untrust,eth1/1,eth1/2,Panorama,1234,1,0,0,0,,PA-FW01,from-policy,,,0,,0,,N/A,0,0,0,0,deny
"""

if __name__ == "__main__":
    main()
