# syslog-parser
Simple syslog parser to understand syslog and its uses in cybersecurity.

## How to run

### Demo mode with built-in samples
python3 syslog_parser.py nonexistent.log --alerts

### Real auth log with alerts
python3 syslog_parser.py /var/log/auth.log --alerts

### JSON output for piping into jq or a SIEM
python3 syslog_parser.py /var/log/syslog --format json | jq '.[] | select(.severity == "critical")'

### Only show SSH brute force (linux_auth format)
python3 syslog_parser.py auth.log --filter-format linux_auth --alerts

### Read from stdin (pipe from netcat on UDP 514)
nc -ulk 514 | python3 syslog_parser.py -
