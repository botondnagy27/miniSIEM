import re
from datetime import datetime
import pandas as pd

# 1. naplófejléc minta (Dátum, Hostnév, Program[PID]: Üzenet)
# Kezeli az "sshd(pam_unix)[1234]" és a "kernel:" formátumokat is
LINE_PATTERN = re.compile(
    r'^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[A-Za-z0-9_\-\.\(\)]+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)$'
)

# 2. biztonsági minták kinyerése a szövegtörzsből
PAM_AUTH_FAIL = re.compile(
    r'authentication failure;.*?(?:rhost=(?P<rhost>\S+))?.*?(?:user=(?P<user>\S+))?$'
)
FTPD_CONN = re.compile(
    r'connection from (?P<ip>[\d\.]+)'
)
IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
