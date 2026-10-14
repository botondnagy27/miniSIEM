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


def parse_log_line(line: str, default_year: int = 2025) -> dict | None:
    """Egyetlen naplósort parszol és biztonsági eseménytípushoz rendel."""
    line = line.strip()
    match = LINE_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()

    # Dátum előállítása 
    ts_str = f"{default_year} {data['month']} {data['day']} {data['time']}"
    try:
        data['timestamp'] = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
    except ValueError:
        data['timestamp'] = None

    del data['month']
    del data['day']
    del data['time']

    process = data['process'].lower()
    message = data['message']

    data['event_type'] = 'SYSTEM_INFO'
    data['user'] = None
    data['ip_or_host'] = None

    # PAM hitelesítési hiba (pl. SSH behatolási kísérletek)
    if 'authentication failure' in message:
        data['event_type'] = 'AUTH_FAILURE'
        pam_match = PAM_AUTH_FAIL.search(message)
        if pam_match:
            data['ip_or_host'] = pam_match.group('rhost')
            data['user'] = pam_match.group('user')

    # Ismeretlen felhasználó próbálkozás
    elif 'check pass; user unknown' in message:
        data['event_type'] = 'USER_UNKNOWN'

    # Sikeres belépések / Session nyitások
    elif 'session opened' in message:
        data['event_type'] = 'SESSION_OPEN'
        user_match = re.search(r'for user (\S+)', message)
        if user_match:
            data['user'] = user_match.group(1)

    # FTP csatlakozások sorozata (gyakori portszkennelés vagy brute-force)
    elif 'ftpd' in process and 'connection from' in message:
        data['event_type'] = 'FTP_CONNECTION'
        ftp_match = FTPD_CONN.search(message)
        if ftp_match:
            data['ip_or_host'] = ftp_match.group('ip')

    # Exploit / Puffer-túlcsordulási kísérletek az rpc.statd ellen
    elif 'rpc.statd' in process and 'gethostbyname error' in message:
        data['event_type'] = 'EXPLOIT_ATTEMPT'

    # Egyéb hibaüzenetek
    elif 'failed' in message.lower() or 'alert' in message.lower():
        data['event_type'] = 'SERVICE_ALERT'

    # Ha még nincs IP/host, de a szöveg tartalmaz IPv4-et, mentsük el
    if not data['ip_or_host']:
        ip_match = IP_REGEX.search(message)
        if ip_match:
            data['ip_or_host'] = ip_match.group(0)

    return data


def parse_linux_log(file_path: str) -> pd.DataFrame:
    """Feldolgozza a fájlt és visszaadja a strukturált DataFrame-et."""
    records = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                records.append(parsed)

    df = pd.DataFrame(records)
    if not df.empty:
        df = df.sort_values(by='timestamp').reset_index(drop=True)
    return df


if __name__ == '__main__':
    log_file_path = "Linux.log"  

    try:
        df = parse_linux_log(log_file_path)
        print("Sikeres feldolgozás!")
        print(f"Feldolgozott sorok száma: {len(df)}\n")

        print("Detektált eseménytípusok megoszlása:")
        print(df['event_type'].value_counts())

        print("\nLeggyakoribb források (IP / Host):")
        print(df['ip_or_host'].value_counts().head(5))

        print("\nElső 5 rekord a táblázatból:")
        print(df[['timestamp', 'process', 'event_type', 'user', 'ip_or_host']].head())

    except FileNotFoundError:
        print(f"Nem található a fájl: {log_file_path}")
