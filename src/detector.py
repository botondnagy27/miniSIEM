import pandas as pd
from datetime import timedelta

def detect_rule_based_threats(df: pd.DataFrame) -> pd.DataFrame:

    alerts = []
    # 1. SZABÁLY: Exploit kísérletek (azonnali Critical riasztás)
    exploits = df[df['event_type'] == 'EXPLOIT_ATTEMPT']
    for _, row in exploits.iterrows():
        alerts.append({
            'timestamp': row['timestamp'],
            'rule_name': 'BUFFER_OVERFLOW_EXPLOIT',
            'severity': 'CRITICAL',
            'source': row.get('ip_or_host', 'Unknown'),
            'details': f"Exploit payload detektálva a folyamatban: {row.get('process')}"
        })

    # Az időablakos vizsgálathoz csak a forrással és érvényes időbélyeggel rendelkező sorok kellenek
    valid_events = df.dropna(subset=['timestamp', 'ip_or_host']).copy()

    # 2. SZABÁLY: SSH Brute-Force detektálás (pl. >= 5 hibás kísérlet 2 percen belül)
    auth_failures = valid_events[valid_events['event_type'] == 'AUTH_FAILURE']
    for source, group in auth_failures.groupby('ip_or_host'):
        group = group.sort_values(by='timestamp')
        times = group['timestamp'].tolist()
        
        # Csúszóablak vizsgálat (2 perc = 120 másodperc)
        alerted_times = set()
        for i in range(len(times)):
            window_end = times[i]
            window_start = window_end - timedelta(minutes=2)
            
            # Megszámoljuk az ablakba eső próbálkozásokat
            count_in_window = sum(1 for t in times if window_start <= t <= window_end)
            
            # Ha eléri a küszöböt és erre a percre még nem dobtunk riasztást
            minute_key = window_end.strftime("%Y-%m-%d %H:%M")
            if count_in_window >= 5 and minute_key not in alerted_times:
                alerted_times.add(minute_key)
                target_users = group[(group['timestamp'] >= window_start) & (group['timestamp'] <= window_end)]['user'].dropna().unique()
                user_list = ", ".join(target_users) if len(target_users) > 0 else "unknown"
                
                alerts.append({
                    'timestamp': window_end,
                    'rule_name': 'SSH_BRUTE_FORCE',
                    'severity': 'HIGH',
                    'source': source,
                    'details': f"{count_in_window} sikertelen kísérlet 2 percen belül (Célzott fiókok: {user_list})"
                })

    # 3. SZABÁLY: FTP Connection Flood (pl. >= 10 kapcsolat 1 percen belül)
    ftp_events = valid_events[valid_events['event_type'] == 'FTP_CONNECTION']
    for source, group in ftp_events.groupby('ip_or_host'):
        group = group.sort_values(by='timestamp')
        times = group['timestamp'].tolist()
        
        alerted_times = set()
        for i in range(len(times)):
            window_end = times[i]
            window_start = window_end - timedelta(minutes=1)
            
            count_in_window = sum(1 for t in times if window_start <= t <= window_end)
            minute_key = window_end.strftime("%Y-%m-%d %H:%M")
            
            if count_in_window >= 10 and minute_key not in alerted_times:
                alerted_times.add(minute_key)
                alerts.append({
                    'timestamp': window_end,
                    'rule_name': 'FTP_FLOOD_ATTACK',
                    'severity': 'MEDIUM',
                    'source': source,
                    'details': f"{count_in_window} FTP kapcsolat kísérlet 1 percen belül"
                })

    alerts_df = pd.DataFrame(alerts)
    if not alerts_df.empty:
        alerts_df = alerts_df.sort_values(by='timestamp').reset_index(drop=True)
    return alerts_df



if __name__ == '__main__':
    from parser import parse_linux_log

    log_path = "Linux.log"
    print(f"Naplófájl beolvasása: {log_path}...")
    df_logs = parse_linux_log(log_path)
    
    print(f"Összes esemény: {len(df_logs)}")
    print("Szabályalapú vizsgálat futtatása...")
    
    threats_df = detect_rule_based_threats(df_logs)
    
    print(f"\nTalált riasztások száma: {len(threats_df)}\n")
    print("Riasztások típus szerint:")
    print(threats_df['rule_name'].value_counts())
    
    print("\nSúlyosság szerinti megoszlás:")
    print(threats_df['severity'].value_counts())
    
    print("\nElső 10 generált riasztás:")
    print(threats_df[['timestamp', 'severity', 'rule_name', 'source', 'details']]
