import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def extract_ip_features(df: pd.DataFrame) -> pd.DataFrame:
        # Csak azokat a sorokat vesszük figyelembe, ahol van ismert forrás IP/host
    df_valid = df.dropna(subset=['ip_or_host']).copy()

    features = []
    for ip, group in df_valid.groupby('ip_or_host'):
        total_events = len(group)
        auth_failures = sum(group['event_type'] == 'AUTH_FAILURE')
        ftp_connections = sum(group['event_type'] == 'FTP_CONNECTION')
        unique_processes = group['process'].nunique()
        unique_users = group['user'].dropna().nunique()
        failure_ratio = auth_failures / total_events if total_events > 0 else 0

        features.append({
            'ip_or_host': ip,
            'total_events': total_events,
            'auth_failures': auth_failures,
            'ftp_connections': ftp_connections,
            'unique_processes': unique_processes,
            'unique_users': unique_users,
            'failure_ratio': failure_ratio
        })

    return pd.DataFrame(features)


def train_and_detect_anomalies(features_df: pd.DataFrame, contamination: float = 0.08) -> pd.DataFrame:
        if len(features_df) < 5:
        print("Kevés az adat az anomáliadetektáláshoz!")
        return features_df

    # A tanításhoz használt oszlopok
    feature_cols = [
        'total_events', 
        'auth_failures', 
        'ftp_connections', 
        'unique_processes', 
        'unique_users', 
        'failure_ratio'
    ]
    
    X = features_df[feature_cols].copy()

    # Skálázás: hogy a nagy számok (pl. total_events) ne nyomják el a kis számokat
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Isolation Forest tanítása
    # contamination: a becsült anomália-arány 
    model = IsolationForest(contamination=contamination, random_state=42)
    features_df['anomaly'] = model.fit_predict(X_scaled)
    
    # Anomália pontszám: minél alacsonyabb / negatívabb, annál furcsább a viselkedés
    features_df['anomaly_score'] = model.decision_function(X_scaled)

    # -1: anomália (támadó/gyanús), 1: normális viselkedés
    features_df['is_anomaly'] = features_df['anomaly'].apply(lambda x: True if x == -1 else False)

    # Rendezes
    return features_df.sort_values(by='anomaly_score').reset_index(drop=True)


if __name__ == '__main__':
    from parser import parse_linux_log

    log_path = "Linux.log"
    print(f"Logok beolvasása: {log_path}...")
    df_logs = parse_linux_log(log_path)

    print("1. Jellemzők (feature-ök) kinyerése IP-címek szerint...")
    features_df = extract_ip_features(df_logs)
    print(f"Elemzett egyedi forrás IP-k száma: {len(features_df)}")

    print("\n2. Isolation Forest modell futtatása...")
    results_df = train_and_detect_anomalies(features_df, contamination=0.08)

    anomalies = results_df[results_df['is_anomaly']]
    print(f"\nTalált anomális források száma: {len(anomalies)} / {len(results_df)}")
    
    print("\nA leginkább gyanús IP-címek listája:")
    display_cols = ['ip_or_host', 'total_events', 'auth_failures', 'ftp_connections', 'anomaly_score']
    print(anomalies[display_cols].head(10))
