# Fájl betöltése (vagy a helyi Linux.log használata alapértelmezettként)
@st.cache_data
def load_data(file):
    if file is not None:
        # Ha a felületen töltött fel fájlt
        with open("temp_uploaded.log", "wb") as f:
            f.write(file.getbuffer())
        return parse_linux_log("temp_uploaded.log")
    else:
        # Alapértelmezett helyi fájl
        try:
            return parse_linux_log("Linux.log")
        except FileNotFoundError:
            return pd.DataFrame()

df_logs = load_data(uploaded_file)

if df_logs.empty:
    st.warning("⚠️ Nem található logfájl. Kérlek tölts fel egyet a bal oldali menüben!")
    st.stop()

# Fő metrikák kártyái (KPIs)
col1, col2, col3, col4 = st.columns(4)
col1.metric("Összes naplósor", f"{len(df_logs):,}")
col2.metric("Egyedi Forrás IP-k", f"{df_logs['ip_or_host'].nunique():,}")
auth_fails = sum(df_logs['event_type'] == 'AUTH_FAILURE')
col3.metric("Sikertelen belépések", f"{auth_fails:,}")
exploits = sum(df_logs['event_type'] == 'EXPLOIT_ATTEMPT')
col4.metric("Közvetlen Exploit kísérlet", f"{exploits:,}")

st.divider()

tab1, tab2, tab3 = st.tabs(["📊 Áttekintés & Forgalom", "🚨 Szabályalapú Riasztások", "🤖 Gépi Tanulás (Isolation Forest)"])

# --- 1. TAB: ÁTTEKINTÉS ---
with tab1:
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        st.subheader("Eseménytípusok megoszlása")
        event_counts = df_logs['event_type'].value_counts().reset_index()
        event_counts.columns = ['Esemény', 'Darabszám']
        fig_pie = px.pie(event_counts, values='Darabszám', names='Esemény', hole=0.4,
                         color_discrete_sequence=px.colors.qualitative.Safe)
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_chart2:
        st.subheader("Időbeli aktivitás (Forgalom alakulása)")
        # Óránkénti aggregáció
        df_logs['hour'] = df_logs['timestamp'].dt.floor('H')
        time_counts = df_logs.groupby('hour').size().reset_index(name='Kérések száma')
        fig_line = px.line(time_counts, x='hour', y='Kérések száma', markers=True,
                           labels={'hour': 'Időpont'})
        st.plotly_chart(fig_line, use_container_width=True)

    st.subheader("Legfrissebb naplósorok (Minta)")
    st.dataframe(df_logs[['timestamp', 'process', 'event_type', 'user', 'ip_or_host']].head(10), use_container_width=True)

# --- 2. TAB: SZABÁLYALAPÚ MOTOR ---
with tab2:
    st.subheader("Heurisztikus Riasztási Lista")
    threats_df = detect_rule_based_threats(df_logs)
    
    if not threats_df.empty:
        col_t1, col_t2 = st.columns([1, 3])
        with col_t1:
            st.metric("Összes riasztás", len(threats_df))
            st.write("**Súlyosság szerint:**")
            st.write(threats_df['severity'].value_counts())
        
        with col_t2:
            severity_filter = st.multiselect(
                "Szűrés súlyosság szerint:", 
                options=['CRITICAL', 'HIGH', 'MEDIUM'], 
                default=['CRITICAL', 'HIGH', 'MEDIUM']
            )
            filtered_threats = threats_df[threats_df['severity'].isin(severity_filter)]
            st.dataframe(filtered_threats, use_container_width=True)
    else:
        st.success("Nem található szabályalapú riasztás a logban.")

# --- 3. TAB: GÉPI TANULÁS ---
with tab3:
    st.subheader("Isolation Forest Anomáliakeresés")
    st.write("A modell az IP-címek viselkedési sajátosságai (kérések száma, hibaarány, stb.) alapján keres mintázatokat.")

    features_df = extract_ip_features(df_logs)
    ml_results = train_and_detect_anomalies(features_df, contamination=contamination)
    anomalies = ml_results[ml_results['is_anomaly']]

    col_ml1, col_ml2 = st.columns(2)
    col_ml1.metric("Kiugró (Anomális) források száma", f"{len(anomalies)} / {len(ml_results)}")
    
    # Szórásdiagram (Scatter plot): Kérések száma vs. Hibaarány
    fig_scatter = px.scatter(
        ml_results,
        x='total_events',
        y='failure_ratio',
        color='is_anomaly',
        hover_data=['ip_or_host', 'auth_failures', 'ftp_connections', 'anomaly_score'],
        labels={'total_events': 'Összes kérés', 'failure_ratio': 'Sikertelenségi arány (0-1)', 'is_anomaly': 'Anomália?'},
        title="Normál vs. Anomális források elhelyezkedése",
        color_discrete_map={False: '#2ca02c', True: '#d62728'}
    )
    st.plotly_chart(fig_scatter, use_container_width=True)

    st.subheader("Leginkább gyanús IP-címek (Részletes táblázat)")
    display_cols = ['ip_or_host', 'anomaly_score', 'total_events', 'auth_failures', 'ftp_connections', 'failure_ratio']
    st.dataframe(anomalies[display_cols].sort_values(by='anomaly_score'), use_container_width=True)
