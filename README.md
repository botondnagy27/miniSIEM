# Mini-SIEM: Biztonsági Logelemző és Anomáliadetektáló Rendszer

Python alapú biztonsági eseményelemző alkalmazás, amely Linux logokat dolgoz fel, majd szabályalapú heurisztikákkal és felügyelet nélküli gépi tanulással (Isolation Forest) azonosítja a támadásokat és anomális hálózati forrásokat.

---

## 📌 A Projekt Célja és Áttekintése

A biztonsági naplófájlok manuális ellenőrzése a keletkező hatalmas adatmennyiség miatt lehetetlen. A projekt célja egy olyan kettős detekciós motorral ellátott eszköz megvalósítása, amely:
1. **Szabályalapú korrelációval** azonnal riaszt az ismert támadási mintázatokra (Brute-force kísérletek, DoS/Flood forgalom, Exploit payloadok).
2. **Gépi tanulásos anomáliadetektálással** előzetes címkék nélkül képes kiszűrni az átlagostól eltérő, gyanús forrás IP-címeket.
3. Egy interaktív **webes felületen (Streamlit)** vizualizálja az incidenseket és a forgalmi statisztikákat.
