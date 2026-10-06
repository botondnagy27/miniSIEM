# 🛡️Mini-SIEM: Biztonsági Logelemző és Anomáliadetektáló Rendszer

Python alapú biztonsági eseményelemző alkalmazás, amely Linux logokat dolgoz fel, majd szabályalapú heurisztikákkal és felügyelet nélküli gépi tanulással (Isolation Forest) azonosítja a támadásokat és anomális hálózati forrásokat.



## 📌 A Projekt Célja és Áttekintése

A biztonsági naplófájlok manuális ellenőrzése a keletkező hatalmas adatmennyiség miatt lehetetlen. A projekt célja egy olyan kettős detekciós motorral ellátott eszköz megvalósítása, amely:
1. **Szabályalapú döntéshozatal** azonnal riaszt az ismert támadási mintázatokra (Brute-force kísérletek, DoS/Flood forgalom, Exploit payloadok).
2. **Gépi tanulásos anomáliadetektálással** előzetes címkék nélkül képes kiszűrni az átlagostól eltérő, gyanús forrás IP-címeket.
3. Egy interaktív **webes felületen (Streamlit)** vizualizálja az incidenseket és a forgalmi statisztikákat.




## 🚀 Főbb Funkciók

  1. Syslog & PAM Parser: Feldolgozza a Linux rendszerüzeneteket, kinyeri a folyamatok nevét, a célzott felhasználókat, a forrás IP-címeket/hosztneveket és a biztonsági eseménytípusokat.

  2. Szabályalapú Fenyegetéselemzés:

      - SSH_BRUTE_FORCE: Legalább 5 sikertelen hitelesítési kísérlet 2 percen belül ugyanarról a forrásról.

      - FTP_FLOOD_ATTACK: Legalább 10 FTP kapcsolatnyitás 1 percen belül.
      
      - BUFFER_OVERFLOW_EXPLOIT: Formátumsztring vagy shellcode támadási kísérletek felismerése (pl. rpc.statd).

  3. Felügyelet Nélküli Gépi Tanulás (Isolation Forest):

      - Forrás IP-nkénti jellemzők kinyerése: kérések száma, hibaarány, megcélzott felhasználók és szolgáltatások diverzitása.
      
      - Automatikus viselkedés-szeparálás skálázott feature-vektorok alapján (StandardScaler).
      
  4. Interaktív Dashboard:
      
      - Események arányának tortadiagramja és óránkénti forgalmi görbe (Plotly).
      
      - Súlyosság szerinti riasztásszűrés (CRITICAL, HIGH, MEDIUM).
      
      - Anomália-eloszlás szórásdiagramja (Összes kérés és Sikertelenségi arány).



## ⚙️ Rendszerarchitektúra

A rendszer négy fő rétegből áll:

```text
             Linux.log (Nyers naplófájl)
                           │
                           ▼
        [1. Log Parser (src/parser.py)]
        ├── Regex minták kinyerése (PAM, SSH, FTP, RPC)
        └── Strukturált Pandas DataFrame előállítása
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
[2. Szabályalapú Detektor]   [3. ML Anomáliadetektor]
(src/detector.py)            (src/ml_detector.py)
├── Csúszóablakos időelemzés ├── Feature Engineering (IP szinten)
└── Küszöbérték-alapú szűrés └── Isolation Forest algoritmus
                 │                   │
                 └─────────┬─────────┘
                           ▼
          [4. Streamlit Dashboard (src/app.py)]
          ├── Forgalmi KPI-k és idősoros diagramok
          ├── Súlyozott riasztási lista és szűrők
          └── Források szórásdiagramja (Scatter Plot)
```


## 🛠️ Telepítés és Futtatás

### 1.Előfeltételek
  1. Python 3.10 vagy újabb verzió
  2. git verziókövető

### 2. Repository klónozása
  ```text
git clone https://github.com/botondnagy27/miniSIEM.git
cd miniSIEM
```

### 3. Függőségek telepítése
  ```text
pip install -r requirements.txt
```

### 4. Modulok külön futtatása
  ```text
# Parser tesztelése:
python src/parser.py

# Szabályalapú vizsgálat:
python src/detector.py

# Gépi tanulási anomáliakeresés:
python src/ml_detector.py
```
### 5. Webes Dashboard indítása
  ```text
cd src
streamlit run app.py
```
A parancs lefutása után az alkalmazás automatikusan megnyílik a böngészőben a http://localhost:8501 címen.


## 📂 Mappaszerkezet
```text
miniSIEM/
├── src/
│   ├── parser.py             # Log beolvasása és Regex feldolgozása
│   ├── detector.py           # Szabályalapú csúszóablakos detektor
│   ├── ml_detector.py        # Feature extraction és Isolation Forest modell
│   ├── app.py                # Streamlit webes alkalmazás
│   └── Linux.log             # A teszteléshez használt minta naplófájl (https://github.com/logpai/loghub/tree/master/Linux)
├── AI_USAGE.md               # MI eszközök használatának transzparens naplója
├── README.md                 # Rendszerdokumentáció
└── requirements.txt          # Szükséges Python könyvtárak listája
```
