# 🤖 AI Használati Nyilatkozat 

**Tárgy:** Haladó Programozás  
**Projekt neve:** Mini-SIEM: Biztonsági Logelemző és Anomáliadetektáló Rendszer  

---

## 📌 Az AI Használatának Áttekintése

A projekt fejlesztése során generatív AI eszközöket (Gemini, ChatGPT, Claude) használtunk asszisztensként a komplex logikai vázak, reguláris kifejezések és a gépi tanulási architektúra összeállításához. A generált kódokat minden esetben manuálisan ellenőriztük, finomítottuk és integráltuk a rendszerbe.

---

## ⚙️ Részletes AI Használati Kimutatás Modulonként

### 1. Log Parser Modul (`src/parser.py`)
* **Használt MI-eszköz:** Gemini
* **Feladat:** A logfájl feldolgozásánál a komplex regexek összeállítása és az adatszerkezet vázlatának elkészítése.
* **Fontosabb promptok:**
  * *"Írj egy Python reguláris kifejezést, ami feldolgozza a standard RedHat Linux syslog összes sorát"*
  * *"Adj olyan regex mintákat, amik felismerik az autentikációs hibákat, az FTP csatlakozásokat és az rpc.statd exploit kísérleteket."*
* **Kapott eredmény:** Generált `line_pattern` és specifikus biztonsági minták (PAM, FTPD), valamint egy `parse_log_line()` függvényváz, ami szótár formájában adja vissza a fájlból kinyert adatokat.
# AI Használati Nyilatkozat

A Linux log parser és machine learning anomáliadetektor projektfeladat elkészítése közben a csapat a Gemini, illetve a ChatGPT segítségét igénybe vette az alábbi feladatrészekben, hogy felgyorsítsuk a fejlesztést és megoldjuk a komplex mintafelismerési feladatokat.

## parser.py – Logfájl feldolgozása és adatszerkezet kialakítása
* **Használt AI:** Gemini
* **Feladat:** A logfájl feldolgozásánál az AI főként a komplex regexek összeállításában és az adatszerkezet vázlatának elkészítésében segített.
* **Példa a promptokra:**
  * "Írj egy Python reguláris kifejezést, ami feldolgozza a standard RedHat Linux syslog összes sorát"
  * "Adj olyan regex mintákat, amik felismerik az autentikációs hibákat, az FTP csatlakozásokat és az rpc.statd exploit kísérleteket."
* **Kapott eredmények:**
  * Generált line_pattern és specifikus biztonsági minták (PAM, FTPD), egy parse_log_line() függvényváz, ami szótár formájában adja vissza a fájlból kinyert adatokat.
* **Módosítások:**
  * **Dátumkezelés és évszám:** A syslog nem tartalmaz évszámot, ezért manuálisan egészítettük ki a logikát az évszámok hozzáadásával. A hónap és a nap közötti dupla szóközöket normalizáltuk.
  * Hozzáadtunk egy tartalék szabályt, ami kinyeri az IPv4-címet, ha a specifikus minta nem illeszkedett rá.

## detector.py - Fenyegetés-detektáló Modul 
* **Használt AI:** Gemini
* **Feladat:** Szabályalapú heurisztikák és időablakos vizsgálatok implementálása.
* **Főbb promptok:**
  * "Hogyan lehet Pandas-ban időablakos vizsgálatot végezni, hogy kiszűrjük azokat az IP-címeket, ahonnan 2 percen belül legalább 5 sikertelen belépés érkezett?"
  * "Generálj egy vázat a szabályalapú riasztási struktúrához (időbélyeg, szabály neve, súlyosság, forrás, részletek)."
* **Eredmények:** 
  * Csúszóablakos kódváz, riasztásokat gyűjtő lista és a Pandas DataFrame-mé alakítása.
* **Módosítások:**
  * **Küszöbértékek finomhangolása:** Mi határoztuk meg a konkrét riasztási küszöböket pl. SSH 5 hiba/2 perc, FTP flood: 10 kapcsolat/1 perc, Exploit: azonnali kritikus.
  * **Riasztási duplikáció szűrése:** Egyedi logikát írtunk, hogy ugyanarra az IP-címre percenként ne dobjon tucatnyi egyforma riasztást.
  * **Kontextus bővítése:** Kiegészítettük a kódot a célzott felhasználónevek kinyerésével, hogy a riasztás részleteinél a megtámadott fiók is látszódjon.

## app.py - Webes felület 
* **Használt AI:** ChatGPT
* **Feladat:** UI szerkezet és az interaktív Plotly grafikonok kódjának elkészítése.
* **Fontosabb promptok:**
  * "Adj egy 3 fülből álló Streamlit dashboard vázat KPI kártyákkal és oldalsávval."
  * "Írj Plotly kódot az események kördiagramjához és az ML anomáliák scatter plotjához."
* **Eredmények:**
  * Alapvető Streamlit felépítés (st.tabs, st.columns, st.sidebar).
  * Működő Plotly diagram-kódok (px.pie, px.scatter).
* **Módosítások:**
  * **Modulintegráció:** Mi kötöttük össze az app.py-t a parser.py, detector.py és ml_detector.py modulokkal.
  * **Fájlkezelés és gyorsítótár:** Beépítettük a fájlfeltöltést és a teljesítményoptimalizálást.
  * **Interaktív szűrők:** Megírtuk a súlyosság szerinti szűrést és az ML küszöbérték-csúszkát.

## ml_detector.py - Gépi tanulás anomáliadetektor
* **Használt AI-eszköz:** ChatGPT / Claude
* **Feladat:** Algoritmusválasztás és a Scikit-Learn alapú modell vázának elkészítése.
* **Fontosabb promptok:**
  * "Milyen unsupervised algoritmust ajánlasz IP-alapú log-anomáliákhoz, és miért?"
  * "Írj egy Python kódot, ami StandardScaler-t és Isolation Forestet használ a feature-ökön."
* **Kapott eredmény:** 
  * Az AI az Isolation Forest algoritmust javasolta, mivel a biztonsági logokban a ritka anomáliák (támadások) kiszűrésére ez a leghatékonyabb tanító adatok nélkül, emellett megkaptuk az alapfüggvényeket is.
* **Ellenőrzés és módosítások:**
  * Beállítottuk a contamination paramétert 0.08-ra a valós logok alapján.
  * Beletettünk egy ellenőrzést, hogy kevés adat (kevesebb mint 5 sor) esetén ne dobjon vissza hibát a kód.
