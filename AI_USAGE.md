A logfájl feldolgozásánál az AI(Gemini) főként a komplex regexek összeállításában és az adatszerkezet vázlatának elkészítésében segített. 
Példa a promptokra:
"Írj egy Python reguláris kifejezést, ami feldolgozza a standard RedHat Linux syslog összes sorát"
"Adj olyan regex mintákat, amik felismerik az autentikációs hibákat, az FTP csatlakozásokat és az rpc.statd exploit kísérleteket." 
Kapott eredmények:
Generált line_pattern és specifikus biztonsági minták (PAM, FTPD),egy parse_log_line() függvényváz, ami szótár formájában adja vissza a fájlból kinyert adatokat
Módosítások:
Dátumkezelés és évszám: A syslog nem tartalmaz évszámot, ezért manuálisan egészítettük ki a logikát az évszámok hozzáadásával. A hónap és a nap közötti dupla szóközöket normalizáltuk
Hozzáadtunk egy tartalék szabályt, ami kinyeri az IPv4-címet, ha a specifikus minta nem illeszkedett rá.

