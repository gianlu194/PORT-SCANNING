# PortScanPy

Port scanner scritto in Python per allenarmi con socket, networking e tecniche base di scanning.

---

##  Perché l’ho realizzato
Volevo un progetto semplice ma concreto per capire meglio:
- come funziona davvero una socket TCP  
- cosa accade dietro una chiamata `connect()`  
- come implementare un port-scanner senza librerie esterne  
- come strutturare un tool che cresce nel tempo  

È un progetto “da palestra”: ogni funzione che aggiungo serve a migliorare Python, logica e networking.

---

##  Cosa fa
Il tool al momento  può effettuare scansioni udp,scansioni tcp o scansioni normali:

1. crea una socket IPv4/TCP  
2. tenta `connect(ip, porta)`  
3. se non ci sono errori → la porta risulta **open** se no open/filtred, close ecc
 

---

## Funzionalità attuali
- Scansione completa 1–65535  
- Stampa immediata delle porte aperte  
- Modalità semplice e leggibile  
- Codice pulito e facile da estendere
- udp,tcp e normale

---

## 🔥 Funzionalità future (work in progress)
Sto lavorando per aggiungere:
- Banner grabbing (lettura risposta dopo la connect)  
~~Scansione UDP~~  
- Salvataggio dei risultati su file  
~~Range di porte personalizzati~~  
- Output più pulito e colorato
- evasioni come la frammentazione

L’obiettivo è far crescere questo tool mentre imparo.

---

## 📂 Struttura del progetto
- **portscan.py** — file principale dello scanner  
- **funzioni extra** — test, mini-script, prove  
- **README.md** — documentazione del progetto  


