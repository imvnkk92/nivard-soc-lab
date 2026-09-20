
# Analyse réseau Wireshark — Infection malware (Angry Poutine)

## Contexte
Exercice pratique basé sur un pcap public (malware-traffic-analysis.net), simulant une infection réelle sur un réseau Windows/AD.

**Réseau analysé** : 10.9.10.0/24 — Domaine ANGRYPOUTINE

## Méthodologie d'investigation

**1. Identification de la victime (trafic DHCP)**
Filtre : `dhcp`
→ Hostname : DESKTOP-KKITB6Q
→ MAC : 00:4f:49:b1:e8:c3
→ IP attribuée : 10.9.10.102

**2. Identification du compte utilisateur (trafic Kerberos)**
Filtre : `kerberos && ip.addr==10.9.10.102`
→ Compte : hobart.gunnarsson

**3. Repérage du trafic HTTP suspect**
Statistiques → HTTP → Requêtes
→ Domaine de typosquatting identifié : `simpsonsavingss.com` (à comparer avec le légitime "simpsonsavings")

**4. Analyse du flux complet (Follow HTTP Stream)**
→ Fichier exécutable livré (signature "MZ", `Content-Disposition: filename="date6"`)
→ Serveur malveillant : 194.62.42.206

**5. Extraction et identification du malware**
```bash
sha256sum "date1%3fBNLv65=pAAS"
```
→ Hash vérifié sur VirusTotal : **59/71 moteurs antivirus** détectent le fichier comme malveillant
→ Famille identifiée : **Kryplod / Bazar / Quantum** (loader associé au ransomware Quantum)

## Executive Summary
Le 10 septembre 2021, l'utilisateur hobart.gunnarsson (DESKTOP-KKITB6Q, 10.9.10.102) a été infecté par le malware Kryplod après téléchargement depuis un domaine de typosquatting. Ce loader est typiquement un vecteur d'accès initial précédant un déploiement de ransomware.

## IOCs
- IP malveillante : 194.62.42.206
- Domaine : simpsonsavingss.com
- SHA256 : eed363fc4af7a9070d69340592dcab7c78db4f90710357de29e3b624aa957cf8

## Compétences démontrées
- Analyse de trafic réseau brut (Wireshark, filtres display)
- Extraction d'objets depuis un flux HTTP
- Calcul et vérification de hash (VirusTotal)
- Reconnaissance de patterns d'attaque (typosquatting, dropper/loader)
