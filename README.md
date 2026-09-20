# Nivard SOC Lab

Architecture complète de détection : Kali (attaque) vers Windows AD + Sysmon (cible) vers Splunk (SIEM), avec Universal Forwarder pour la remontée de logs. Complété par des exercices d'investigation sur datasets publics (Splunk BOTS, Wireshark).

## Infrastructure
- Splunk Enterprise avec Universal Forwarder Windows
- Sysmon avec configuration de référence (SwiftOnSecurity)
- Active Directory (nivard.local) avec comptes de test

## Cas traités

| # | Cas | Compétences démontrées |
|---|---|---|
| [01](./01-brute-force/) | Brute force (Hydra) | Détection Splunk, alerte temps réel, classification MITRE ATT&CK |
| [02](./02-password-spraying/) | Password spraying | Détection par corrélation (dc), différenciation des patterns d'attaque |
| [03](./03-dashboard-splunk/) | Dashboard Splunk | Visualisation multi-panneaux, SPL avancé |
| [04](./04-phishing-botsv1/) | Investigation phishing (dataset BOTS v1) | Analyse de logs réseau, identification d'IOC, corrélation Suricata |
| [05](./05-wireshark-angry-poutine/) | Analyse malware (Wireshark) | Analyse de trafic brut, extraction de fichiers, identification malware (VirusTotal) |

## Stack technique
Splunk Enterprise, Sysmon, Active Directory, Wireshark, Kali Linux, SPL, MITRE ATT&CK

## Méthodologie
Chaque cas suit un format standardisé : contexte → requêtes/commandes utilisées → conclusion → IOCs, dans une démarche reproductible de type SOC N1.
