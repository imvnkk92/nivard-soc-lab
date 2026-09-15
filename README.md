# Nivard SOC Lab

Architecture complète de détection : Kali (attaque) vers Windows AD + Sysmon (cible) vers Splunk (SIEM), avec Universal Forwarder pour la remontée de logs.

## Ce qui a été mis en place
- Splunk Enterprise avec Universal Forwarder Windows
- Sysmon avec configuration de reference (SwiftOnSecurity)
- Attaque brute force reelle (Hydra) detectee en temps reel
- Alerte Splunk fonctionnelle
- Investigation complete avec classification MITRE ATT&CK

## Voir le rapport complet
incident-report.md
