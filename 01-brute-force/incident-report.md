# Ticket SOC #001 — Nivard Security Operations

## Résumé

| Champ | Valeur |
|---|---|
| Alerte initiale | Détection Brute Force - testuser (Splunk) |
| Date de l'incident | 15/09/2026 |
| Cible | SRV-AD (192.168.1.10) — Contrôleur de domaine Windows |
| Compte visé | testuser |
| Protocole attaqué | SMB (port 445) |
| Sévérité | Critique |
| Statut | Vrai Positif — Compromission confirmée |

## Contexte

Une supervision de sécurité a été mise en place sur l'infrastructure Nivard Solutions : un contrôleur de domaine Windows (SRV-AD) équipé de Sysmon, dont les logs sont collectés via un Splunk Universal Forwarder et centralisés dans Splunk Enterprise (SRV-SIEM). Une attaque par brute force a été simulée depuis Kali Linux, dans le cadre d'un test de détection autorisé sur infrastructure personnelle.

## Investigation

### Détection initiale

index=main EventCode=4625 Nom_du_compte=testuser
| stats count

Résultat : plus de 1200 tentatives de connexion échouées enregistrées.

### Origine de l'attaque
- Outil identifié : Hydra (THC-Hydra v9.7)
- Méthode : test de mots de passe (wordlist ciblée) contre testuser via SMB
- Machine source : Kali Linux

### Confirmation de compromission
Après plusieurs centaines d'échecs (Event Code 4625), une connexion réussie a été identifiée (Event Code 4624) sur le même compte, confirmant la compromission.

## Classification MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |

## Conclusion

Vrai Positif — Sévérité Critique. Le compte testuser a été compromis.

## Actions recommandées

1. Réinitialisation immédiate du mot de passe compromis
2. Activation d'une politique de verrouillage de compte
3. Restriction de l'accès SMB/RDP depuis l'extérieur du réseau de confiance
4. Mise en place d'une authentification multifacteur (MFA)
5. Maintien de l'alerte Splunk créée

## Alerte Splunk mise en place


index=main EventCode=4625 Nom_du_compte=testuser
| stats count
| where count > 5

Planification : toutes les 5 minutes. Déclenchement : nombre de résultats > 0.

## Architecture de détection

Kali Linux (attaquant)
|
v
SRV-AD (Windows Server + Sysmon)
| Splunk Universal Forwarder
v
SRV-SIEM (Splunk Enterprise) — analyse, alerting
