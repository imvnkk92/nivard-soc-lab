# Phishing / Scan de reconnaissance — Dataset Splunk BOTS v1

## Contexte
Investigation utilisant le dataset public Splunk BOTS v1 (Boss of the SOC), simulant une attaque contre l'entreprise fictive "Wayne Enterprises".

## Chaîne d'investigation

**1. Fichier suspect détecté via trafic HTTP**
```spl
index=botsv1 sourcetype=stream:http (uri="*.exe" OR uri="*.zip" OR uri="*.scr")
| table _time, src_ip, dest_ip, uri, http_user_agent
```
→ Fichier `imreallynotbatman_backup.zip` téléchargé depuis l'IP externe `40.80.148.42`.

**2. Historique complet de l'IP source**
```spl
index=botsv1 src_ip=40.80.148.42
| table _time, sourcetype, dest_ip, uri
| sort _time
```
→ Révèle 17 802 requêtes HTTP en quelques secondes — signature d'un scan automatisé.

**3. Identification de l'alerte IDS (Suricata)**
```spl
index=botsv1 src_ip=40.80.148.42 sourcetype=suricata event_type=alert
| table _time, alert.signature, alert.category
```
→ Signature : **"ET SCAN Acunetix Version 6 (Free Edition) Scan Detected"**
→ Catégorie : **"Attempted Information Leak"**

## Conclusion
Scan de vulnérabilité automatisé (Acunetix) depuis IP externe, suivi du téléchargement d'un fichier suspect — reconnaissance active précédant probablement une exfiltration ou l'installation d'un payload.

## IOCs
- IP source : 40.80.148.42
- Fichier : imreallynotbatman_backup.zip
