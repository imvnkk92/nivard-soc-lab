IOC Enrichment Tool

Outil Python d'enrichissement automatique d'indicateurs de compromission (IOC) via l'API VirusTotal, développé pour accélérer la qualification des alertes de mon lab SOC (Nivard SOC Lab).

Pourquoi ce script

Lors d'une investigation SOC, une des premières étapes face à un hash, une IP ou un domaine suspect est de vérifier sa réputation. Fait manuellement sur le site VirusTotal, ça prend du temps pour chaque IOC. Ce script automatise cette vérification et retourne un verdict exploitable directement (MALVEILLANT / SUSPECT / PROPRE / INCONNU), avec le détail du nombre de moteurs antivirus qui le détectent.

Fonctionnalités
Détection automatique du type d'IOC (hash MD5/SHA1/SHA256, IP, domaine)
Verdict synthétique basé sur les statistiques de détection VirusTotal
Mode unitaire (un IOC en ligne de commande) ou batch (liste d'IOC depuis un fichier)
Export CSV pour intégration dans un rapport d'incident
Respect du quota de l'API gratuite VirusTotal (4 requêtes/minute)
Utilisation

pip install requests
export VT_API_KEY="ta_cle_api_virustotal"

python3 ioc_enrich.py 8.8.8.8
python3 ioc_enrich.py --file iocs.txt --out rapport.csv

Exemple de sortie

44d88612fea8a8f36de82e1278abb02f [hash]
Verdict : MALVEILLANT
Détection : 62/72 moteurs le détectent comme malveillant
Réputation : -85

Pistes d'évolution
Intégration directe avec l'API TheHive pour enrichir automatiquement un cas ouvert
Ajout d'autres sources (AbuseIPDB, Shodan) pour croiser les verdicts
Webhook Splunk pour déclencher l'enrichissement dès la remontée d'une alerte
Contexte

Développé dans le cadre de mon lab personnel de détection SOC (Splunk / Active Directory / Sysmon) : github.com/imvnkk92/nivard-soc-lab
