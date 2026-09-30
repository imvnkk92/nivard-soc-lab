#!/usr/bin/env python3
"""
ioc_enrich.py — Outil d'enrichissement d'indicateurs de compromission (IOC)

Interroge l'API VirusTotal v3 pour un hash, une IP ou un domaine, et retourne
un verdict synthétique (malveillant / suspect / propre) avec le détail des
moteurs antivirus qui le détectent. Pensé pour être branché sur les alertes
d'un SOC (Splunk, TheHive...) afin d'automatiser la première étape de
qualification d'une alerte : "cet indicateur est-il déjà connu comme malveillant ?"

Utilisation :
    export VT_API_KEY="ta_cle_api_virustotal"

    # Un seul indicateur
    python3 ioc_enrich.py 8.8.8.8
    python3 ioc_enrich.py malware.example.com
    python3 ioc_enrich.py 44d88612fea8a8f36de82e1278abb02f

    # Plusieurs indicateurs depuis un fichier (un IOC par ligne)
    python3 ioc_enrich.py --file iocs.txt --out rapport.csv

Une clé API VirusTotal gratuite (4 requêtes/minute) suffit pour ce script :
https://www.virustotal.com/gui/join-us
"""

import argparse
import csv
import ipaddress
import os
import re
import sys
import time

import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def detect_ioc_type(ioc: str) -> str:
    """Devine le type d'IOC : hash, ip ou domain."""
    ioc = ioc.strip()
    if HASH_RE.match(ioc):
        return "hash"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    return "domain"


def vt_endpoint(ioc_type: str, ioc: str) -> str:
    if ioc_type == "hash":
        return f"{VT_BASE_URL}/files/{ioc}"
    if ioc_type == "ip":
        return f"{VT_BASE_URL}/ip_addresses/{ioc}"
    return f"{VT_BASE_URL}/domains/{ioc}"


def query_virustotal(ioc: str, api_key: str) -> dict:
    """Interroge VirusTotal et retourne un résumé exploitable pour un analyste SOC."""
    ioc_type = detect_ioc_type(ioc)
    url = vt_endpoint(ioc_type, ioc)
    headers = {"x-apikey": api_key}

    resp = requests.get(url, headers=headers, timeout=15)

    if resp.status_code == 404:
        return {
            "ioc": ioc,
            "type": ioc_type,
            "verdict": "INCONNU",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_engines": 0,
            "reputation": "N/A",
            "detail": "Non référencé dans VirusTotal (à ne pas confondre avec 'propre')",
        }

    resp.raise_for_status()
    data = resp.json()["data"]["attributes"]

    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    total = sum(stats.values()) if stats else 0

    if malicious >= 5:
        verdict = "MALVEILLANT"
    elif malicious > 0 or suspicious >= 3:
        verdict = "SUSPECT"
    else:
        verdict = "PROPRE"

    return {
        "ioc": ioc,
        "type": ioc_type,
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total_engines": total,
        "reputation": data.get("reputation", "N/A"),
        "detail": f"{malicious}/{total} moteurs le détectent comme malveillant",
    }


def print_result(result: dict) -> None:
    verdict_icon = {
        "MALVEILLANT": "🔴",
        "SUSPECT": "🟠",
        "PROPRE": "🟢",
        "INCONNU": "⚪",
    }.get(result["verdict"], "⚪")

    print(f"\n{verdict_icon} {result['ioc']}  [{result['type']}]")
    print(f"   Verdict     : {result['verdict']}")
    print(f"   Détection   : {result['detail']}")
    print(f"   Réputation  : {result['reputation']}")


def run_batch(iocs: list, api_key: str, out_path: str = None) -> None:
    results = []
    for i, ioc in enumerate(iocs):
        ioc = ioc.strip()
        if not ioc:
            continue
        try:
            result = query_virustotal(ioc, api_key)
        except requests.HTTPError as exc:
            result = {
                "ioc": ioc, "type": "?", "verdict": "ERREUR",
                "malicious": "", "suspicious": "", "harmless": "",
                "total_engines": "", "reputation": "",
                "detail": str(exc),
            }
        results.append(result)
        print_result(result)

        # Respecte le quota API gratuit (4 requêtes/minute)
        if i < len(iocs) - 1:
            time.sleep(16)

    if out_path:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"\nRapport exporté : {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Enrichissement d'IOC via VirusTotal")
    parser.add_argument("ioc", nargs="?", help="Un hash, une IP ou un domaine")
    parser.add_argument("--file", help="Fichier texte contenant un IOC par ligne")
    parser.add_argument("--out", help="Fichier CSV de sortie (utilisé avec --file)")
    args = parser.parse_args()

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        sys.exit("Erreur : variable d'environnement VT_API_KEY manquante.")

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            iocs = f.readlines()
        run_batch(iocs, api_key, args.out)
    elif args.ioc:
        result = query_virustotal(args.ioc, api_key)
        print_result(result)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
