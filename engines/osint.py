import requests
import os

# Dictionnaire global pour la réputation (partagé via import)
VT_REPUTATIONS = {}

def osint_crtsh(domain):
    try:
        res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=7)
        if res.status_code == 200:
            return {n.replace('*.', '') for entry in res.json() for n in entry['name_value'].split('\n')}
    except: pass
    return set()

def osint_hackertarget(domain):
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=7)
        if res.status_code == 200:
            return {line.split(',')[0].strip() for line in res.text.split('\n') if ',' in line}
    except: pass
    return set()

def osint_virustotal(domain):
    api_key = os.getenv("VT_API_KEY")
    if not api_key: return set()
    headers = {"x-apikey": api_key}
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40", headers=headers, timeout=7)
        if res.status_code == 200:
            subdomains = set()
            for item in res.json().get('data', []):
                sub_name = item['id']
                subdomains.add(sub_name)
                stats = item.get('attributes', {}).get('last_analysis_stats', {})
                VT_REPUTATIONS[sub_name] = stats.get('malicious', 0)
            return subdomains
    except: pass
    return set()

def get_all_subdomains(domain):
    print(f"[*] 🔍 Recherche multi-sources pour {domain}...")
    subs = set()
    subs.update(osint_crtsh(domain))
    subs.update(osint_hackertarget(domain))
    subs.update(osint_virustotal(domain))
    return list(subs)[:40]
