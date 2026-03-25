import requests
import os

VT_REPUTATIONS = {}

def osint_crtsh(domain):
    try:
        res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=7)
        return {n.replace('*.', '') for entry in res.json() for n in entry['name_value'].split('\n')} if res.status_code == 200 else set()
    except: return set()

def osint_hackertarget(domain):
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=7)
        return {line.split(',')[0].strip() for line in res.text.split('\n') if ',' in line} if res.status_code == 200 else set()
    except: return set()

def osint_virustotal(domain):
    api_key = os.getenv("VT_API_KEY")
    if not api_key: return set()
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40", headers={"x-apikey": api_key}, timeout=7)
        if res.status_code == 200:
            subs = set()
            for item in res.json().get('data', []):
                name = item['id']
                subs.add(name)
                VT_REPUTATIONS[name] = item.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            return subs
    except: pass
    return set()

def get_all_subdomains(domain):
    print(f"[*] 🔍 OSINT en cours pour {domain}...")
    subs = set()
    subs.update(osint_crtsh(domain))
    subs.update(osint_hackertarget(domain))
    subs.update(osint_virustotal(domain))
    return list(subs)[:40]
