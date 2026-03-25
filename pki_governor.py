import socket
import ssl
import datetime
import argparse
import sys
import os
import requests

# Couleurs pour le terminal
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

# Dictionnaire global pour stocker la réputation VirusTotal
VT_REPUTATIONS = {}

def get_cert_expiry(domain, port=443, timeout=3):
    """Récupère la date d'expiration et l'émetteur du certificat SSL/TLS."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                expire_date = expire_date.replace(tzinfo=datetime.timezone.utc)
                
                issuer_name = "Inconnu"
                for item in cert.get('issuer', []):
                    for field in item:
                        if field[0] == 'organizationName':
                            issuer_name = field[1]
                            break
                if issuer_name == "Inconnu":
                    for item in cert.get('issuer', []):
                        for field in item:
                            if field[0] == 'commonName':
                                issuer_name = field[1]
                                break
                
                if len(issuer_name) > 18: issuer_name = issuer_name[:15] + "..."
                return expire_date, issuer_name, None
    except ssl.SSLCertVerificationError: return None, None, "Certificat Invalide"
    except socket.timeout: return None, None, "Timeout réseau"
    except socket.gaierror: return None, None, "Erreur DNS"
    except Exception: return None, None, "Erreur de connexion"

# ==========================================
# MOTEURS OSINT
# ==========================================

def osint_crtsh(domain):
    print(f"  [~] Interrogation de crt.sh...")
    try:
        res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=7)
        if res.status_code == 200:
            return {n.replace('*.', '') for entry in res.json() for n in entry['name_value'].split('\n')}
    except Exception: pass
    return set()

def osint_hackertarget(domain):
    print(f"  [~] Interrogation de HackerTarget...")
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=7)
        if res.status_code == 200:
            return {line.split(',')[0].strip() for line in res.text.split('\n') if ',' in line and line.split(',')[0].strip()}
    except Exception: pass
    return set()

def osint_virustotal(domain):
    print(f"  [~] Interrogation de VirusTotal...")
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print(f"      {YELLOW}ℹ️ Ignoré : Clé API 'VT_API_KEY' non détectée.{RESET}")
        return set()
    
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    try:
        res = requests.get(url, headers=headers, timeout=7)
        if res.status_code == 200:
            subdomains = set()
            # On extrait les domaines ET leur score de malveillance
            for item in res.json().get('data', []):
                sub_name = item['id']
                subdomains.add(sub_name)
                
                # Récupération des stats (ex: combien d'antivirus disent que c'est malveillant)
                stats = item.get('attributes', {}).get('last_analysis_stats', {})
                malicious_score = stats.get('malicious', 0)
                VT_REPUTATIONS[sub_name] = malicious_score
                
            return subdomains
        else:
            print(f"      {RED}Erreur VT: {res.status_code}{RESET}")
    except Exception: pass
    return set()

def get_all_subdomains(domain):
    print(f"\n[*] 🔍 Découverte OSINT Multi-Sources pour : *.{domain}")
    all_subdomains = set()
    all_subdomains.update(osint_crtsh(domain))
    all_subdomains.update(osint_hackertarget(domain))
    all_subdomains.update(osint_virustotal(domain))
    
    result = list(all_subdomains)[:40]
    print(f"[+] {len(result)} sous-domaines uniques trouvés au total !\n")
    return result

# ==========================================
# PROGRAMME PRINCIPAL
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="🛡️ PKI Governor - Auditeur de certificats SSL/TLS")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Fichier texte avec la liste des domaines")
    group.add_argument("-t", "--target", help="Domaine cible pour l'auto-découverte (ex: github.com)")
    parser.add_argument("-w", "--warning", type=int, default=30, help="Seuil d'alerte en jours (défaut: 30)")
    args = parser.parse_args()

    domains = []
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{RED}[-] Erreur : Fichier '{args.file}' introuvable.{RESET}")
            sys.exit(1)
        with open(args.file, 'r') as file:
            domains = [line.strip() for line in file if line.strip() and not line.startswith('#')]
    elif args.target:
        domains = get_all_subdomains(args.target)
        if args.target not in domains:
            domains.insert(0, args.target)

    if not domains:
        print(f"{RED}[-] Aucun domaine à analyser.{RESET}")
        sys.exit(0)

    print(f"[*] Démarrage de l'audit PKI...")
    print(f"[*] Seuil d'alerte critique configuré à : {args.warning} jours")
    
    # Le tableau est élargi pour la nouvelle colonne RÉPUTATION
    print("-" * 110)
    print(f"{'DOMAINE':<30} | {'STATUT':<10} | {'ÉMETTEUR':<18} | {'RÉPUTATION':<12} | {'DÉTAILS'}")
    print("-" * 110)

    now = datetime.datetime.now(datetime.timezone.utc)

    for domain in domains:
        expire_date, issuer, error = get_cert_expiry(domain)
        
        # Formatage du score VirusTotal
        vt_score_display = "-"
        if domain in VT_REPUTATIONS:
            malicious = VT_REPUTATIONS[domain]
            if malicious > 0:
                vt_score_display = f"{RED}🚨 {malicious} alertes{RESET}"
            else:
                vt_score_display = f"{GREEN}✅ Clean{RESET}"

        if error:
            print(f"{domain:<30} | {RED}{'ERREUR':<10}{RESET} | {'-':<18} | {vt_score_display:<21} | {error}")
            continue

        delta = expire_date - now
        days_left = delta.days

        if days_left < 0:
            print(f"{domain:<30} | {RED}{'EXPIRÉ':<10}{RESET} | {issuer:<18} | {vt_score_display:<21} | Expiré depuis {abs(days_left)} jours !")
        elif days_left <= args.warning:
            print(f"{domain:<30} | {YELLOW}{'ATTENTION':<10}{RESET} | {issuer:<18} | {vt_score_display:<21} | Expire dans {days_left} j ({expire_date.strftime('%Y-%m-%d')})")
        else:
            print(f"{domain:<30} | {GREEN}{'OK':<10}{RESET} | {issuer:<18} | {vt_score_display:<21} | Expire dans {days_left} jours")

    print("-" * 110)
    print("[*] Audit terminé.\n")

# C'est ici que l'on gère le Ctrl+C !
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Intercepte le Ctrl+C proprement
        print(f"\n\n{YELLOW}[!] Interruption clavier détectée.{RESET}")
        print(f"{GREEN}[*] Nettoyage en cours... Vous avez quitté le programme. À bientôt !{RESET}\n")
        sys.exit(0)
    except Exception as e:
        # Intercepte toute autre erreur grave non prévue
        print(f"\n{RED}[-] Une erreur inattendue est survenue : {e}{RESET}\n")
        sys.exit(1)
