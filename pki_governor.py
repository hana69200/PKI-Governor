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

def get_cert_expiry(domain, port=443, timeout=3):
    """Récupère la date d'expiration et l'émetteur du certificat SSL/TLS."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # 1. Extraction de la date
                expire_date_str = cert['notAfter']
                expire_date = datetime.datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                expire_date = expire_date.replace(tzinfo=datetime.timezone.utc)
                
                # 2. Extraction propre de l'émetteur (Issuer)
                issuer_name = "Inconnu"
                for item in cert.get('issuer', []):
                    for field in item:
                        # On cherche d'abord le nom de l'organisation (O)
                        if field[0] == 'organizationName':
                            issuer_name = field[1]
                            break
                # Si pas d'organisation, on prend le nom commun (CN)
                if issuer_name == "Inconnu":
                    for item in cert.get('issuer', []):
                        for field in item:
                            if field[0] == 'commonName':
                                issuer_name = field[1]
                                break
                
                # On raccourcit le nom s'il est trop long pour le tableau
                if len(issuer_name) > 20:
                    issuer_name = issuer_name[:17] + "..."
                    
                return expire_date, issuer_name, None
                
    except ssl.SSLCertVerificationError:
        return None, None, "Certificat Invalide"
    except socket.timeout:
        return None, None, "Timeout réseau"
    except socket.gaierror:
        return None, None, "Erreur DNS"
    except Exception:
        return None, None, "Erreur de connexion"

def get_subdomains_from_crtsh(base_domain):
    """Découvre dynamiquement les sous-domaines via l'API crt.sh."""
    print(f"\n[*] 🔍 Découverte OSINT en cours pour : *.{base_domain} ...")
    url = f"https://crt.sh/?q=%.{base_domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                name = entry['name_value']
                for n in name.split('\n'):
                    subdomains.add(n.replace('*.', ''))
            result_list = list(subdomains)[:30]
            print(f"[+] {len(result_list)} sous-domaines trouvés !\n")
            return result_list
        else:
            print(f"{RED}[-] Erreur API crt.sh (Code: {response.status_code}){RESET}\n")
            return []
    except requests.exceptions.RequestException:
        print(f"{RED}[-] Impossible de joindre crt.sh (Timeout){RESET}\n")
        return []

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
        domains = get_subdomains_from_crtsh(args.target)
        if args.target not in domains:
            domains.insert(0, args.target)

    if not domains:
        print(f"{RED}[-] Aucun domaine à analyser.{RESET}")
        sys.exit(0)

    print(f"[*] Démarrage de l'audit PKI...")
    print(f"[*] Seuil d'alerte critique configuré à : {args.warning} jours")
    
    # Tableau élargi pour accueillir l'émetteur
    print("-" * 95)
    print(f"{'DOMAINE':<30} | {'STATUT':<10} | {'ÉMETTEUR':<20} | {'DÉTAILS'}")
    print("-" * 95)

    now = datetime.datetime.now(datetime.timezone.utc)

    for domain in domains:
        expire_date, issuer, error = get_cert_expiry(domain)

        if error:
            print(f"{domain:<30} | {RED}{'ERREUR':<10}{RESET} | {'-':<20} | {error}")
            continue

        delta = expire_date - now
        days_left = delta.days

        if days_left < 0:
            print(f"{domain:<30} | {RED}{'EXPIRÉ':<10}{RESET} | {issuer:<20} | Expiré depuis {abs(days_left)} jours !")
        elif days_left <= args.warning:
            print(f"{domain:<30} | {YELLOW}{'ATTENTION':<10}{RESET} | {issuer:<20} | Expire dans {days_left} j ({expire_date.strftime('%Y-%m-%d')})")
        else:
            print(f"{domain:<30} | {GREEN}{'OK':<10}{RESET} | {issuer:<20} | Expire dans {days_left} jours")

    print("-" * 95)
    print("[*] Audit terminé.\n")

if __name__ == "__main__":
    main()
