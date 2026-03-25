import socket
import ssl
import datetime
import argparse
import sys
import os

# Couleurs pour le terminal (ANSI)
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

def get_cert_expiry(domain, port=443, timeout=3):
    """
    Se connecte à un domaine et récupère la date d'expiration de son certificat SSL/TLS.
    """
    context = ssl.create_default_context()
    
    try:
        # Création d'une connexion réseau avec un timeout de sécurité
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Le format standard renvoyé est : 'Oct 25 23:59:59 2024 GMT'
                expire_date_str = cert['notAfter']
                expire_date = datetime.datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                return expire_date, None
                
    except ssl.SSLCertVerificationError as e:
        return None, f"Certificat Invalide/Expiré"
    except socket.timeout:
        return None, "Timeout (Serveur injoignable)"
    except socket.gaierror:
        return None, "Erreur DNS (Domaine introuvable)"
    except Exception as e:
        return None, f"Erreur de connexion"

def main():
    parser = argparse.ArgumentParser(description="🛡️ PKI Governor - Auditeur de certificats SSL/TLS")
    parser.add_argument("-f", "--file", required=True, help="Fichier texte contenant la liste des domaines (un par ligne)")
    parser.add_argument("-w", "--warning", type=int, default=30, help="Seuil d'alerte en jours (défaut: 30)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"{RED}[-] Erreur : Le fichier '{args.file}' n'existe pas.{RESET}")
        sys.exit(1)

    print(f"\n[*] Démarrage de l'audit PKI...")
    print(f"[*] Seuil d'alerte critique configuré à : {args.warning} jours")
    print("-" * 70)
    print(f"{'DOMAINE':<30} | {'STATUT':<15} | {'DÉTAILS'}")
    print("-" * 70)

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # Lecture sécurisée du fichier
    with open(args.file, 'r') as file:
        domains = [line.strip() for line in file if line.strip() and not line.startswith('#')]

    for domain in domains:
        expire_date, error = get_cert_expiry(domain)

        if error:
            print(f"{domain:<30} | {RED}{'ERREUR':<15}{RESET} | {error}")
            continue

        # Calcul de la différence entre la date d'expiration et aujourd'hui
        delta = expire_date - now
        days_left = delta.days

        if days_left < 0:
            print(f"{domain:<30} | {RED}{'EXPIRÉ':<15}{RESET} | Expiré depuis {abs(days_left)} jours !")
        elif days_left <= args.warning:
            print(f"{domain:<30} | {YELLOW}{'ATTENTION':<15}{RESET} | Expire dans {days_left} jours ({expire_date.strftime('%Y-%m-%d')})")
        else:
            print(f"{domain:<30} | {GREEN}{'OK':<15}{RESET} | Expire dans {days_left} jours")

    print("-" * 70)
    print("[*] Audit terminé.\n")

if __name__ == "__main__":
    main()
