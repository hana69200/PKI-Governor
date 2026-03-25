import argparse, sys, os, datetime
from engines.scanner import get_cert_expiry
from engines.osint import get_all_subdomains, VT_REPUTATIONS
from reports.generator import generate_report

GREEN, YELLOW, RED, RESET = '\033[92m', '\033[93m', '\033[91m', '\033[0m'

def main():
    parser = argparse.ArgumentParser(description="🛡️ PKI Governor v2 - Architecture Modulaire")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Liste de domaines")
    group.add_argument("-t", "--target", help="Domaine pour OSINT")
    parser.add_argument("-w", "--warning", type=int, default=30)
    args = parser.parse_args()

    domains = []
    if args.file:
        with open(args.file, 'r') as f: domains = [l.strip() for l in f if l.strip()]
    else:
        domains = get_all_subdomains(args.target)
        if args.target not in domains: domains.insert(0, args.target)

    print(f"[*] Audit de {len(domains)} domaines...")
    results_for_report = []
    now = datetime.datetime.now(datetime.timezone.utc)

    for d in domains:
        exp, issuer, err = get_cert_expiry(d)
        vt_score = VT_REPUTATIONS.get(d, "-")
        status = "ERREUR" if err else ("ATTENTION" if (exp - now).days <= args.warning else "OK")
        
        print(f"[{status}] {d}")
        results_for_report.append({
            "domain": d, "status": status, "issuer": issuer if issuer else "-",
            "vt": vt_score, "details": err if err else f"Expire dans {(exp - now).days} j"
        })

    report_path = generate_report(results_for_report, args.target if args.target else "file_audit")
    print(f"{GREEN}[+] Terminé. Rapport disponible : {report_path}{RESET}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n{YELLOW}[!] Arrêt du programme.{RESET}")
