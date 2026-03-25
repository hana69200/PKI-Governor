import argparse, sys, datetime
from engines.scanner import get_cert_details
from engines.osint import get_all_subdomains, VT_REPUTATIONS
from reports.generator import generate_report

GREEN, YELLOW, RED, RESET = '\033[92m', '\033[93m', '\033[91m', '\033[0m'

def main():
    parser = argparse.ArgumentParser(description="🛡️ PKI Governor Expert v2.0")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file")
    group.add_argument("-t", "--target")
    args = parser.parse_args()

    if args.file:
        with open(args.file, 'r') as f: domains = [l.strip() for l in f if l.strip()]
    else:
        domains = get_all_subdomains(args.target)
        if args.target not in domains: domains.insert(0, args.target)

    now = datetime.datetime.now(datetime.timezone.utc)
    results = []

    print("-" * 115)
    print(f"{'DOMAINE':<30} | {'EXP.':<6} | {'ROBUSTESSE':<25} | {'ALGO':<8} | {'VT':<4}")
    print("-" * 115)

    for d in domains:
        res = get_cert_details(d)
        vt = VT_REPUTATIONS.get(d, "-")
        
        if res.get("error"):
            print(f"{d:<30} | {RED}{'ERR':<6}{RESET} | {'-':<25} | {'-':<8} | {vt:<4} | {res['error'][:20]}")
            results.append({"domain": d, "days": "-", "key_size": "-", "algo": "-", "vt": vt, "status": "ERREUR", "details": res["error"]})
            continue

        days = (res["expire_date"] - now).days
        status = "ATTENTION" if days < 30 else "OK"
        if days < 0: status = "ERREUR"

        # Affichage Terminal simplifié
        k_info = f"{res['key_type']} {res['key_size']}b"
        color = GREEN if status == "OK" else (YELLOW if status == "ATTENTION" else RED)
        print(f"{d:<30} | {color}{days:<4}j{RESET} | {k_info:<25} | {res['sig_algo']:<8} | {vt:<4}")

        results.append({
            "domain": d, "days": f"{days} j", "key_size": res["key_size"], "key_type": res["key_type"],
            "algo": res["sig_algo"], "vt": vt, "status": status, "details": res["issuer"]
        })

    report = generate_report(results, args.target if args.target else "file_audit")
    print("-" * 115)
    print(f"{GREEN}[+] Audit terminé. Rapport : {report}{RESET}")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n[!] Sortie.")
