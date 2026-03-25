import datetime

def generate_report(results, target_name):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    filename = f"reports/rapport_{target_name}.html"
    
    html = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: sans-serif; background: #f4f7f6; padding: 20px; }}
            table {{ width: 100%; border-collapse: collapse; background: white; }}
            th {{ background: #2c3e50; color: white; padding: 12px; }}
            td {{ border: 1px solid #ddd; padding: 8px; }}
            .OK {{ color: green; font-weight: bold; }}
            .ATTENTION {{ color: orange; font-weight: bold; }}
            .ERREUR {{ color: red; font-weight: bold; }}
            .bad {{ background: #fee; color: red; border: 1px solid red; padding: 2px; }}
        </style>
    </head>
    <body>
        <h2>🛡️ Audit PKI : {target_name}</h2>
        <p>Généré le {now}</p>
        <table>
            <tr><th>Domaine</th><th>Statut</th><th>Émetteur</th><th>VT</th><th>Détails</th></tr>
    """
    for r in results:
        vt_style = 'class="bad"' if r['vt'] != "-" and r['vt'] > 0 else ""
        html += f"<tr><td>{r['domain']}</td><td class='{r['status']}'>{r['status']}</td>"
        html += f"<td>{r['issuer']}</td><td><span {vt_style}>{r['vt']}</span></td><td>{r['details']}</td></tr>"
    
    html += "</table></body></html>"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename
