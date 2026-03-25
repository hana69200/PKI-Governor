import datetime

def generate_report(results, target):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    filename = f"reports/rapport_{target}.html"
    
    html = f"""
    <html><head><meta charset="UTF-8"><style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #eceff1; padding: 30px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        th {{ background: #263238; color: white; padding: 15px; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #eee; }}
        .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }}
        .status-OK {{ color: #2e7d32; font-weight: bold; }}
        .status-ERREUR {{ color: #c62828; font-weight: bold; }}
        .key-modern {{ background: #e3f2fd; color: #1565c0; border: 1px solid #1565c0; }}
        .key-standard {{ background: #e8f5e9; color: #2e7d32; border: 1px solid #2e7d32; }}
        .key-weak {{ background: #ffebee; color: #c62828; border: 1px solid #c62828; }}
        .vt-warn {{ background: #ffccbc; color: #d84315; }}
        .err-row {{ background-color: #fff8f8; }}
    </style></head><body>
        <h1>🛡️ Rapport d'Audit PKI : {target}</h1>
        <p>Généré le : {now} | Analyse de Robustesse et Menaces</p>
        <table>
            <tr><th>Domaine</th><th>Jours</th><th>Robustesse de la Clé</th><th>Algo Signature</th><th>VT</th><th>Statut / Détails</th></tr>
    """
    for r in results:
        # Traduction humaine de la technologie de clé
        k_val = r.get('key_size')
        k_type = r.get('key_type', '')
        
        if k_val == "-":
            k_display, k_class = "-", ""
        elif k_type == "ECC" and k_val <= 256:
            k_display, k_class = "Ultra-Moderne (ECC 256)", "key-modern"
        elif k_val >= 2048:
            k_display, k_class = f"Standard (RSA {k_val})", "key-standard"
        else:
            k_display, k_class = f"Faible ({k_val} bits)", "key-weak"

        row_class = "class='err-row'" if r['status'] == "ERREUR" else ""
        vt_style = "class='badge vt-warn'" if isinstance(r['vt'], int) and r['vt'] > 0 else ""
        
        html += f"""
            <tr {row_class}>
                <td><strong>{r['domain']}</strong></td>
                <td>{r['days']}</td>
                <td><span class="badge {k_class}">{k_display}</span></td>
                <td>{r['algo']}</td>
                <td><span {vt_style}>{r['vt']}</span></td>
                <td class="status-{r['status']}">{r['status']} <br><small style="color:#666">{r['details']}</small></td>
            </tr>
        """
    html += "</table></body></html>"
    with open(filename, "w", encoding="utf-8") as f: f.write(html)
    return filename
