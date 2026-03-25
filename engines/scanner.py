import socket
import ssl
import datetime

def get_cert_expiry(domain, port=443, timeout=3):
    """Réalise le handshake TLS et extrait les infos du certificat."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extraction et conversion de la date
                expire_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                expire_date = expire_date.replace(tzinfo=datetime.timezone.utc)
                
                # Extraction de l'émetteur (Organisation ou Common Name)
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
                
                return expire_date, issuer_name, None
    except ssl.SSLCertVerificationError: return None, None, "Certificat Invalide"
    except socket.timeout: return None, None, "Timeout réseau"
    except socket.gaierror: return None, None, "Erreur DNS"
    except Exception as e: return None, None, f"Erreur: {str(e)[:20]}"
