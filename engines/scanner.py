import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def get_cert_details(domain, port=443, timeout=3):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_obj = x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # Extraction du type de clé
                pub_key = cert_obj.public_key()
                key_type = "RSA" if isinstance(pub_key, rsa.RSAPublicKey) else "ECC"
                
                return {
                    "expire_date": cert_obj.not_valid_after_utc,
                    "key_size": pub_key.key_size,
                    "key_type": key_type,
                    "sig_algo": cert_obj.signature_hash_algorithm.name,
                    "issuer": cert_obj.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value if cert_obj.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) else "Inconnu",
                    "error": None
                }
    except socket.gaierror: return {"error": "DNS: Introuvable"}
    except socket.timeout: return {"error": "Connexion: Timeout"}
    except Exception as e: return {"error": str(e)[:30]}
