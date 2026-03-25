# 🛡️ PKI Governor v2.0 - Audit & Threat Intelligence

**PKI Governor** est un outil d'audit de sécurité spécialisé dans l'analyse des certificats SSL/TLS et la découverte de sous-domaines (OSINT). Conçu pour un usage en milieu professionnel (Niveau N3), il permet de surveiller la conformité cryptographique d'un parc de domaines et de détecter d'éventuelles menaces.

---

## 🚀 Fonctionnalités Clés

- **Découverte OSINT Multi-sources** : Identification automatique des sous-domaines via `crt.sh`, `HackerTarget` et `VirusTotal`.
- **Audit Cryptographique Profond** : 
    - Analyse de la robustesse des clés (Distinction entre **RSA** et **ECC 256** "Ultra-Moderne").
    - Vérification des algorithmes de signature (ex: **SHA-256**).
    - Calcul précis des jours restants avant expiration.
- **Threat Intelligence** : Intégration des scores de réputation **VirusTotal** pour identifier les domaines malveillants.
- **Rapports Professionnels** : Génération automatique d'un rapport **HTML** moderne et visuel avec badges de sécurité.
- **Gestion des Erreurs** : Identification et rapport des erreurs de résolution DNS (Shadow IT).

---

## 🛠️ Installation et Prérequis

Le projet utilise un environnement virtuel Python pour garantir la stabilité du système et isoler les dépendances.

### 1. Installation de la bibliothèque Cryptography
Nous utilisons la bibliothèque `cryptography` pour l'analyse avancée des certificats. L'installation se fait dans un environnement virtuel (`venv`).

```bash
# Créer l'environnement virtuel
python3 -m venv .venv

# Activer l'environnement
source .venv/bin/activate

# Installer les dépendances nécessaires
pip install cryptography requests
