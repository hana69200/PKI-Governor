# 🛡️ PKI Governor

Un outil d'audit et de gouvernance automatisé pour la surveillance des certificats SSL/TLS, développé en Python.

## 🎯 Le problème métier (Pourquoi cet outil ?)
Dans les architectures complexes (Cloud, architectures n-tiers, milieux industriels/OT), l'expiration silencieuse d'un certificat SSL/TLS est l'une des causes principales d'interruption de service critique. 
Cet outil répond à un besoin de **Gouvernance N3** : auditer en masse un parc de noms de domaine, anticiper les expirations et alerter les équipes opérationnelles avant que la panne ou la faille de sécurité ne se produise.

## ✨ Fonctionnalités
- **Audit de masse :** Lecture depuis un fichier texte de configuration.
- **Vérification cryptographique :** Connexion directe au socket sécurisé pour récupérer le certificat public réel (sans dépendre d'API tierces).
- **Triage intelligent :** Calcul des jours restants et mise en évidence des domaines à risque selon un seuil personnalisable.
- **DevSecOps friendly :** Code robuste (gestion des timeouts, des erreurs DNS et des certificats auto-signés) utilisant uniquement des bibliothèques standards.

## 🚀 Installation & Prérequis
Ce projet ne nécessite aucune dépendance externe lourde. Il utilise uniquement les bibliothèques standards de Python 3.

```bash
# Cloner le dépôt
git clone [https://github.com/hana69200/PKI-Governor.git](https://github.com/hana69200/PKI-Governor.git)
cd PKI-Governor
