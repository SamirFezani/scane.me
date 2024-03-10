# MSPR 6.1 - Havster et Nester

## Description du Projet

Ce projet consiste en deux composants principaux :

1. **Havster** : Une application Python permettant le scan automatique du réseau local et la génération de résultats au format JSON.
2. **Nester** : Une interface web conviviale pour visualiser les résultats des scans et leur historique. Nester est développé en HTML, CSS et PHP, avec une base de données MySQL pour stocker les données.

## Composants du Projet

### Havster
- **Fonctionnalités** :
  - Scan automatique du réseau local.
  - Génération de résultats au format JSON.
- **Utilisation** : Exécutez l'application Python `havster.py` pour lancer le scan. Les résultats seront sauvegardés dans le fichier `scan_results.json`.

### Nester
- **Fonctionnalités** :
  - Affichage des résultats des scans.
  - Historique des scans précédents.
  - Système de login sécurisé pour restreindre l'accès aux données sensibles.
- **Utilisation** : Déployez les fichiers HTML, CSS et PHP sur un serveur web compatible avec PHP et MySQL. Assurez-vous de configurer la base de données MySQL avec le schéma fourni dans le fichier `database.sql`.

## Sécurité dans Nester

Nester intègre un système de login sécurisé pour garantir la confidentialité des informations réseau. Les utilisateurs doivent s'authentifier avec leurs identifiants pour accéder aux résultats des scans.

## Configuration Requise

- Python 3.x pour Havster.
- Un serveur web compatible avec PHP et MySQL pour Nester.

## Instructions d'Installation et d'Utilisation

### Havster
1. Assurez-vous d'avoir Python 3.x installé sur votre système.
2. Exécutez `havster.py` pour lancer l'application.
3. Suivez les instructions à l'écran pour lancer le scan du réseau.

### Nester
1. Déployez les fichiers HTML, CSS et PHP sur votre serveur web.
2. Importez le fichier `database.sql` dans votre base de données MySQL.
3. Configurez les paramètres de connexion à la base de données dans le fichier `config.php`.
4. Accédez à l'interface web via votre navigateur et connectez-vous avec vos identifiants.

## Auteur
Samir Fezani
Slimani rayane Malik
KOUKOUTHA ARDEL KALEB
Jiovani Dylan MANGNIM

## Licence
Ce projet est sous licence [EPSI]. 
