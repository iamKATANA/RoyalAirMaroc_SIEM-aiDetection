#  Détection d'Anomalies Réseau - Royal Air Maroc

Ce projet propose une plateforme complète de **surveillance des logs réseau** avec :
- IA intégrée (Random Forest + Cohere pour l'analyse),
- interface Web interactive (HTML/CSS/JS),
- backend en **FastAPI** avec **WebSocket**,
- visualisation en temps réel des **logs critiques**, **classement des utilisateurs suspects**,
- **assistant cybersécurité IA**, 
- et un **firewall animé** affichant les IPs critiques de manière graphique.

---

##  Fonctionnalités principales

-  **Streaming WebSocket temps réel** des logs réseau (CSV simulé ou en direct)
-  **Détection automatique des anomalies critiques** via un modèle IA RandomForest
-  **Assistant IA** (via Cohere) qui analyse les actions suspectes et propose des recommandations
-  **Animation graphique du Firewall** : IPs critiques qui apparaissent autour du pare-feu
-  **Dashboard visual** :
  - Logs temps réel
  - Classement des utilisateurs les plus suspects
  - Zone critique avec actions potentiellement malveillantes
  - Connexions IP vers Firewall

---

##  Structure du projet

├── backend/
│ ├── main.py # Backend FastAPI avec WebSocket et routes API
│ ├── security_logs_royalairmaroc_melange.csv # Données de logs réseau
│
├── frontend/
│ ├── static/
│ │ └── index.html # Interface HTML + CSS + JS avec animations

##  Technologies utilisées

- **FastAPI** (Python)
- **WebSocket**
- **Scikit-learn** (RandomForestClassifier)
- **Cohere API** (analyse IA des attaques)
- **HTML/CSS/JS** pour l'interface
- **Pandas** pour le traitement des logs
- **WebSocket côté JS** pour la communication en temps réel

---

##  IA intégrée

- Détection des anomalies via un modèle RandomForest entraîné sur des colonnes (`Hour`, `event_type`, `action`, `status`, `protocol`)
- IP suspectes scorées de 0 à 100
- IA Cohere intégrée pour analyser le comportement des utilisateurs et suggérer le type d'attaque et des contre-mesures

---

##  Exécution

### 1. Lancer le backend :

```bash

uvicorn backend.main:app --reload

http://localhost:8000/static/index.html
