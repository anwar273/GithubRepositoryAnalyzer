# 🔐 Analyseur de Vulnérabilités GitHub – Application Fullstack

Ce projet est une application fullstack permettant d’analyser les vulnérabilités dans des dépôts GitHub à l’aide d’un backend Python (FastAPI) et d’un frontend React.js. Ce guide explique pas à pas comment exécuter le projet localement.

---

## 🧰 Technologies Utilisées

- **Frontend** : React.js (`react-scripts`)
- **Backend** : FastAPI + Uvicorn
- **Langages** : JavaScript, Python
- **Librairies backend** : `aiohttp`, `gitpython`, `pydantic`, `fpdf`, etc.
- **Librairies frontend** : `react-chartjs-2`, `react-router-dom`, `chart.js`, etc.

---

## 📦 Prérequis

Avant de commencer, assure-toi d’avoir les éléments suivants installés sur ta machine :

- **Node.js** (version 16 ou 18 recommandée) : [https://nodejs.org](https://nodejs.org)
- **Python** (≥ 3.10) : [https://python.org](https://python.org)
- **Git**

---

## 🚀 Installation et Lancement du Projet

### 1️⃣ Cloner le dépôt

```bash
git clone https://github.com/votre-utilisateur/nom-du-repo.git
cd nom-du-repo
```

---

## 🔙 Lancement du Backend (FastAPI)

### Étape 1 : Se placer dans le dossier `backend`

```bash
cd backend
```

### Étape 2 : Créer un environnement virtuel

```bash
python -m venv venv
```

### Étape 3 : Activer l’environnement virtuel

- **Sous Linux/macOS :**

```bash
source venv/bin/activate
```

- **Sous Windows :**

```bash
venv\Scripts\activate
```

### Étape 4 : Installer les dépendances Python

```bash
pip install -r requirements.txt
```

### Étape 5 : Lancer le serveur FastAPI

```bash
uvicorn main:app --reload
```

> ⚠️ Assure-toi que le fichier `main.py` contient bien l’instance `app = FastAPI()`.

---

## 🖥️ Lancement du Frontend (React)

### Étape 1 : Ouvrir un nouveau terminal et se placer dans le dossier `frontend`

```bash
cd frontend
```

### Étape 2 : Installer les dépendances Node.js

```bash
npm install
```

### Étape 3 : Lancer l’application React

```bash
npm start
```

> L’application sera accessible à l’adresse : [http://localhost:3000](http://localhost:3000)

---

## 📂 Arborescence du Projet

```
.
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   └── ...
├── frontend/
│   ├── src/
│   ├── package.json
│   └── ...
└── README.md
```

---

## 🧪 Tests

### Pour lancer les tests backend (avec `pytest`) :

```bash
cd backend
pytest
```

### Pour lancer les tests frontend :

```bash
cd frontend
npm test
```

---

## 🙌 Aide

Si tu rencontres un problème lors de l’installation ou de l’exécution, vérifie :

- Que tu es bien dans le bon dossier (`frontend/` ou `backend/`)
- Que les ports 3000 (frontend) et 8000 (backend) sont libres
- Que les versions de Python/Node.js sont compatibles
- Que les fichiers `requirements.txt` et `package.json` sont présents

---

## 📝 Auteur

Ce projet a été développé par Mohamed Anwar Quibane
N’hésitez pas à créer une _issue_ pour toute question ou bug rencontré.

---
