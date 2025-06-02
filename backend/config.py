import os
from pathlib import Path
from dotenv import load_dotenv

# Charger les variables d'environnement depuis le fichier .env s'il existe
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

# Configuration de l'API
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1", "t")

# URL d'Ollama
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434")

# Configuration de sécurité
SECRET_KEY = os.getenv("SECRET_KEY", "cle_secrete_par_defaut_a_changer_en_production")

# Origines CORS autorisées
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")