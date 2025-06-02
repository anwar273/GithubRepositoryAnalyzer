from fastapi import FastAPI, HTTPException, Depends, Body, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
import os
import tempfile
import shutil
import json
from datetime import datetime

# Import du module de configuration
from config import ALLOWED_ORIGINS, OLLAMA_API_URL, DEBUG

# Import des modules personnalisés
from github import GitHubAPI
from ollama import OllamaManager
from analyzer import RepositoryAnalyzer
from report import ReportGenerator

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Création de l'application FastAPI
app = FastAPI(title="Analyseur de Vulnérabilités GitHub")

# Configuration CORS pour permettre les requêtes depuis le frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modèles de données
class GitHubToken(BaseModel):
    token: str

class Repository(BaseModel):
    name: str
    full_name: str
    description: Optional[str] = None
    html_url: str
    created_at: str
    updated_at: str
    stargazers_count: int
    language: Optional[str] = None
    default_branch: str

class AnalysisRequest(BaseModel):
    token: str
    repo_name: str
    models: List[str] = []  # Si vide, tous les modèles disponibles seront utilisés

class AnalysisStatus(BaseModel):
    task_id: str
    status: str
    progress: float = 0.0
    result: Optional[Dict[str, Any]] = None

class VulnerabilityReport(BaseModel):
    repo_name: str
    analysis_date: str
    vulnerabilities: List[Dict[str, Any]]
    summary: Dict[str, Any]
    best_model: str

# Stockage des tâches en cours (en mémoire - à remplacer par une base de données pour la production)
tasks = {}

# Route pour tester la connexion
@app.get("/api/health")
def health_check():
    return {"status": "ok", "message": "Service opérationnel"}

# Route pour valider un token GitHub
@app.post("/api/auth/validate")
async def validate_github_token(token_data: GitHubToken):
    github_api = GitHubAPI(token_data.token)
    try:
        user = await github_api.get_user()
        return {"valid": True, "user": user}
    except Exception as e:
        logger.error(f"Erreur de validation du token : {str(e)}")
        raise HTTPException(status_code=401, detail="Token GitHub invalide")

# Route pour obtenir la liste des dépôts
@app.post("/api/repos/list")
async def list_repositories(token_data: GitHubToken):
    github_api = GitHubAPI(token_data.token)
    try:
        repos = await github_api.get_repositories()
        return {"repositories": repos}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des dépôts : {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur : {str(e)}")

# Route pour obtenir les modèles Ollama disponibles
@app.get("/api/ollama/models")
async def list_ollama_models():
    try:
        ollama_manager = OllamaManager()
        models = await ollama_manager.list_models()
        return {"models": models}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des modèles Ollama : {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur : {str(e)}")

# Route pour démarrer une analyse
@app.post("/api/analysis/start")
async def start_analysis(analysis_request: AnalysisRequest, background_tasks: BackgroundTasks):
    task_id = f"task_{datetime.now().strftime('%Y%m%d%H%M%S')}_{analysis_request.repo_name.replace('/', '_')}"
    
    # Initialisation de l'état de la tâche
    tasks[task_id] = {
        "status": "initialisé",
        "progress": 0.0,
        "result": None,
        "repo_name": analysis_request.repo_name,
        "token": analysis_request.token,
        "models": analysis_request.models
    }
    
    # Démarrage de l'analyse en arrière-plan
    background_tasks.add_task(
        run_analysis_task,
        task_id,
        analysis_request.token,
        analysis_request.repo_name,
        analysis_request.models
    )
    
    return {"task_id": task_id, "status": "initialisé"}

async def run_analysis_task(task_id: str, token: str, repo_name: str, models: List[str]):
    """Fonction qui exécute l'analyse en arrière-plan"""
    temp_dir = None
    try:
        tasks[task_id]["status"] = "en cours"
        
        # Création d'un répertoire temporaire pour le clone
        temp_dir = tempfile.mkdtemp()
        logger.info(f"Répertoire temporaire créé : {temp_dir}")
        
        try:
            # 1. Clone du dépôt
            tasks[task_id]["progress"] = 0.1
            github_api = GitHubAPI(token)
            repo_path = await github_api.clone_repository(repo_name, temp_dir)
            
            # 2. Récupération des modèles Ollama
            tasks[task_id]["progress"] = 0.2
            ollama_manager = OllamaManager()
            available_models = await ollama_manager.list_models()
            
            # Si aucun modèle n'est spécifié, utiliser tous les modèles disponibles
            if not models:
                models = available_models
            else:
                # Vérifier que les modèles demandés sont disponibles
                models = [model for model in models if model in available_models]
                if not models:
                    raise ValueError(f"Aucun des modèles demandés n'est disponible localement")
            
            # 3. Analyse du dépôt
            tasks[task_id]["progress"] = 0.3
            analyzer = RepositoryAnalyzer(repo_path, ollama_manager)
            
            # Progression de l'analyse (30% à 80%)
            def progress_callback(progress):
                progress_scaled = 0.3 + (progress * 0.5)  # Scale from 0-1 to 0.3-0.8
                tasks[task_id]["progress"] = progress_scaled
            
            analysis_results = await analyzer.analyze_repository(models, progress_callback)
            
            # 4. Génération du rapport formaté pour PDF (optionnel)
            tasks[task_id]["progress"] = 0.9
            report_generator = ReportGenerator(repo_name, analysis_results.get("vulnerabilities", []), 
                                              best_model=analysis_results.get("best_model"))
            formatted_report = report_generator.generate_report()
            
            # 5. Merger les résultats complets avec le rapport formaté
            # Les résultats d'analyse contiennent toutes les données avancées
            # Le rapport formaté contient les données organisées pour l'affichage
            full_result = analysis_results.copy()
            
            # Ajouter les champs formatés du rapport si ils n'existent pas déjà
            if "repo_name" not in full_result:
                full_result["repo_name"] = formatted_report.get("repo_name")
            if "analysis_date" not in full_result:
                full_result["analysis_date"] = formatted_report.get("analysis_date")
            if "summary" not in full_result:
                full_result["summary"] = formatted_report.get("summary")
            
            # Stocker le rapport formaté séparément pour la génération PDF
            full_result["formatted_report"] = formatted_report
            
            # 6. Finalisation
            tasks[task_id]["progress"] = 1.0
            tasks[task_id]["status"] = "terminé"
            tasks[task_id]["result"] = full_result
            
            logger.info(f"Analyse terminée pour {repo_name}. Résultats disponibles avec {len(analysis_results.get('vulnerabilities', []))} vulnérabilités détectées.")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse dans le bloc interne: {str(e)}")
            raise
            
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse : {str(e)}")
        tasks[task_id]["status"] = "erreur"
        tasks[task_id]["error"] = str(e)
    finally:
        # Nettoyage du répertoire temporaire
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.info(f"Répertoire temporaire supprimé : {temp_dir}")
            except Exception as cleanup_error:
                logger.warning(f"Erreur lors du nettoyage du répertoire temporaire: {str(cleanup_error)}")
                # Continuer même en cas d'erreur de nettoyage

# Route pour vérifier l'état d'une analyse
@app.get("/api/analysis/status/{task_id}")
async def get_analysis_status(task_id: str):
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="Tâche non trouvée")
    
    task = tasks[task_id]
    return {
        "task_id": task_id,
        "status": task["status"],
        "progress": task["progress"],
        "result": task["result"]
    }

# Route pour générer un PDF à partir du rapport
@app.get("/api/report/pdf/{task_id}")
async def generate_pdf_report(task_id: str):
    if task_id not in tasks or tasks[task_id]["status"] != "terminé":
        raise HTTPException(status_code=404, detail="Rapport non disponible")
    
    try:
        full_result = tasks[task_id]["result"]
        
        # Utiliser le rapport formaté s'il existe, sinon créer un nouveau
        if "formatted_report" in full_result:
            formatted_report = full_result["formatted_report"]
            report_generator = ReportGenerator(
                formatted_report["repo_name"], 
                formatted_report["vulnerabilities"],
                best_model=formatted_report["best_model"]
            )
        else:
            # Fallback: créer un nouveau rapport formaté
            report_generator = ReportGenerator(
                tasks[task_id]["repo_name"], 
                full_result.get("vulnerabilities", []),
                best_model=full_result.get("best_model")
            )
        
        pdf_bytes = report_generator.generate_pdf()
        
        # En vrai, nous retournerions le PDF comme réponse ici
        # Pour l'instant, nous allons simplement indiquer qu'il est généré
        return {"pdf_available": True, "pdf_bytes_length": len(pdf_bytes)}
    except Exception as e:
        logger.error(f"Erreur lors de la génération du PDF : {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erreur : {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)