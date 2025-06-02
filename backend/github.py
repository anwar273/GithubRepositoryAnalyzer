import aiohttp
import os
import logging
import shutil
from typing import List, Dict, Any, Optional
import json
from git import Repo
import asyncio

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GitHubAPI:
    """Classe pour interagir avec l'API GitHub"""
    
    def __init__(self, token: str):
        """
        Initialise l'API GitHub avec un token d'accès
        
        Args:
            token: Le token d'accès GitHub
        """
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHub-Vuln-Analyzer"
        }
    
    async def get_user(self) -> Dict[str, Any]:
        """
        Récupère les informations de l'utilisateur GitHub authentifié
        
        Returns:
            Dict contenant les informations de l'utilisateur
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/user",
                headers=self.headers
            ) as response:
                if response.status != 200:
                    error_msg = await response.text()
                    logger.error(f"Erreur GitHub API: {error_msg}")
                    raise Exception(f"Erreur d'authentification GitHub: {response.status}")
                
                return await response.json()
    
    async def get_repositories(self) -> List[Dict[str, Any]]:
        """
        Récupère la liste des dépôts de l'utilisateur GitHub
        
        Returns:
            Liste des dépôts avec leurs informations
        """
        repos = []
        page = 1
        per_page = 100
        
        async with aiohttp.ClientSession() as session:
            while True:
                async with session.get(
                    f"{self.base_url}/user/repos",
                    headers=self.headers,
                    params={"page": page, "per_page": per_page, "sort": "updated"}
                ) as response:
                    if response.status != 200:
                        error_msg = await response.text()
                        logger.error(f"Erreur GitHub API: {error_msg}")
                        raise Exception(f"Erreur lors de la récupération des dépôts: {response.status}")
                    
                    page_repos = await response.json()
                    if not page_repos:
                        break
                    
                    # Filtrer et formater les données des dépôts
                    for repo in page_repos:
                        repos.append({
                            "id": repo["id"],
                            "name": repo["name"],
                            "full_name": repo["full_name"],
                            "description": repo["description"],
                            "html_url": repo["html_url"],
                            "created_at": repo["created_at"],
                            "updated_at": repo["updated_at"],
                            "pushed_at": repo["pushed_at"],
                            "stargazers_count": repo["stargazers_count"],
                            "watchers_count": repo["watchers_count"],
                            "language": repo["language"],
                            "forks_count": repo["forks_count"],
                            "default_branch": repo["default_branch"],
                            "size": repo["size"],
                            "open_issues_count": repo["open_issues_count"],
                            "visibility": repo.get("visibility", "public")
                        })
                    
                    page += 1
        
        return repos
    
    async def clone_repository(self, repo_name: str, target_dir: str, shallow: bool = True) -> str:
        """
        Clone un dépôt GitHub dans un répertoire local
        
        Args:
            repo_name: Nom du dépôt (format: "username/repo")
            target_dir: Répertoire cible pour le clone
            shallow: Si True, effectue un clone superficiel (sans historique complet)
            
        Returns:
            Chemin du dépôt cloné
        """
        repo_dir = os.path.join(target_dir, repo_name.split('/')[-1])
        
        # Utiliser le token pour l'accès
        repo_url = f"https://{self.token}@github.com/{repo_name}.git"
        
        try:
            # Exécuter le clone dans un processus distinct pour ne pas bloquer
            def clone_repo():
                try:
                    if shallow:
                        # Clone superficiel (sans historique complet)
                        Repo.clone_from(repo_url, repo_dir, depth=1)
                        
                        # Supprimer le dossier .git pour éviter les problèmes d'accès
                        git_dir = os.path.join(repo_dir, '.git')
                        if os.path.exists(git_dir):
                            try:
                                shutil.rmtree(git_dir, ignore_errors=True)
                                logger.info(f"Dossier .git supprimé pour éviter les problèmes d'accès")
                            except Exception as e:
                                logger.warning(f"Impossible de supprimer le dossier .git: {str(e)}")
                    else:
                        # Clone complet avec historique
                        Repo.clone_from(repo_url, repo_dir)
                except Exception as e:
                    logger.error(f"Erreur dans la fonction clone_repo: {str(e)}")
                    raise
            
            # Exécuter le clone de manière asynchrone
            await asyncio.to_thread(clone_repo)
            
            logger.info(f"Dépôt cloné avec succès dans {repo_dir}")
            return repo_dir
            
        except Exception as e:
            logger.error(f"Erreur lors du clonage du dépôt {repo_name}: {str(e)}")
            raise Exception(f"Erreur lors du clonage du dépôt: {str(e)}")
    
    async def get_repository_languages(self, repo_name: str) -> Dict[str, int]:
        """
        Récupère les langages utilisés dans un dépôt GitHub
        
        Args:
            repo_name: Nom du dépôt (format: "username/repo")
            
        Returns:
            Dictionnaire des langages avec leur proportion en octets
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/repos/{repo_name}/languages",
                headers=self.headers
            ) as response:
                if response.status != 200:
                    error_msg = await response.text()
                    logger.error(f"Erreur GitHub API: {error_msg}")
                    raise Exception(f"Erreur lors de la récupération des langages: {response.status}")
                
                return await response.json()
    
    async def get_repository_contents(self, repo_name: str, path: str = "") -> List[Dict[str, Any]]:
        """
        Récupère le contenu d'un dossier dans un dépôt GitHub
        
        Args:
            repo_name: Nom du dépôt (format: "username/repo")
            path: Chemin dans le dépôt (vide pour la racine)
            
        Returns:
            Liste des fichiers et dossiers à ce chemin
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/repos/{repo_name}/contents/{path}",
                headers=self.headers
            ) as response:
                if response.status != 200:
                    error_msg = await response.text()
                    logger.error(f"Erreur GitHub API: {error_msg}")
                    raise Exception(f"Erreur lors de la récupération du contenu: {response.status}")
                
                return await response.json()
    
    async def get_file_content(self, repo_name: str, file_path: str) -> str:
        """
        Récupère le contenu d'un fichier dans un dépôt GitHub
        
        Args:
            repo_name: Nom du dépôt (format: "username/repo")
            file_path: Chemin du fichier dans le dépôt
            
        Returns:
            Contenu du fichier (décodé en texte)
        """
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/repos/{repo_name}/contents/{file_path}",
                headers=self.headers
            ) as response:
                if response.status != 200:
                    error_msg = await response.text()
                    logger.error(f"Erreur GitHub API: {error_msg}")
                    raise Exception(f"Erreur lors de la récupération du fichier: {response.status}")
                
                content = await response.json()
                
                if content.get("encoding") == "base64" and content.get("content"):
                    import base64
                    return base64.b64decode(content["content"]).decode('utf-8', errors='replace')
                else:
                    raise Exception("Format de contenu non pris en charge")