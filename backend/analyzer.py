import os
import logging
from typing import List, Dict, Any, Optional, Callable
import json
import asyncio
from ollama import OllamaManager
from datetime import datetime
import subprocess
from collections import defaultdict, Counter
import re

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RepositoryAnalyzer:
    """Analyseur de dépôts pour détecter les vulnérabilités"""
    
    def __init__(self, repo_path: str, ollama_manager: OllamaManager):
        """
        Initialise l'analyseur de dépôts
        
        Args:
            repo_path: Chemin du dépôt cloné localement
            ollama_manager: Gestionnaire de modèles Ollama
        """
        self.repo_path = repo_path
        self.ollama_manager = ollama_manager
        self.analysis_start_time = None
        self.analysis_end_time = None
    
    def get_repository_context(self) -> Dict[str, Any]:
        """
        Récupère le contexte détaillé du dépôt
        
        Returns:
            Dictionnaire contenant les informations contextuelles du dépôt
        """
        context = {
            "repository_name": os.path.basename(self.repo_path),
            "analysis_timestamp": datetime.now().isoformat(),
            "total_files": 0,
            "total_size_bytes": 0,
            "languages": {},
            "file_types": {},
            "directory_structure": {},
            "lines_of_code": {
                "total": 0,
                "by_language": {},
                "by_file_type": {}
            },
            "repository_health": {},
            "dependencies": {},
            "configuration_files": []
        }
        
        try:
            # Analyser la structure du dépôt
            for root, dirs, files in os.walk(self.repo_path):
                # Ignorer .git et autres dossiers cachés
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if file.startswith('.'):
                        continue
                        
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, self.repo_path)
                    
                    try:
                        # Statistiques de base
                        context["total_files"] += 1
                        file_size = os.path.getsize(file_path)
                        context["total_size_bytes"] += file_size
                        
                        # Extension et type de fichier
                        _, ext = os.path.splitext(file)
                        if ext:
                            context["file_types"][ext] = context["file_types"].get(ext, 0) + 1
                        
                        # Détection du langage
                        language = self.detect_language(file)
                        if language != "Inconnu":
                            context["languages"][language] = context["languages"].get(language, 0) + 1
                        
                        # Compter les lignes de code pour les fichiers texte
                        if self._is_text_file(file_path) and file_size < 1024 * 1024:  # < 1MB
                            lines = self._count_lines_of_code(file_path)
                            if lines > 0:
                                context["lines_of_code"]["total"] += lines
                                context["lines_of_code"]["by_language"][language] = \
                                    context["lines_of_code"]["by_language"].get(language, 0) + lines
                                context["lines_of_code"]["by_file_type"][ext or "no_extension"] = \
                                    context["lines_of_code"]["by_file_type"].get(ext or "no_extension", 0) + lines
                        
                        # Détecter les fichiers de configuration importants
                        if self._is_config_file(file):
                            context["configuration_files"].append({
                                "file": relative_path,
                                "type": self._get_config_type(file),
                                "size": file_size
                            })
                        
                        # Analyser les dépendances
                        if self._is_dependency_file(file):
                            deps = self._parse_dependencies(file_path, file)
                            if deps:
                                context["dependencies"][file] = deps
                                
                    except Exception as e:
                        logger.warning(f"Erreur lors de l'analyse du fichier {file_path}: {str(e)}")
                        continue
            
            # Calculer les métriques de santé du dépôt
            context["repository_health"] = self._calculate_repository_health(context)
            
            # Structure des répertoires (limitée aux 2 premiers niveaux)
            context["directory_structure"] = self._get_directory_structure()
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du contexte du dépôt: {str(e)}")
            
        return context
    
    def _is_text_file(self, file_path: str) -> bool:
        """Vérifie si un fichier est un fichier texte"""
        text_extensions = {'.py', '.js', '.ts', '.java', '.c', '.cpp', '.cs', '.go', '.rb', '.php', 
                          '.swift', '.kt', '.rs', '.sh', '.html', '.css', '.sql', '.md', '.json', 
                          '.yml', '.yaml', '.xml', '.toml', '.txt', '.cfg', '.ini', '.conf'}
        _, ext = os.path.splitext(file_path)
        return ext.lower() in text_extensions or file_path.endswith('Dockerfile')
    
    def _count_lines_of_code(self, file_path: str) -> int:
        """Compte les lignes de code (non vides, non commentaires)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Compter les lignes non vides et non commentaires
            code_lines = 0
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith(('#', '//', '/*', '*', '--', '<!--')):
                    code_lines += 1
                    
            return code_lines
        except Exception:
            return 0
    
    def _is_config_file(self, filename: str) -> bool:
        """Vérifie si c'est un fichier de configuration important"""
        config_files = {
            'package.json', 'requirements.txt', 'Gemfile', 'pom.xml', 'build.gradle',
            'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            '.env', '.env.example', 'config.json', 'config.yml', 'config.yaml',
            'webpack.config.js', 'babel.config.js', '.eslintrc', '.prettierrc',
            'tsconfig.json', 'setup.py', 'Pipfile', 'composer.json'
        }
        return filename.lower() in config_files
    
    def _get_config_type(self, filename: str) -> str:
        """Détermine le type de fichier de configuration"""
        config_types = {
            'package.json': 'Node.js Package',
            'requirements.txt': 'Python Dependencies',
            'Gemfile': 'Ruby Gems',
            'pom.xml': 'Maven Project',
            'build.gradle': 'Gradle Build',
            'Dockerfile': 'Docker Container',
            'docker-compose.yml': 'Docker Compose',
            'docker-compose.yaml': 'Docker Compose',
            '.env': 'Environment Variables',
            'webpack.config.js': 'Webpack Configuration',
            'tsconfig.json': 'TypeScript Configuration',
            'setup.py': 'Python Setup',
            'composer.json': 'PHP Composer'
        }
        return config_types.get(filename.lower(), 'Configuration File')
    
    def _is_dependency_file(self, filename: str) -> bool:
        """Vérifie si c'est un fichier de dépendances"""
        dependency_files = {'package.json', 'requirements.txt', 'Gemfile', 'pom.xml', 'composer.json'}
        return filename.lower() in dependency_files
    
    def _parse_dependencies(self, file_path: str, filename: str) -> List[Dict[str, str]]:
        """Parse les dépendances depuis un fichier"""
        dependencies = []
        try:
            if filename.lower() == 'package.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    deps = data.get('dependencies', {})
                    dev_deps = data.get('devDependencies', {})
                    for name, version in deps.items():
                        dependencies.append({"name": name, "version": version, "type": "production"})
                    for name, version in dev_deps.items():
                        dependencies.append({"name": name, "version": version, "type": "development"})
            
            elif filename.lower() == 'requirements.txt':
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '==' in line:
                                name, version = line.split('==', 1)
                                dependencies.append({"name": name.strip(), "version": version.strip(), "type": "production"})
                            else:
                                dependencies.append({"name": line, "version": "*", "type": "production"})
        except Exception as e:
            logger.warning(f"Erreur lors du parsing des dépendances dans {file_path}: {str(e)}")
            
        return dependencies
    
    def _calculate_repository_health(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Calcule les métriques de santé du dépôt"""
        health = {
            "score": 0,
            "factors": {},
            "size_category": "",
            "complexity_level": "",
            "maintenance_indicators": {}
        }
        
        try:
            total_files = context["total_files"]
            total_size = context["total_size_bytes"]
            total_loc = context["lines_of_code"]["total"]
            
            # Catégorie de taille
            if total_files < 10:
                health["size_category"] = "Très petit"
                health["factors"]["size"] = 0.8
            elif total_files < 50:
                health["size_category"] = "Petit"
                health["factors"]["size"] = 0.9
            elif total_files < 200:
                health["size_category"] = "Moyen"
                health["factors"]["size"] = 1.0
            elif total_files < 500:
                health["size_category"] = "Grand"
                health["factors"]["size"] = 0.9
            else:
                health["size_category"] = "Très grand"
                health["factors"]["size"] = 0.7
            
            # Niveau de complexité
            if total_loc < 1000:
                health["complexity_level"] = "Simple"
                health["factors"]["complexity"] = 1.0
            elif total_loc < 10000:
                health["complexity_level"] = "Modéré"
                health["factors"]["complexity"] = 0.9
            elif total_loc < 50000:
                health["complexity_level"] = "Complexe"
                health["factors"]["complexity"] = 0.8
            else:
                health["complexity_level"] = "Très complexe"
                health["factors"]["complexity"] = 0.7
            
            # Diversité des langages
            num_languages = len(context["languages"])
            if num_languages == 1:
                health["factors"]["language_diversity"] = 1.0
            elif num_languages <= 3:
                health["factors"]["language_diversity"] = 0.95
            elif num_languages <= 5:
                health["factors"]["language_diversity"] = 0.85
            else:
                health["factors"]["language_diversity"] = 0.75
            
            # Présence de fichiers de configuration
            config_bonus = min(len(context["configuration_files"]) * 0.1, 0.3)
            health["factors"]["configuration"] = 0.7 + config_bonus
            
            # Score global
            factors = health["factors"]
            health["score"] = round(
                (factors.get("size", 0.5) * 0.25 + 
                 factors.get("complexity", 0.5) * 0.25 + 
                 factors.get("language_diversity", 0.5) * 0.25 + 
                 factors.get("configuration", 0.5) * 0.25) * 100, 1
            )
            
            # Indicateurs de maintenance
            health["maintenance_indicators"] = {
                "has_readme": any("readme" in f["file"].lower() for f in context["configuration_files"]),
                "has_dockerfile": any(f["type"] == "Docker Container" for f in context["configuration_files"]),
                "has_dependencies": len(context["dependencies"]) > 0,
                "has_config_files": len(context["configuration_files"]) > 0
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul de la santé du dépôt: {str(e)}")
            health["score"] = 50  # Score par défaut
            
        return health
    
    def _get_directory_structure(self) -> Dict[str, Any]:
        """Obtient la structure des répertoires (2 niveaux max)"""
        structure = {}
        try:
            for item in os.listdir(self.repo_path):
                item_path = os.path.join(self.repo_path, item)
                if os.path.isdir(item_path) and not item.startswith('.'):
                    structure[item] = {
                        "type": "directory",
                        "files": len([f for f in os.listdir(item_path) if not f.startswith('.')]) if os.path.exists(item_path) else 0
                    }
                elif os.path.isfile(item_path) and not item.startswith('.'):
                    structure[item] = {
                        "type": "file",
                        "size": os.path.getsize(item_path)
                    }
        except Exception as e:
            logger.warning(f"Erreur lors de la récupération de la structure: {str(e)}")
            
        return structure
    
    def get_file_content(self, file_path: str) -> str:
        """
        Récupère le contenu d'un fichier
        
        Args:
            file_path: Chemin du fichier
            
        Returns:
            Contenu du fichier en texte
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du fichier {file_path}: {str(e)}")
            return ""
    
    def get_file_list(self) -> List[str]:
        """
        Récupère la liste des fichiers dans le dépôt
        
        Returns:
            Liste des chemins de fichiers (relatifs à la racine du dépôt)
        """
        file_list = []
        for root, dirs, files in os.walk(self.repo_path):
            # Ignorer explicitement .git et tous les répertoires cachés
            if '.git' in dirs:
                dirs.remove('.git')
            
            # Ignorer les autres répertoires cachés
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                # Ignorer les fichiers cachés et les fichiers non texte courants
                if (not file.startswith('.') and 
                    not file.endswith(('.exe', '.dll', '.so', '.bin', '.dat', '.zip', 
                                    '.tar', '.gz', '.xz', '.pdf', '.jpg', '.png', '.gif'))):
                    try:
                        file_path = os.path.join(root, file)
                        # Vérifier si le chemin contient .git (sécurité supplémentaire)
                        if '.git' in file_path.split(os.sep):
                            continue
                            
                        # Chemin relatif par rapport à la racine du dépôt
                        relative_path = os.path.relpath(file_path, self.repo_path)
                        
                        # Vérifier si le fichier n'est pas trop volumineux avant de l'ajouter
                        if os.path.getsize(file_path) < 1024 * 1024:  # Moins de 1 MB
                            file_list.append(relative_path)
                    except Exception as e:
                        logger.warning(f"Erreur lors de l'accès au fichier {file_path}: {str(e)}")
                        continue
        
        return file_list
    
    def detect_language(self, file_path: str) -> str:
        """
        Détecte le langage de programmation d'un fichier en fonction de son extension
        
        Args:
            file_path: Chemin du fichier
            
        Returns:
            Nom du langage détecté ou "Inconnu"
        """
        extensions = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.cs': 'C#',
            '.go': 'Go',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.rs': 'Rust',
            '.sh': 'Shell',
            '.html': 'HTML',
            '.css': 'CSS',
            '.sql': 'SQL',
            '.md': 'Markdown',
            '.json': 'JSON',
            '.yml': 'YAML',
            '.yaml': 'YAML',
            '.xml': 'XML',
            '.toml': 'TOML',
            '.Dockerfile': 'Dockerfile',
        }
        
        _, ext = os.path.splitext(file_path)
        if file_path.endswith('Dockerfile'):
            return 'Dockerfile'
        return extensions.get(ext.lower(), 'Inconnu')
    
    def create_vulnerability_prompt(self, language: str) -> str:
        """
        Crée un prompt pour l'analyse des vulnérabilités
        
        Args:
            language: Langage de programmation du fichier
            
        Returns:
            Prompt pour le modèle LLM
        """
        return f"""
        Analysez le code {language} suivant pour identifier les vulnérabilités de sécurité, les mauvaises pratiques et les code smells.
        Concentrez-vous sur les types de vulnérabilités suivants:
        1. Injection SQL
        2. Cross-site scripting (XSS)
        3. Secrets ou identifiants codés en dur
        4. Pratiques cryptographiques non sécurisées
        5. Traversée de chemin
        6. Injection de commandes
        7. Désérialisation non sécurisée
        8. Validation incorrecte des entrées
        9. Références directes non sécurisées aux objets
        10. Gestion incorrecte des erreurs

        Pour chaque vulnérabilité trouvée, veuillez fournir:
        - Une brève description de la vulnérabilité
        - Le niveau de gravité (Élevé, Moyen, Faible)
        - Le numéro de ligne ou la plage où se trouve la vulnérabilité
        - Une recommandation pour corriger le problème

        Formatez votre réponse comme un tableau JSON avec ces champs:
        - type_vulnerabilite: string
        - description: string
        - severite: "Élevé", "Moyen", ou "Faible"
        - numeros_ligne: tableau de nombres ou plages (ex. [10] ou [15-20])
        - recommandation: string

        Si aucune vulnérabilité n'est trouvée, retournez un tableau vide.
        """
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calcule un score de risque détaillé basé sur les vulnérabilités
        
        Args:
            vulnerabilities: Liste des vulnérabilités trouvées
            
        Returns:
            Dictionnaire avec les scores de risque détaillés
        """
        if not vulnerabilities:
            return {
                "overall_risk": "Très faible",
                "risk_score": 0,
                "risk_factors": {
                    "severity_impact": 0,
                    "volume_impact": 0,
                    "diversity_impact": 0,
                    "critical_files_impact": 0
                },
                "recommendations": ["Continuer les bonnes pratiques de sécurité"]
            }
        
        risk_factors = {
            "severity_impact": 0,
            "volume_impact": 0,
            "diversity_impact": 0,
            "critical_files_impact": 0
        }
        
        # Impact de la sévérité
        severity_weights = {"Élevé": 10, "Moyen": 5, "Faible": 1}
        total_severity_score = sum(
            severity_weights.get(v.get("severity") or v.get("severite", "Faible"), 1) 
            for v in vulnerabilities
        )
        risk_factors["severity_impact"] = min(total_severity_score / len(vulnerabilities), 10)
        
        # Impact du volume
        vuln_count = len(vulnerabilities)
        if vuln_count <= 5:
            risk_factors["volume_impact"] = vuln_count * 2
        elif vuln_count <= 20:
            risk_factors["volume_impact"] = 10 + (vuln_count - 5) * 0.5
        else:
            risk_factors["volume_impact"] = min(20, 10 + (vuln_count - 5) * 0.3)
        
        # Impact de la diversité des types de vulnérabilités
        unique_types = len(set(
            v.get("vulnerability_type") or v.get("type_vulnerabilite", "Autre") 
            for v in vulnerabilities
        ))
        risk_factors["diversity_impact"] = min(unique_types * 2, 10)
        
        # Impact des fichiers critiques (configuration, auth, etc.)
        critical_patterns = ['config', 'auth', 'login', 'password', 'secret', 'key', 'admin']
        critical_files = sum(
            1 for v in vulnerabilities 
            if any(pattern in v.get("file_path", "").lower() for pattern in critical_patterns)
        )
        risk_factors["critical_files_impact"] = min(critical_files * 3, 15)
        
        # Score global de risque
        total_risk = sum(risk_factors.values())
        risk_score = min(total_risk / 4, 25)  # Normaliser sur 25
        
        # Catégorisation du risque
        if risk_score <= 5:
            overall_risk = "Très faible"
            color = "green"
        elif risk_score <= 10:
            overall_risk = "Faible"
            color = "lightgreen"
        elif risk_score <= 15:
            overall_risk = "Moyen"
            color = "orange"
        elif risk_score <= 20:
            overall_risk = "Élevé"
            color = "red"
        else:
            overall_risk = "Critique"
            color = "darkred"
        
        # Recommandations basées sur le risque
        recommendations = []
        if risk_factors["severity_impact"] > 7:
            recommendations.append("Traiter immédiatement les vulnérabilités de haute sévérité")
        if risk_factors["volume_impact"] > 10:
            recommendations.append("Prioriser la correction en lot des vulnérabilités similaires")
        if risk_factors["diversity_impact"] > 6:
            recommendations.append("Mettre en place une formation sécurité pour l'équipe")
        if risk_factors["critical_files_impact"] > 5:
            recommendations.append("Réviser immédiatement les fichiers critiques identifiés")
        
        if not recommendations:
            recommendations = ["Maintenir les bonnes pratiques de sécurité actuelles"]
        
        return {
            "overall_risk": overall_risk,
            "risk_score": round(risk_score, 1),
            "risk_color": color,
            "risk_factors": {k: round(v, 1) for k, v in risk_factors.items()},
            "recommendations": recommendations
        }
    
    def _analyze_security_patterns(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyse les modèles de sécurité dans les vulnérabilités
        
        Args:
            vulnerabilities: Liste des vulnérabilités
            
        Returns:
            Analyse des modèles de sécurité
        """
        patterns = {
            "hotspots": defaultdict(int),  # Fichiers avec le plus de vulnérabilités
            "vulnerability_clusters": defaultdict(list),  # Groupes de vulnérabilités similaires
            "affected_components": defaultdict(int),  # Composants les plus affectés
            "security_debt": {
                "technical_debt_score": 0,
                "maintenance_priority": [],
                "refactoring_candidates": []
            },
            "trend_analysis": {
                "common_mistakes": Counter(),
                "language_specific_issues": defaultdict(Counter),
                "severity_distribution_by_type": defaultdict(Counter)
            }
        }
        
        if not vulnerabilities:
            return patterns
        
        # Analyser les hotspots (fichiers problématiques)
        for vuln in vulnerabilities:
            file_path = vuln.get("file_path", "unknown")
            patterns["hotspots"][file_path] += 1
            
            # Analyser les composants affectés (répertoires)
            if "/" in file_path:
                component = file_path.split("/")[0]
                patterns["affected_components"][component] += 1
            
            # Grouper les vulnérabilités similaires
            vuln_type = vuln.get("vulnerability_type") or vuln.get("type_vulnerabilite", "Autre")
            patterns["vulnerability_clusters"][vuln_type].append({
                "file": file_path,
                "severity": vuln.get("severity") or vuln.get("severite", "Moyen"),
                "lines": vuln.get("line_numbers") or vuln.get("numeros_ligne", [])
            })
            
            # Analyser les erreurs communes
            if "injection" in vuln_type.lower():
                patterns["trend_analysis"]["common_mistakes"]["Injection Attacks"] += 1
            elif "auth" in vuln_type.lower():
                patterns["trend_analysis"]["common_mistakes"]["Authentication Issues"] += 1
            elif "exposure" in vuln_type.lower() or "exposition" in vuln_type.lower():
                patterns["trend_analysis"]["common_mistakes"]["Data Exposure"] += 1
            elif "validation" in vuln_type.lower():
                patterns["trend_analysis"]["common_mistakes"]["Input Validation"] += 1
            
            # Analyser par langage
            language = vuln.get("language", "Unknown")
            patterns["trend_analysis"]["language_specific_issues"][language][vuln_type] += 1
            
            # Distribution sévérité par type
            severity = vuln.get("severity") or vuln.get("severite", "Moyen")
            patterns["trend_analysis"]["severity_distribution_by_type"][vuln_type][severity] += 1
        
        # Calculer la dette technique
        total_vulns = len(vulnerabilities)
        high_severity_count = sum(1 for v in vulnerabilities 
                                 if (v.get("severity") or v.get("severite")) == "Élevé")
        
        patterns["security_debt"]["technical_debt_score"] = round(
            (high_severity_count * 3 + total_vulns) / max(total_vulns, 1) * 100, 1
        )
        
        # Identifier les priorités de maintenance
        hotspot_files = sorted(patterns["hotspots"].items(), key=lambda x: x[1], reverse=True)[:5]
        patterns["security_debt"]["maintenance_priority"] = [
            {"file": file, "vulnerability_count": count, "priority": "High" if count > 3 else "Medium"}
            for file, count in hotspot_files
        ]
        
        # Candidats pour refactoring
        patterns["security_debt"]["refactoring_candidates"] = [
            file for file, count in patterns["hotspots"].items() if count > 2
        ]
        
        # Convertir les defaultdict en dict normaux pour la sérialisation JSON
        patterns["hotspots"] = dict(patterns["hotspots"])
        patterns["affected_components"] = dict(patterns["affected_components"])
        patterns["vulnerability_clusters"] = dict(patterns["vulnerability_clusters"])
        patterns["trend_analysis"]["common_mistakes"] = dict(patterns["trend_analysis"]["common_mistakes"])
        patterns["trend_analysis"]["language_specific_issues"] = {
            k: dict(v) for k, v in patterns["trend_analysis"]["language_specific_issues"].items()
        }
        patterns["trend_analysis"]["severity_distribution_by_type"] = {
            k: dict(v) for k, v in patterns["trend_analysis"]["severity_distribution_by_type"].items()
        }
        
        return patterns
    
    def _calculate_model_performance_metrics(self, model_performance: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calcule des métriques détaillées sur les performances des modèles
        
        Args:
            model_performance: Données de performance brutes des modèles
            
        Returns:
            Métriques détaillées de performance
        """
        metrics = {
            "model_rankings": [],
            "performance_summary": {},
            "reliability_scores": {},
            "recommendation": {
                "best_overall": None,
                "most_reliable": None,
                "reasons": []
            }
        }
        
        # Calculer les scores de performance et fiabilité
        for model, data in model_performance.items():
            analyses = data.get("analyses", 0)
            errors = data.get("errors", 0)
            avg_score = data.get("average_score", 0.0)
            
            # Score de fiabilité (basé sur le taux de succès)
            total_attempts = analyses + errors
            reliability = (analyses / max(total_attempts, 1)) * 100 if total_attempts > 0 else 0
            
            # Score de performance combiné
            performance_score = (avg_score * 0.7 + (reliability / 100) * 0.3) * 100
            
            metrics["reliability_scores"][model] = {
                "reliability_percentage": round(reliability, 1),
                "average_quality_score": round(avg_score, 3),
                "total_analyses": analyses,
                "error_count": errors,
                "combined_performance": round(performance_score, 1)
            }
            
            metrics["model_rankings"].append({
                "model": model,
                "performance_score": round(performance_score, 1),
                "quality_score": round(avg_score, 3),
                "reliability": round(reliability, 1),
                "analyses_completed": analyses
            })
        
        # Trier par score de performance
        metrics["model_rankings"].sort(key=lambda x: x["performance_score"], reverse=True)
        
        # Résumé des performances
        if metrics["model_rankings"]:
            best_model = metrics["model_rankings"][0]
            most_reliable = max(metrics["reliability_scores"].items(), 
                              key=lambda x: x[1]["reliability_percentage"])
            
            metrics["performance_summary"] = {
                "total_models_tested": len(model_performance),
                "best_performer": best_model["model"],
                "best_performance_score": best_model["performance_score"],
                "most_reliable_model": most_reliable[0],
                "highest_reliability": most_reliable[1]["reliability_percentage"],
                "average_performance": round(
                    sum(m["performance_score"] for m in metrics["model_rankings"]) / 
                    len(metrics["model_rankings"]), 1
                )
            }
            
            # Recommandations
            metrics["recommendation"]["best_overall"] = best_model["model"]
            metrics["recommendation"]["most_reliable"] = most_reliable[0]
            
            reasons = []
            if best_model["performance_score"] > 80:
                reasons.append(f"{best_model['model']} excelle avec un score de {best_model['performance_score']}")
            if most_reliable[1]["reliability_percentage"] > 90:
                reasons.append(f"{most_reliable[0]} est très fiable ({most_reliable[1]['reliability_percentage']}% de succès)")
            if best_model["model"] == most_reliable[0]:
                reasons.append("Le meilleur modèle est aussi le plus fiable")
            
            metrics["recommendation"]["reasons"] = reasons or ["Analyse comparative disponible"]
        
        return metrics
    
    def _generate_actionable_insights(self, vulnerabilities: List[Dict[str, Any]], 
                                    analysis_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Génère des insights actionnables basés sur l'analyse
        
        Args:
            vulnerabilities: Liste des vulnérabilités
            analysis_stats: Statistiques d'analyse
            
        Returns:
            Insights et recommandations actionnables
        """
        insights = {
            "immediate_actions": [],
            "short_term_goals": [],
            "long_term_strategy": [],
            "process_improvements": [],
            "training_needs": [],
            "tool_recommendations": [],
            "metrics": {
                "security_maturity_level": "",
                "improvement_priority": "",
                "estimated_fix_time": ""
            }
        }
        
        if not vulnerabilities:
            insights["immediate_actions"] = ["Excellent! Maintenir les bonnes pratiques actuelles"]
            insights["metrics"]["security_maturity_level"] = "Élevé"
            return insights
        
        severity_counts = Counter(v.get("severity") or v.get("severite", "Moyen") for v in vulnerabilities)
        vuln_types = Counter(v.get("vulnerability_type") or v.get("type_vulnerabilite", "Autre") for v in vulnerabilities)
        
        # Actions immédiates
        if severity_counts.get("Élevé", 0) > 0:
            insights["immediate_actions"].extend([
                f"🚨 Corriger immédiatement les {severity_counts['Élevé']} vulnérabilités de haute sévérité",
                "🔍 Effectuer une revue de sécurité approfondie des fichiers critiques",
                "📋 Créer un plan de correction priorisé"
            ])
        
        if severity_counts.get("Moyen", 0) > 5:
            insights["immediate_actions"].append(
                f"⚠️ Planifier la correction des {severity_counts['Moyen']} vulnérabilités moyennes"
            )
        
        # Objectifs à court terme
        common_types = vuln_types.most_common(3)
        for vuln_type, count in common_types:
            if count > 1:
                insights["short_term_goals"].append(
                    f"🎯 Traiter les {count} cas de {vuln_type} (pattern récurrent)"
                )
        
        # Stratégie à long terme
        total_vulns = len(vulnerabilities)
        if total_vulns > 20:
            insights["long_term_strategy"].extend([
                "🏗️ Mettre en place des contrôles de sécurité automatisés (SAST/DAST)",
                "📚 Établir des guidelines de développement sécurisé",
                "🔄 Intégrer la sécurité dans le pipeline CI/CD"
            ])
        
        # Améliorations de processus
        coverage = analysis_stats.get("analysis_coverage", 0)
        if coverage < 80:
            insights["process_improvements"].append(
                f"📈 Améliorer la couverture d'analyse ({coverage}% actuellement)"
            )
        
        if analysis_stats.get("files_with_errors", 0) > 0:
            insights["process_improvements"].append(
                "🔧 Résoudre les erreurs d'analyse pour une couverture complète"
            )
        
        # Besoins de formation
        if "Injection" in str(vuln_types.keys()):
            insights["training_needs"].append("💡 Formation sur la prévention des injections")
        if "authentification" in str(vuln_types.keys()).lower():
            insights["training_needs"].append("🔐 Formation sur l'authentification sécurisée")
        if "exposition" in str(vuln_types.keys()).lower():
            insights["training_needs"].append("🛡️ Formation sur la protection des données")
        
        # Recommandations d'outils
        languages = set(v.get("language", "") for v in vulnerabilities)
        if "Python" in languages:
            insights["tool_recommendations"].append("🐍 Bandit pour l'analyse Python")
        if "JavaScript" in languages:
            insights["tool_recommendations"].append("🟨 ESLint avec plugins sécurité")
        if "Java" in languages:
            insights["tool_recommendations"].append("☕ SpotBugs ou SonarQube")
        
        # Métriques de maturité
        high_severity_ratio = severity_counts.get("Élevé", 0) / max(total_vulns, 1)
        if high_severity_ratio < 0.1 and total_vulns < 10:
            insights["metrics"]["security_maturity_level"] = "Élevé"
        elif high_severity_ratio < 0.2 and total_vulns < 20:
            insights["metrics"]["security_maturity_level"] = "Moyen"
        else:
            insights["metrics"]["security_maturity_level"] = "Faible"
        
        # Priorité d'amélioration
        if severity_counts.get("Élevé", 0) > 0:
            insights["metrics"]["improvement_priority"] = "Critique"
        elif severity_counts.get("Moyen", 0) > 10:
            insights["metrics"]["improvement_priority"] = "Élevée"
        else:
            insights["metrics"]["improvement_priority"] = "Normale"
        
        # Estimation du temps de correction
        estimated_hours = (
            severity_counts.get("Élevé", 0) * 4 +
            severity_counts.get("Moyen", 0) * 2 +
            severity_counts.get("Faible", 0) * 0.5
        )
        
        if estimated_hours < 8:
            insights["metrics"]["estimated_fix_time"] = f"{int(estimated_hours)}h (< 1 jour)"
        elif estimated_hours < 40:
            insights["metrics"]["estimated_fix_time"] = f"{int(estimated_hours)}h (~{int(estimated_hours/8)} jours)"
        else:
            insights["metrics"]["estimated_fix_time"] = f"{int(estimated_hours)}h (~{int(estimated_hours/40)} semaines)"
        
        return insights
    
    async def analyze_file(self, file_path: str, models: List[str]) -> Dict[str, Any]:
        """
        Analyse un fichier pour les vulnérabilités avec plusieurs modèles
        
        Args:
            file_path: Chemin du fichier (relatif à la racine du dépôt)
            models: Liste des modèles à utiliser
            
        Returns:
            Résultats de l'analyse
        """
        full_path = os.path.join(self.repo_path, file_path)
        language = self.detect_language(file_path)
        
        # Ignorer les fichiers de langage inconnu ou binaires
        if language == 'Inconnu':
            return {
                "file_path": file_path,
                "language": language,
                "status": "ignoré",
                "reason": "Langage non pris en charge"
            }
        
        content = self.get_file_content(full_path)
        
        # Ignorer les fichiers vides ou trop volumineux
        if not content:
            return {
                "file_path": file_path,
                "language": language,
                "status": "ignoré",
                "reason": "Fichier vide"
            }
        
        if len(content) > 50000:  # Limiter à 50KB
            logger.info(f"Fichier {file_path} trop volumineux, tronqué pour l'analyse")
            content = content[:50000] + "\n[Fichier tronqué...]"
        
        # Créer le prompt pour l'analyse
        prompt = self.create_vulnerability_prompt(language)
        
        # Comparer les modèles
        try:
            model_comparison = await self.ollama_manager.compare_models(models, content, prompt)
            
            # Récupérer les résultats du meilleur modèle
            best_model = model_comparison["best_model"]
            best_result = model_comparison["results"][best_model]["response"]
            
            # Si le meilleur modèle a renvoyé une liste de vulnérabilités
            vulnerabilities = best_result.get("vulnerabilities", [])
            
            if vulnerabilities:
                # Formatter les vulnérabilités avec les informations du fichier
                for vuln in vulnerabilities:
                    vuln["file_path"] = file_path
                    vuln["language"] = language
                    vuln["file_size"] = len(content)
                    vuln["lines_in_file"] = len(content.split('\n'))
                
                return {
                    "file_path": file_path,
                    "language": language,
                    "status": "analysé",
                    "best_model": best_model,
                    "model_scores": {model: result["quality_score"] for model, result in model_comparison["results"].items()},
                    "vulnerabilities": vulnerabilities,
                    "file_stats": {
                        "size_bytes": len(content),
                        "lines_count": len(content.split('\n')),
                        "analysis_time": datetime.now().isoformat()
                    }
                }
            else:
                # Si aucune vulnérabilité n'a été trouvée
                return {
                    "file_path": file_path,
                    "language": language,
                    "status": "analysé",
                    "best_model": best_model,
                    "model_scores": {model: result["quality_score"] for model, result in model_comparison["results"].items()},
                    "vulnerabilities": [],
                    "file_stats": {
                        "size_bytes": len(content),
                        "lines_count": len(content.split('\n')),
                        "analysis_time": datetime.now().isoformat()
                    }
                }
                
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du fichier {file_path}: {str(e)}")
            return {
                "file_path": file_path,
                "language": language,
                "status": "erreur",
                "error": str(e)
            }
    
    async def analyze_repository(self, 
                               models: List[str], 
                               progress_callback: Optional[Callable[[float], None]] = None) -> Dict[str, Any]:
        """
        Analyse l'ensemble du dépôt pour les vulnérabilités
        
        Args:
            models: Liste des modèles à utiliser
            progress_callback: Fonction de rappel pour suivre la progression
            
        Returns:
            Résultats de l'analyse pour l'ensemble du dépôt
        """
        self.analysis_start_time = datetime.now()
        
        # Récupérer le contexte du dépôt
        repository_context = self.get_repository_context()
        
        file_list = self.get_file_list()
        logger.info(f"Analyse de {len(file_list)} fichiers dans le dépôt")
        
        # Limiter le nombre de fichiers pour les grands dépôts
        max_files = 100
        if len(file_list) > max_files:
            logger.warning(f"Dépôt trop volumineux, limitation à {max_files} fichiers")
            file_list = file_list[:max_files]
        
        # Analyser les fichiers les plus susceptibles de contenir des vulnérabilités en premier
        priority_extensions = ['.py', '.js', '.php', '.java', '.rb', '.go', '.cs', '.ts']
        file_list.sort(key=lambda f: os.path.splitext(f)[1] in priority_extensions, reverse=True)
        
        results = []
        all_vulnerabilities = []
        model_performance = {model: {"analyses": 0, "total_score": 0.0, "errors": 0} for model in models}
        
        # Limiter la concurrence pour éviter de surcharger Ollama
        semaphore = asyncio.Semaphore(1)
        
        async def analyze_with_rate_limit(file_path):
            async with semaphore:
                return await self.analyze_file(file_path, models)
        
        # Créer les tâches d'analyse
        tasks = [analyze_with_rate_limit(file_path) for file_path in file_list]
        
        # Exécuter les analyses et suivre la progression
        for i, task in enumerate(asyncio.as_completed(tasks)):
            result = await task
            results.append(result)
            
            # Collecter les vulnérabilités
            if result.get("status") == "analysé" and "vulnerabilities" in result:
                all_vulnerabilities.extend(result["vulnerabilities"])
                
                # Mettre à jour les performances des modèles
                best_model = result.get("best_model")
                if best_model and best_model in model_performance:
                    model_scores = result.get("model_scores", {})
                    for model, score in model_scores.items():
                        if model in model_performance:
                            model_performance[model]["analyses"] += 1
                            model_performance[model]["total_score"] += score
            elif result.get("status") == "erreur":
                # Compter les erreurs pour tous les modèles
                for model in model_performance:
                    model_performance[model]["errors"] += 1
            
            # Mettre à jour la progression
            if progress_callback:
                progress_callback((i + 1) / len(file_list))
        
        self.analysis_end_time = datetime.now()
        analysis_duration = (self.analysis_end_time - self.analysis_start_time).total_seconds()
        
        # Calculer les scores moyens des modèles
        for model_data in model_performance.values():
            if model_data["analyses"] > 0:
                model_data["average_score"] = model_data["total_score"] / model_data["analyses"]
            else:
                model_data["average_score"] = 0.0
        
        # Déterminer le meilleur modèle global en fonction des scores
        model_scores = {}
        for result in results:
            if "model_scores" in result:
                for model, score in result["model_scores"].items():
                    if model in model_scores:
                        model_scores[model] += score
                    else:
                        model_scores[model] = score
        
        # Trouver le modèle avec le score total le plus élevé
        best_model = max(model_scores.items(), key=lambda x: x[1])[0] if model_scores else None
        
        # Statistiques détaillées des vulnérabilités
        severity_stats = {"Élevé": 0, "Moyen": 0, "Faible": 0, "Total": len(all_vulnerabilities)}
        type_stats = {}
        language_stats = {}
        file_stats = {}
        
        for vuln in all_vulnerabilities:
            # Par sévérité
            severity = vuln.get("severity") or vuln.get("severite")
            if severity in severity_stats:
                severity_stats[severity] += 1
            
            # Par type
            vuln_type = vuln.get("vulnerability_type") or vuln.get("type_vulnerabilite", "Autre")
            type_stats[vuln_type] = type_stats.get(vuln_type, 0) + 1
            
            # Par langage
            language = vuln.get("language", "Inconnu")
            language_stats[language] = language_stats.get(language, 0) + 1
            
            # Par fichier
            file_path = vuln.get("file_path", "Inconnu")
            if file_path not in file_stats:
                file_stats[file_path] = {"count": 0, "severities": {"Élevé": 0, "Moyen": 0, "Faible": 0}}
            file_stats[file_path]["count"] += 1
            if severity in file_stats[file_path]["severities"]:
                file_stats[file_path]["severities"][severity] += 1
        
        # Statistiques d'analyse des fichiers
        analysis_stats = {
            "total_files_found": len(self.get_file_list()),
            "files_analyzed": len([r for r in results if r.get("status") == "analysé"]),
            "files_ignored": len([r for r in results if r.get("status") == "ignoré"]),
            "files_with_errors": len([r for r in results if r.get("status") == "erreur"]),
            "files_with_vulnerabilities": len([r for r in results if r.get("status") == "analysé" and r.get("vulnerabilities", [])]),
            "analysis_coverage": round((len([r for r in results if r.get("status") == "analysé"]) / max(len(results), 1)) * 100, 1),
            "analysis_duration_seconds": round(analysis_duration, 2),
            "analysis_speed": round(len(results) / max(analysis_duration, 1), 2)  # fichiers par seconde
        }
        
        # *** NOUVELLES STATISTIQUES DÉTAILLÉES ***
        
        # Calcul du score de risque détaillé
        risk_assessment = self._calculate_risk_score(all_vulnerabilities)
        
        # Analyse des modèles de sécurité
        security_patterns = self._analyze_security_patterns(all_vulnerabilities)
        
        # Métriques de performance des modèles
        model_performance_metrics = self._calculate_model_performance_metrics(model_performance)
        
        # Insights actionnables
        actionable_insights = self._generate_actionable_insights(all_vulnerabilities, analysis_stats)
        
        # Statistiques temporelles
        temporal_stats = {
            "analysis_start": self.analysis_start_time.isoformat(),
            "analysis_end": self.analysis_end_time.isoformat(),
            "total_duration": f"{int(analysis_duration // 60)}m {int(analysis_duration % 60)}s",
            "average_time_per_file": round(analysis_duration / max(len(results), 1), 2),
            "throughput": {
                "files_per_minute": round(len(results) / max(analysis_duration / 60, 1), 1),
                "vulnerabilities_found_per_minute": round(len(all_vulnerabilities) / max(analysis_duration / 60, 1), 1)
            }
        }
        
        # Comparaison avec benchmarks (valeurs typiques)
        benchmark_comparison = {
            "vulnerability_density": {
                "current": round(len(all_vulnerabilities) / max(analysis_stats["files_analyzed"], 1), 2),
                "industry_average": 0.5,  # vulnérabilités par fichier (estimation)
                "status": "low" if len(all_vulnerabilities) / max(analysis_stats["files_analyzed"], 1) < 0.5 else "high"
            },
            "security_coverage": {
                "current": analysis_stats["analysis_coverage"],
                "recommended_minimum": 80,
                "status": "good" if analysis_stats["analysis_coverage"] >= 80 else "needs_improvement"
            },
            "critical_issues_ratio": {
                "current": round((severity_stats.get("Élevé", 0) / max(len(all_vulnerabilities), 1)) * 100, 1),
                "acceptable_threshold": 10,  # % de vulnérabilités critiques acceptables
                "status": "acceptable" if (severity_stats.get("Élevé", 0) / max(len(all_vulnerabilities), 1)) * 100 <= 10 else "concerning"
            }
        }
        
        # Prédictions et tendances
        trend_predictions = {
            "security_trend": "improving" if len(all_vulnerabilities) < 10 else "stable" if len(all_vulnerabilities) < 30 else "needs_attention",
            "maintenance_effort": actionable_insights["metrics"]["estimated_fix_time"],
            "next_review_recommended": (datetime.now() + 
                                      (datetime.now() - self.analysis_start_time) * 
                                      (5 if len(all_vulnerabilities) < 5 else 3 if len(all_vulnerabilities) < 15 else 1)
                                     ).strftime("%Y-%m-%d"),
            "priority_areas": list(Counter(vuln.get("language", "Unknown") for vuln in all_vulnerabilities).most_common(3))
        }
        
        return {
            "repository": os.path.basename(self.repo_path),
            "repository_context": repository_context,
            "analysis_stats": analysis_stats,
            "vulnerabilities": all_vulnerabilities,
            "best_model": best_model,
            "model_scores": model_scores,
            "model_performance": model_performance,
            "detailed_statistics": {
                "by_severity": severity_stats,
                "by_type": type_stats,
                "by_language": language_stats,
                "by_file": file_stats
            },
            
            # *** NOUVELLES STATISTIQUES DÉTAILLÉES ***
            "risk_assessment": risk_assessment,
            "security_patterns": security_patterns,
            "model_performance_metrics": model_performance_metrics,
            "actionable_insights": actionable_insights,
            "temporal_analysis": temporal_stats,
            "benchmark_comparison": benchmark_comparison,
            "trend_predictions": trend_predictions,
            
            "file_results": results  # Résultats détaillés par fichier
        }