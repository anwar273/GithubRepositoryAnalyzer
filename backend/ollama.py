import aiohttp
import asyncio
import logging
from typing import List, Dict, Any, Optional
import json
import re
from config import OLLAMA_API_URL

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OllamaManager:
    """Gestionnaire pour l'API Ollama"""
    
    def __init__(self, base_url: str = OLLAMA_API_URL):
        """
        Initialise le gestionnaire Ollama
        
        Args:
            base_url: URL de base de l'API Ollama (par défaut depuis config.py)
        """
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
    
    async def list_models(self) -> List[str]:
        """
        Liste les modèles Ollama disponibles localement
        
        Returns:
            Liste des noms des modèles
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.api_url}/tags") as response:
                    if response.status != 200:
                        error_msg = await response.text()
                        logger.error(f"Erreur Ollama API: {error_msg}")
                        raise Exception(f"Erreur lors de la récupération des modèles: {response.status}")
                    
                    data = await response.json()
                    return [model["name"] for model in data.get("models", [])]
        except aiohttp.ClientConnectorError:
            logger.error("Impossible de se connecter à Ollama. Assurez-vous qu'Ollama est en cours d'exécution.")
            raise Exception("Ollama n'est pas accessible. Veuillez vérifier qu'Ollama est démarré.")
    
    async def analyze_code(self, model: str, code: str, prompt: str) -> Dict[str, Any]:
        """
        Analyse du code avec un modèle Ollama spécifique
        
        Args:
            model: Nom du modèle Ollama à utiliser
            code: Code source à analyser
            prompt: Instructions pour l'analyse
            
        Returns:
            Résultat de l'analyse
        """
        # Créer un prompt compatible avec analyzer.py
        full_prompt = f"""
{prompt}

CODE À ANALYSER:
```
{code}
```

IMPORTANT: Vous DEVEZ répondre UNIQUEMENT avec un JSON valide dans ce format exact :
{{
  "vulnerabilities": [
    {{
      "type_vulnerabilite": "type_de_vulnérabilité",
      "severite": "Élevé",
      "description": "Description détaillée de la vulnérabilité",
      "numeros_ligne": [10, 15],
      "recommandation": "Comment corriger cette vulnérabilité"
    }}
  ]
}}

Les valeurs possibles pour "severite" sont exactement : "Élevé", "Moyen", "Faible"
Les "numeros_ligne" peuvent être un tableau de nombres ou de plages.

Si aucune vulnérabilité n'est trouvée, répondez avec :
{{
  "vulnerabilities": []
}}

Ne ajoutez AUCUN texte avant ou après le JSON. Commencez directement par {{ et terminez par }}.
"""
        
        try:
            logger.info(f"Envoi de la requête à Ollama avec le modèle {model}")
            logger.info(f"Longueur du code: {len(code)} caractères")
            logger.info(f"Longueur totale du prompt: {len(full_prompt)} caractères")
            
            # Si le texte est trop long, le tronquer
            if len(full_prompt) > 32000:  # Une limite raisonnable pour la plupart des modèles
                logger.warning(f"Prompt trop long ({len(full_prompt)} caractères), troncature à 32000 caractères")
                truncated_code = code[:16000]  # Garder la première moitié du code
                full_prompt = f"""
{prompt}

CODE À ANALYSER (tronqué car trop long):
```
{truncated_code}
...
[Code tronqué - trop long pour l'analyse]
```

Veuillez formater votre réponse sous la forme d'un JSON valide.
"""
                logger.info(f"Nouvelle longueur du prompt après troncature: {len(full_prompt)} caractères")
            
            # Pas de timeout pour les modèles locaux - ils peuvent prendre le temps qu'il faut
            logger.info(f"Exécution du modèle {model} sans timeout (peut prendre du temps selon votre machine)")
            
            # Effectuer la requête sans timeout
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=None)  # Pas de timeout
                ) as session:
                    payload = {
                        "model": model,
                        "prompt": full_prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.1,
                            "num_predict": 2048
                        }
                    }
                    
                    async with session.post(f"{self.api_url}/generate", json=payload) as response:
                        if response.status != 200:
                            error_msg = await response.text()
                            logger.error(f"Erreur Ollama API: {error_msg}")
                            return {
                                "error": f"Erreur Ollama API: {response.status} - {error_msg}",
                                "vulnerabilities": []
                            }
                        
                        result = await response.json()
                        response_text = result.get("response", "")
                        
                        logger.info(f"Réponse reçue d'Ollama pour le modèle {model}")
                        logger.info(f"Longueur de la réponse: {len(response_text)} caractères")
                        
                        # Tenter d'extraire un JSON de la réponse
                        return self._extract_json_from_response(response_text)
                        
            except aiohttp.ClientConnectorError as e:
                logger.error(f"Erreur de connexion avec Ollama: {str(e)}")
                return {
                    "error": f"Erreur de connexion avec Ollama: {str(e)}",
                    "vulnerabilities": []
                }
                    
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse avec {model}: {str(e)}")
            import traceback
            logger.error(f"Traceback complet: {traceback.format_exc()}")
            
            return {
                "error": f"Erreur lors de l'analyse avec {model}: {str(e)}",
                "vulnerabilities": []
            }
    
    def _extract_json_from_response(self, response_text: str) -> Dict[str, Any]:
        """
        Extrait et parse le JSON de la réponse d'Ollama
        
        Args:
            response_text: Texte de réponse d'Ollama
            
        Returns:
            Dictionnaire parsé ou structure d'erreur
        """
        if not response_text:
            logger.warning("Réponse vide reçue")
            return {"raw_response": "", "vulnerabilities": []}
            
        try:
            # Log de la réponse complète pour déboguer
            logger.info("=== DÉBUT DE LA RÉPONSE COMPLÈTE ===")
            logger.info(response_text)
            logger.info("=== FIN DE LA RÉPONSE COMPLÈTE ===")
            
            logger.debug(f"Tentative d'extraction JSON de: {response_text[:200]}...")
            
            # Recherche de blocs JSON dans la réponse - version plus robuste
            # Chercher des JSON complets avec des accolades équilibrées
            json_matches = []
            brace_count = 0
            start_pos = -1
            
            for i, char in enumerate(response_text):
                if char == '{':
                    if brace_count == 0:
                        start_pos = i
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and start_pos != -1:
                        json_matches.append(response_text[start_pos:i+1])
            
            # Essayer de parser chaque JSON trouvé
            for json_str in json_matches:
                try:
                    logger.info(f"Tentative de parsing JSON: {json_str[:100]}...")
                    parsed_json = json.loads(json_str)
                    logger.info("JSON parsé avec succès")
                    return parsed_json
                except json.JSONDecodeError as je:
                    logger.debug(f"Échec du parsing pour ce JSON: {str(je)}")
                    # Essayer de compléter le JSON incomplet
                    fixed_json = self._try_fix_incomplete_json(json_str)
                    if fixed_json:
                        try:
                            parsed_json = json.loads(fixed_json)
                            logger.info("JSON incomplet réparé avec succès")
                            return parsed_json
                        except:
                            logger.debug("Échec de la réparation du JSON")
                    continue
            
            # Si aucun JSON complet n'est trouvé, essayer la méthode regex comme fallback
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                logger.info(f"JSON trouvé avec regex")
                try:
                    parsed_json = json.loads(json_str)
                    return parsed_json
                except json.JSONDecodeError as je:
                    logger.warning(f"JSON invalide trouvé dans la réponse: {str(je)}")
                    # Essayer de réparer le JSON
                    fixed_json = self._try_fix_incomplete_json(json_str)
                    if fixed_json:
                        try:
                            parsed_json = json.loads(fixed_json)
                            logger.info("JSON réparé avec succès")
                            return parsed_json
                        except:
                            logger.warning("Échec de la réparation du JSON")
                    
                    # Tentative de nettoyage du JSON
                    cleaned_json_str = re.sub(r',\s*}', '}', json_str)
                    cleaned_json_str = re.sub(r',\s*]', ']', cleaned_json_str)
                    try:
                        parsed_json = json.loads(cleaned_json_str)
                        logger.info("JSON nettoyé avec succès")
                        return parsed_json
                    except Exception as clean_error:
                        logger.warning(f"Échec du nettoyage du JSON: {str(clean_error)}")
            
            # Essayer de trouver une liste JSON
            json_list_match = re.search(r'\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]', response_text, re.DOTALL)
            if json_list_match:
                json_str = json_list_match.group(0)
                logger.info(f"Liste JSON trouvée dans la réponse")
                try:
                    parsed_list = json.loads(json_str)
                    return {"vulnerabilities": parsed_list}
                except json.JSONDecodeError as je:
                    logger.warning(f"Liste JSON invalide: {str(je)}")
            
            # Si toujours pas de JSON, essayer d'extraire des vulnérabilités du texte libre
            logger.warning(f"Aucun JSON valide trouvé, tentative d'extraction depuis le texte libre")
            extracted_vulns = self._extract_vulnerabilities_from_text(response_text)
            if extracted_vulns:
                logger.info(f"Extraction de {len(extracted_vulns)} vulnérabilités depuis le texte libre")
                return {"vulnerabilities": extracted_vulns}
            
            return {"raw_response": response_text, "vulnerabilities": []}
            
        except Exception as extract_error:
            logger.error(f"Erreur lors de l'extraction du JSON: {str(extract_error)}")
            import traceback
            logger.debug(f"Traceback: {traceback.format_exc()}")
            return {"raw_response": response_text or "", "error": str(extract_error), "vulnerabilities": []}
    
    def _try_fix_incomplete_json(self, json_str: str) -> Optional[str]:
        """
        Essaie de réparer un JSON incomplet
        
        Args:
            json_str: Chaîne JSON potentiellement incomplète
            
        Returns:
            JSON réparé ou None si impossible
        """
        try:
            # Compter les accolades et crochets pour voir ce qui manque
            open_braces = json_str.count('{')
            close_braces = json_str.count('}')
            open_brackets = json_str.count('[')
            close_brackets = json_str.count(']')
            
            # Si il manque des accolades de fermeture
            missing_braces = open_braces - close_braces
            missing_brackets = open_brackets - close_brackets
            
            if missing_braces > 0 or missing_brackets > 0:
                fixed = json_str
                
                # Vérifier si le JSON se termine par une virgule incomplète
                fixed = re.sub(r',\s*$', '', fixed.strip())
                
                # Ajouter les fermetures manquantes
                for _ in range(missing_brackets):
                    fixed += ']'
                for _ in range(missing_braces):
                    fixed += '}'
                
                logger.info(f"Tentative de réparation: ajout de {missing_braces} }} et {missing_brackets} ]")
                return fixed
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur lors de la réparation du JSON: {str(e)}")
            return None
    
    def _extract_vulnerabilities_from_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Extrait les vulnérabilités depuis un texte libre (fallback quand pas de JSON)
        
        Args:
            text: Texte de réponse libre
            
        Returns:
            Liste des vulnérabilités extraites
        """
        vulnerabilities = []
        
        try:
            # Mots-clés indiquant des vulnérabilités
            vuln_keywords = [
                r"injection\s*sql",
                r"cross[- ]site\s*scripting",
                r"xss",
                r"csrf",
                r"authentification",
                r"authorization",
                r"exposition\s*de\s*données",
                r"faille\s*de\s*sécurité",
                r"vulnérabilité",
                r"vulnerability",
                r"hardcoded\s*password",
                r"mot\s*de\s*passe\s*en\s*dur",
                r"buffer\s*overflow",
                r"path\s*traversal",
                r"command\s*injection",
                r"code\s*injection"
            ]
            
            lines = text.split('\n')
            current_vuln = {}
            
            for line in lines:
                line_lower = line.lower().strip()
                
                # Détecter le début d'une vulnérabilité
                for keyword_pattern in vuln_keywords:
                    if re.search(keyword_pattern, line_lower):
                        # Si on avait déjà une vulnérabilité en cours, la sauvegarder
                        if current_vuln and current_vuln.get("description"):
                            vulnerabilities.append(current_vuln)
                        
                        # Commencer une nouvelle vulnérabilité
                        current_vuln = {
                            "type_vulnerabilite": self._classify_vulnerability_type(line),
                            "severite": self._extract_severity_from_line(line),
                            "description": line.strip(),
                            "numeros_ligne": [],
                            "recommandation": "Vérifier et corriger cette vulnérabilité potentielle"
                        }
                        break
                
                    # Si on a une vulnérabilité en cours et que la ligne semble être une recommandation
                    elif current_vuln and any(word in line_lower for word in ['recommand', 'suggest', 'fix', 'corrig', 'solut']):
                        current_vuln["recommandation"] = line.strip()
                    
                    # Si on a une vulnérabilité en cours et que la ligne contient plus de détails
                    elif current_vuln and len(line.strip()) > 20 and not line.startswith('```'):
                        current_vuln["description"] += " " + line.strip()
            
            # Ajouter la dernière vulnérabilité si elle existe
            if current_vuln and current_vuln.get("description"):
                vulnerabilities.append(current_vuln)
            
            logger.info(f"Extraction textuelle: {len(vulnerabilities)} vulnérabilités trouvées")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction textuelle: {str(e)}")
            return []
    
    def _classify_vulnerability_type(self, line: str) -> str:
        """Classifie le type de vulnérabilité basée sur le contenu de la ligne"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['sql', 'injection sql']):
            return "Injection SQL"
        elif any(word in line_lower for word in ['xss', 'cross-site', 'scripting']):
            return "Cross-Site Scripting (XSS)"
        elif any(word in line_lower for word in ['csrf', 'cross-site request']):
            return "Cross-Site Request Forgery (CSRF)"
        elif any(word in line_lower for word in ['auth', 'authentification']):
            return "Problème d'authentification"
        elif any(word in line_lower for word in ['password', 'mot de passe', 'hardcoded']):
            return "Mot de passe codé en dur"
        elif any(word in line_lower for word in ['exposition', 'exposure', 'leak']):
            return "Exposition de données"
        elif any(word in line_lower for word in ['command', 'injection de commande']):
            return "Injection de commande"
        elif any(word in line_lower for word in ['path', 'traversal', 'directory']):
            return "Path Traversal"
        else:
            return "Vulnérabilité de sécurité"
    
    def _extract_severity_from_line(self, line: str) -> str:
        """Extrait le niveau de sévérité depuis une ligne"""
        line_lower = line.lower()
        
        if any(word in line_lower for word in ['critical', 'critique', 'élevé', 'high', 'grave']):
            return "Élevé"
        elif any(word in line_lower for word in ['medium', 'moyen', 'moderate']):
            return "Moyen"
        elif any(word in line_lower for word in ['low', 'faible', 'minor']):
            return "Faible"
        else:
            # Classification par défaut basée sur le type
            if any(word in line_lower for word in ['sql', 'xss', 'command injection']):
                return "Élevé"
            elif any(word in line_lower for word in ['csrf', 'auth']):
                return "Moyen"
            else:
                return "Moyen"
    
    def evaluate_response_quality(self, response: Dict[str, Any]) -> float:
        """
        Évalue la qualité d'une réponse d'analyse
        
        Args:
            response: Réponse de l'analyse
            
        Returns:
            Score de qualité (0.0 à 1.0)
        """
        if not response or not isinstance(response, dict):
            logger.warning("Réponse invalide pour l'évaluation de qualité")
            return 0.0
            
        score = 0.0
        
        try:
            # Vérifier si la réponse contient une liste de vulnérabilités structurée
            vulnerabilities = response.get("vulnerabilities", [])
            if isinstance(vulnerabilities, list):
                # Points de base pour une liste valide
                score += 0.2
                
                # Points pour chaque vulnérabilité bien formée
                valid_vulns = 0
                for vuln in vulnerabilities:
                    # Vérifier les champs essentiels (utiliser les noms français et anglais)
                    required_fields = ["description"]
                    type_field = vuln.get("vulnerability_type") or vuln.get("type_vulnerabilite")
                    severity_field = vuln.get("severity") or vuln.get("severite")
                    recommendation_field = vuln.get("recommendation") or vuln.get("recommandation")
                    
                    if (isinstance(vuln, dict) and 
                        vuln.get("description") and 
                        type_field and 
                        severity_field and 
                        recommendation_field):
                        valid_vulns += 1
                
                # Calculer le pourcentage de vulnérabilités valides
                if vulnerabilities:
                    score += 0.5 * (valid_vulns / len(vulnerabilities))
                
                # Points pour la diversité des types de vulnérabilités
                unique_types = len(set(
                    (v.get("vulnerability_type") or v.get("type_vulnerabilite", "")) 
                    for v in vulnerabilities 
                    if isinstance(v, dict) and (v.get("vulnerability_type") or v.get("type_vulnerabilite"))
                ))
                if unique_types > 0:
                    score += 0.15 * min(unique_types / 5, 1.0)  # Max 15% pour la diversité (plafonné à 5 types)
                
                # Points pour la diversité des niveaux de sévérité
                unique_severities = len(set(
                    (v.get("severity") or v.get("severite", "")) 
                    for v in vulnerabilities 
                    if isinstance(v, dict) and (v.get("severity") or v.get("severite"))
                ))
                if unique_severities > 0:
                    score += 0.15 * min(unique_severities / 3, 1.0)  # Max 15% pour la diversité (plafonné à 3 niveaux)
            
            # Si pas de structure JSON mais une réponse brute
            elif "raw_response" in response:
                # Analyse simpliste basée sur la longueur et les mots-clés
                raw_text = response.get("raw_response", "")
                if raw_text and isinstance(raw_text, str):
                    score += 0.1  # Points de base pour avoir une réponse
                    
                    # Points pour la longueur (jusqu'à un certain point)
                    score += 0.1 * min(len(raw_text) / 1000, 1.0)  # Max 10% pour la longueur (plafonné à 1000 caractères)
                    
                    # Points pour les mots-clés liés à la sécurité
                    security_keywords = ["vulnérabilité", "sécurité", "injection", "XSS", "authentification", 
                                        "autorisation", "exposition", "faille", "risque", "CVE", "vulnerability", 
                                        "security", "authentication", "authorization", "exposure", "risk"]
                    keyword_count = sum(1 for keyword in security_keywords if keyword.lower() in raw_text.lower())
                    score += 0.2 * min(keyword_count / len(security_keywords), 1.0)  # Max 20% pour les mots-clés
                else:
                    logger.warning("raw_response est vide ou n'est pas une chaîne")
            
            logger.debug(f"Score de qualité calculé: {score}")
            return min(score, 1.0)  # Plafonner à 1.0
            
        except Exception as e:
            logger.error(f"Erreur lors de l'évaluation de la qualité: {str(e)}")
            import traceback
            logger.debug(f"Traceback: {traceback.format_exc()}")
            return 0.0
    
    async def compare_models(self, models: List[str], code: str, prompt: str) -> Dict[str, Any]:
        """
        Compare les résultats d'analyse entre différents modèles
        
        Args:
            models: Liste des modèles à comparer
            code: Code source à analyser
            prompt: Instructions pour l'analyse
            
        Returns:
            Résultats des modèles avec scores et meilleur modèle
        """
        results = {}
        best_model = None
        best_score = -1
        
        if not models:
            logger.warning("Aucun modèle fourni pour l'analyse")
            return {
                "results": {},
                "best_model": None,
                "best_score": 0.0,
                "error": "Aucun modèle fourni"
            }
        
        for model in models:
            try:
                logger.info(f"Analyse avec le modèle {model}")
                response = await self.analyze_code(model, code, prompt)
                
                # Si une erreur s'est produite
                if "error" in response:
                    logger.warning(f"Erreur dans la réponse du modèle {model}: {response.get('error')}")
                    results[model] = {
                        "response": response,
                        "quality_score": 0.0,
                        "error": response.get("error")
                    }
                    continue
                
                # Évaluer la qualité de la réponse
                quality_score = self.evaluate_response_quality(response)
                
                results[model] = {
                    "response": response,
                    "quality_score": quality_score
                }
                
                logger.info(f"Score de qualité pour {model}: {quality_score}")
                
                # Mettre à jour le meilleur modèle si nécessaire
                if quality_score > best_score:
                    best_score = quality_score
                    best_model = model
                    
            except Exception as e:
                logger.error(f"Erreur avec le modèle {model}: {str(e)}")
                import traceback
                logger.debug(f"Traceback pour {model}: {traceback.format_exc()}")
                results[model] = {
                    "error": str(e),
                    "quality_score": 0.0,
                    "response": {"error": str(e), "vulnerabilities": []}
                }
        
        # Si aucun modèle n'a réussi
        if best_model is None and models:
            logger.warning("Tous les modèles ont échoué, sélection du premier modèle comme fallback")
            best_model = models[0]
            best_score = 0.0
        
        return {
            "results": results,
            "best_model": best_model,
            "best_score": best_score
        }