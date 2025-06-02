import logging
from typing import List, Dict, Any, Optional
import json
from datetime import datetime
from fpdf import FPDF
import base64
import os
import io

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReportGenerator:
    """Générateur de rapports pour les analyses de vulnérabilités"""
    
    def __init__(self, repo_name: str, vulnerabilities: List[Dict[str, Any]], best_model: Optional[str] = None):
        """
        Initialise le générateur de rapports
        
        Args:
            repo_name: Nom du dépôt GitHub
            vulnerabilities: Liste des vulnérabilités détectées
            best_model: Nom du meilleur modèle utilisé
        """
        self.repo_name = repo_name
        self.vulnerabilities = vulnerabilities
        self.best_model = best_model
        self.analysis_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Génère un rapport complet de l'analyse
        
        Returns:
            Dictionnaire contenant les données du rapport
        """
        # Calculer les statistiques
        severity_counts = {
            "Élevé": 0,
            "Moyen": 0, 
            "Faible": 0
        }
        
        vulns_by_file = {}
        vulns_by_type = {}
        vulns_by_language = {}
        
        for vuln in self.vulnerabilities:
            # Comptage par sévérité 
            severity = vuln.get("severity") or vuln.get("severite")
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Comptage par fichier
            file_path = vuln.get("file_path", "Inconnu")
            if file_path in vulns_by_file:
                vulns_by_file[file_path] += 1
            else:
                vulns_by_file[file_path] = 1
            
            # Comptage par type 
            vuln_type = vuln.get("vulnerability_type") or vuln.get("type_vulnerabilite", "Autre")
            if vuln_type in vulns_by_type:
                vulns_by_type[vuln_type] += 1
            else:
                vulns_by_type[vuln_type] = 1
            
            # Comptage par langage
            language = vuln.get("language", "Inconnu")
            if language in vulns_by_language:
                vulns_by_language[language] += 1
            else:
                vulns_by_language[language] = 1
        
        # Trier les vulnérabilités par ordre de sévérité
        sorted_vulnerabilities = sorted(
            self.vulnerabilities,
            key=lambda v: {
                "Élevé": 0,
                "Moyen": 1,
                "Faible": 2
            }.get(v.get("severity") or v.get("severite"), 3)
        )
        
        # Calculer le score global de sécurité (inverse de la gravité moyenne)
        total_vulns = len(self.vulnerabilities)
        if total_vulns > 0:
            severity_values = {
                "Élevé": 10,
                "Moyen": 5,
                "Faible": 1
            }
            
            total_severity = (
                severity_counts["Élevé"] * severity_values["Élevé"] +
                severity_counts["Moyen"] * severity_values["Moyen"] +
                severity_counts["Faible"] * severity_values["Faible"]
            )
            
            # Formule: 100 - (total_severity * 100 / (total_vulns * 10))
            # 100 = score parfait, 0 = worst case (toutes les vulns sont élevées)
            security_score = max(0, 100 - (total_severity * 100 / (total_vulns * 10)))
        else:
            security_score = 100  # Score parfait si aucune vulnérabilité
        
        # Limiter la précision du score
        security_score = round(security_score, 1)
        
        # Générer le rapport final
        report = {
            "repo_name": self.repo_name,
            "analysis_date": self.analysis_date,
            "best_model": self.best_model,
            "vulnerabilities": sorted_vulnerabilities,
            "summary": {
                "total_vulnerabilities": total_vulns,
                "security_score": security_score,
                "severity_counts": severity_counts,
                "vulnerabilities_by_file": vulns_by_file,
                "vulnerabilities_by_type": vulns_by_type,
                "vulnerabilities_by_language": vulns_by_language
            }
        }
        
        return report
    
    def generate_pdf(self) -> bytes:
        """
        Génère un rapport PDF
        
        Returns:
            Contenu du PDF en bytes
        """
        # Créer l'objet PDF
        pdf = FPDF()
        pdf.add_page()
        
        # Définir la police
        pdf.set_font("Arial", "B", 16)
        
        # Titre
        pdf.cell(0, 10, f"Rapport d'Analyse de Sécurité", 0, 1, "C")
        pdf.cell(0, 10, f"Dépôt: {self.repo_name}", 0, 1, "C")
        pdf.ln(10)
        
        # Date d'analyse
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 5, f"Date d'analyse: {self.analysis_date}", 0, 1, "R")
        pdf.cell(0, 5, f"Meilleur modèle utilisé: {self.best_model}", 0, 1, "R")
        pdf.ln(5)
        
        # Résumé des vulnérabilités
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Résumé des Vulnérabilités", 0, 1, "L")
        pdf.set_font("Arial", "", 12)
        
        # Calculer les statistiques pour le PDF
        severity_counts = {"Élevé": 0, "Moyen": 0, "Faible": 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity") or vuln.get("severite")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_vulns = len(self.vulnerabilities)
        
        # Score de sécurité
        if total_vulns > 0:
            severity_values = {"Élevé": 10, "Moyen": 5, "Faible": 1}
            total_severity = (
                severity_counts["Élevé"] * severity_values["Élevé"] +
                severity_counts["Moyen"] * severity_values["Moyen"] +
                severity_counts["Faible"] * severity_values["Faible"]
            )
            security_score = max(0, 100 - (total_severity * 100 / (total_vulns * 10)))
        else:
            security_score = 100
        
        security_score = round(security_score, 1)
        
        # Ajouter le score de sécurité
        pdf.cell(0, 10, f"Score de Sécurité: {security_score}/100", 0, 1, "L")
        
        # Ajouter les statistiques de vulnérabilités
        pdf.cell(0, 10, f"Vulnérabilités totales: {total_vulns}", 0, 1, "L")
        pdf.cell(0, 10, f"Sévérité Élevée: {severity_counts['Élevé']}", 0, 1, "L")
        pdf.cell(0, 10, f"Sévérité Moyenne: {severity_counts['Moyen']}", 0, 1, "L")
        pdf.cell(0, 10, f"Sévérité Faible: {severity_counts['Faible']}", 0, 1, "L")
        pdf.ln(5)
        
        # Liste des vulnérabilités
        if total_vulns > 0:
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Vulnérabilités Détectées", 0, 1, "L")
            
            # Trier les vulnérabilités par ordre de sévérité
            sorted_vulnerabilities = sorted(
                self.vulnerabilities,
                key=lambda v: {
                    "Élevé": 0,
                    "Moyen": 1, 
                    "Faible": 2
                }.get(v.get("severity") or v.get("severite"), 3)
            )
            
            # Afficher chaque vulnérabilité
            for i, vuln in enumerate(sorted_vulnerabilities):
                severity = vuln.get("severity") or vuln.get("severite", "Inconnue")
                vuln_type = vuln.get("vulnerability_type") or vuln.get("type_vulnerabilite", "Autre")
                description = vuln.get("description", "Pas de description")
                file_path = vuln.get("file_path", "Inconnu")
                line_numbers = vuln.get("line_numbers") or vuln.get("numeros_ligne", [])
                if isinstance(line_numbers, list):
                    line_str = ", ".join(str(ln) for ln in line_numbers)
                else:
                    line_str = str(line_numbers)
                recommendation = vuln.get("recommendation") or vuln.get("recommandation", "Pas de recommandation")
                
                # Déterminer la couleur en fonction de la sévérité
                if severity == "Élevé":
                    pdf.set_text_color(255, 0, 0)  # Rouge
                elif severity == "Moyen":
                    pdf.set_text_color(255, 165, 0)  # Orange
                else:
                    pdf.set_text_color(0, 0, 255)  # Bleu
                
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, f"{i+1}. {vuln_type} ({severity})", 0, 1, "L")
                
                # Réinitialiser la couleur
                pdf.set_text_color(0, 0, 0)
                
                pdf.set_font("Arial", "", 10)
                pdf.cell(0, 8, f"Fichier: {file_path}", 0, 1, "L")
                pdf.cell(0, 8, f"Lignes: {line_str}", 0, 1, "L")
                
                # Description avec multi-cell pour le texte long
                pdf.set_font("Arial", "B", 10)
                pdf.cell(0, 8, "Description:", 0, 1, "L")
                pdf.set_font("Arial", "", 10)
                pdf.multi_cell(0, 6, description)
                
                # Recommandation avec multi-cell
                pdf.set_font("Arial", "B", 10)
                pdf.cell(0, 8, "Recommandation:", 0, 1, "L")
                pdf.set_font("Arial", "", 10)
                pdf.multi_cell(0, 6, recommendation)
                
                pdf.ln(5)
                
                # Ajouter une ligne de séparation
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(5)
        else:
            pdf.set_font("Arial", "B", 14)
            pdf.set_text_color(0, 128, 0)  # Vert
            pdf.cell(0, 10, "Aucune vulnérabilité détectée!", 0, 1, "L")
            pdf.set_text_color(0, 0, 0)
        
        # Pied de page
        pdf.set_y(-15)
        pdf.set_font("Arial", "I", 8)
        pdf.cell(0, 10, f"Rapport généré par l'Analyseur de Vulnérabilités GitHub", 0, 0, "C")
        
        # Retourner le PDF au format bytes
        return pdf.output(dest='S').encode('latin1')
    
    def get_download_link(self, file_content: bytes, file_name: str, link_text: str) -> str:
        """
        Génère un lien de téléchargement pour un fichier
        
        Args:
            file_content: Contenu du fichier en bytes
            file_name: Nom du fichier
            link_text: Texte du lien
            
        Returns:
            HTML pour le lien de téléchargement
        """
        b64 = base64.b64encode(file_content).decode()
        return f'<a href="data:application/octet-stream;base64,{b64}" download="{file_name}">{link_text}</a>'