import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { 
  Chart as ChartJS, 
  ArcElement, 
  CategoryScale, 
  LinearScale, 
  BarElement, 
  Title, 
  Tooltip, 
  Legend,
  PointElement,
  LineElement,
  RadialLinearScale
} from 'chart.js';
import { Pie, Bar, Doughnut, Radar } from 'react-chartjs-2';
import './Analysis.css';

// Enregistrer les composants ChartJS
ChartJS.register(
  ArcElement, 
  CategoryScale, 
  LinearScale, 
  BarElement, 
  Title, 
  Tooltip, 
  Legend,
  PointElement,
  LineElement,
  RadialLinearScale
);

function Analysis() {
  const { repoName } = useParams();
  const { token, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState('');
  const [taskId, setTaskId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [availableModels, setAvailableModels] = useState([]);
  const [selectedModels, setSelectedModels] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  
  // Vérifier l'authentification
  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);
  
  // Récupérer les modèles Ollama disponibles
  useEffect(() => {
    async function fetchOllamaModels() {
      try {
        const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/ollama/models`);
        
        if (response.ok) {
          const data = await response.json();
          setAvailableModels(data.models);
          setSelectedModels(data.models);
        } else {
          setError('Impossible de récupérer les modèles Ollama');
        }
      } catch (error) {
        console.error('Erreur lors de la récupération des modèles Ollama:', error);
        setError('Erreur de connexion au serveur');
      }
    }
    
    fetchOllamaModels();
  }, []);

  // Démarrer l'analyse
  const startAnalysis = async () => {
    if (!token || !repoName) return;
    
    setAnalyzing(true);
    setError('');
    setProgress(0);
    
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/analysis/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token,
          repo_name: repoName,
          models: selectedModels
        }),
      });
      
      if (!response.ok) {
        throw new Error(`Erreur HTTP ${response.status}`);
      }
      
      const data = await response.json();
      setTaskId(data.task_id);
      
      pollTaskStatus(data.task_id);
    } catch (error) {
      console.error('Erreur lors du démarrage de l\'analyse:', error);
      setError(`Impossible de démarrer l'analyse: ${error.message}`);
      setAnalyzing(false);
    }
  };
  
  // Vérifier périodiquement le statut de la tâche
  const pollTaskStatus = async (taskId) => {
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/analysis/status/${taskId}`);
      
      if (!response.ok) {
        throw new Error(`Erreur HTTP ${response.status}`);
      }
      
      const data = await response.json();
      setProgress(data.progress * 100);
      
      if (data.status === 'terminé') {
        setResult(data.result);
        setAnalyzing(false);
      } else if (data.status === 'erreur') {
        setError(`Erreur lors de l'analyse: ${data.error || 'Raison inconnue'}`);
        setAnalyzing(false);
      } else {
        setTimeout(() => pollTaskStatus(taskId), 2000);
      }
    } catch (error) {
      console.error('Erreur lors de la récupération du statut:', error);
      setError(`Erreur lors de la récupération du statut: ${error.message}`);
      setAnalyzing(false);
    }
  };
  
  // Télécharger le rapport PDF
  const downloadPDF = async () => {
    if (!taskId) return;
    
    setLoading(true);
    try {
      const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/report/pdf/${taskId}`, {
        method: 'GET',
        headers: {
          'Accept': 'application/pdf',
        },
      });
      
      if (!response.ok) {
        throw new Error(`Erreur HTTP ${response.status}`);
      }
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `rapport-vulnerabilite-${repoName.replace('/', '-')}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Erreur lors du téléchargement du PDF:', error);
      setError(`Impossible de télécharger le PDF: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };
  
  // Gérer le changement dans la sélection des modèles
  const handleModelChange = (model) => {
    if (selectedModels.includes(model)) {
      setSelectedModels(selectedModels.filter(m => m !== model));
    } else {
      setSelectedModels([...selectedModels, model]);
    }
  };
  
  // Générer les données pour le graphique de sévérité
  const getSeverityChartData = () => {
    if (!result || !result.summary || !result.summary.severity_counts) {
      return null;
    }
    
    const { severity_counts } = result.summary;
    
    return {
      labels: ['Élevé', 'Moyen', 'Faible'],
      datasets: [
        {
          data: [severity_counts['Élevé'], severity_counts['Moyen'], severity_counts['Faible']],
          backgroundColor: ['#ff4b4b', '#ffa500', '#4b96ff'],
          borderColor: ['#e60000', '#e69500', '#0066cc'],
          borderWidth: 1,
        },
      ],
    };
  };
  
  // Générer les données pour le graphique par type
  const getTypeChartData = () => {
    if (!result || !result.summary || !result.summary.vulnerabilities_by_type) {
      return null;
    }
    
    const byType = result.summary.vulnerabilities_by_type;
    const labels = Object.keys(byType);
    const data = Object.values(byType);
    
    return {
      labels,
      datasets: [
        {
          label: 'Vulnérabilités par type',
          data,
          backgroundColor: 'rgba(54, 162, 235, 0.6)',
          borderColor: 'rgba(54, 162, 235, 1)',
          borderWidth: 1,
        },
      ],
    };
  };
  
  // Générer les données pour le graphique par langage
  const getLanguageChartData = () => {
    if (!result || !result.summary || !result.summary.vulnerabilities_by_language) {
      return null;
    }
    
    const byLanguage = result.summary.vulnerabilities_by_language;
    const labels = Object.keys(byLanguage);
    const data = Object.values(byLanguage);
    
    return {
      labels,
      datasets: [
        {
          label: 'Vulnérabilités par langage',
          data,
          backgroundColor: 'rgba(75, 192, 192, 0.6)',
          borderColor: 'rgba(75, 192, 192, 1)',
          borderWidth: 1,
        },
      ],
    };
  };

  // Générer les données pour le graphique radar de risque
  const getRiskRadarData = () => {
    if (!result || !result.risk_assessment || !result.risk_assessment.risk_factors) {
      return null;
    }

    const factors = result.risk_assessment.risk_factors;
    
    return {
      labels: ['Sévérité', 'Volume', 'Diversité', 'Fichiers Critiques'],
      datasets: [
        {
          label: 'Facteurs de Risque',
          data: [
            factors.severity_impact || 0,
            factors.volume_impact || 0,
            factors.diversity_impact || 0,
            factors.critical_files_impact || 0
          ],
          backgroundColor: 'rgba(255, 99, 132, 0.2)',
          borderColor: 'rgba(255, 99, 132, 1)',
          borderWidth: 2,
          pointBackgroundColor: 'rgba(255, 99, 132, 1)',
        },
      ],
    };
  };

  // Générer les données pour les hotspots
  const getHotspotsData = () => {
    if (!result || !result.security_patterns || !result.security_patterns.hotspots) {
      return null;
    }

    const hotspots = result.security_patterns.hotspots;
    const sortedHotspots = Object.entries(hotspots)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10);

    return {
      labels: sortedHotspots.map(([file]) => file.split('/').pop() || file),
      datasets: [
        {
          label: 'Vulnérabilités par fichier',
          data: sortedHotspots.map(([,count]) => count),
          backgroundColor: sortedHotspots.map((_, i) => 
            i < 3 ? '#ff4b4b' : i < 6 ? '#ffa500' : '#4b96ff'
          ),
          borderWidth: 1,
        },
      ],
    };
  };

  // Générer les données pour la performance des modèles
  const getModelPerformanceData = () => {
    if (!result || !result.model_performance_metrics || !result.model_performance_metrics.model_rankings) {
      return null;
    }

    const rankings = result.model_performance_metrics.model_rankings;
    
    return {
      labels: rankings.map(m => m.model),
      datasets: [
        {
          label: 'Score de Performance',
          data: rankings.map(m => m.performance_score),
          backgroundColor: 'rgba(153, 102, 255, 0.6)',
          borderColor: 'rgba(153, 102, 255, 1)',
          borderWidth: 1,
        },
        {
          label: 'Fiabilité (%)',
          data: rankings.map(m => m.reliability),
          backgroundColor: 'rgba(255, 159, 64, 0.6)',
          borderColor: 'rgba(255, 159, 64, 1)',
          borderWidth: 1,
        },
      ],
    };
  };

  // Fonction pour obtenir la couleur du score de sécurité
  const getSecurityScoreColor = (score) => {
    if (score >= 80) return '#28a745'; // Vert
    if (score >= 60) return '#ffc107'; // Jaune
    if (score >= 40) return '#fd7e14'; // Orange
    return '#dc3545'; // Rouge
  };

  // Fonction pour obtenir la couleur du risque
  const getRiskColor = (riskLevel) => {
    const colors = {
      'Très faible': '#28a745',
      'Faible': '#6f42c1',
      'Moyen': '#ffc107',
      'Élevé': '#fd7e14',
      'Critique': '#dc3545'
    };
    return colors[riskLevel] || '#6c757d';
  };

  // Composant pour afficher les insights actionnables
  const ActionableInsights = ({ insights }) => (
    <div className="actionable-insights">
      <div className="insights-grid">
        <div className="insight-card immediate">
          <h4>🚨 Actions Immédiates</h4>
          <ul>
            {insights.immediate_actions.map((action, i) => (
              <li key={i}>{action}</li>
            ))}
          </ul>
        </div>
        
        <div className="insight-card short-term">
          <h4>🎯 Objectifs à Court Terme</h4>
          <ul>
            {insights.short_term_goals.map((goal, i) => (
              <li key={i}>{goal}</li>
            ))}
          </ul>
        </div>

        <div className="insight-card training">
          <h4>💡 Besoins de Formation</h4>
          <ul>
            {insights.training_needs.map((need, i) => (
              <li key={i}>{need}</li>
            ))}
          </ul>
        </div>

        <div className="insight-card tools">
          <h4>🔧 Outils Recommandés</h4>
          <ul>
            {insights.tool_recommendations.map((tool, i) => (
              <li key={i}>{tool}</li>
            ))}
          </ul>
        </div>
      </div>

      <div className="metrics-summary">
        <div className="metric">
          <span className="metric-label">Niveau de Maturité Sécurité:</span>
          <span className={`metric-value ${insights.metrics.security_maturity_level.toLowerCase()}`}>
            {insights.metrics.security_maturity_level}
          </span>
        </div>
        <div className="metric">
          <span className="metric-label">Priorité d'Amélioration:</span>
          <span className={`metric-value priority-${insights.metrics.improvement_priority.toLowerCase()}`}>
            {insights.metrics.improvement_priority}
          </span>
        </div>
        <div className="metric">
          <span className="metric-label">Temps de Correction Estimé:</span>
          <span className="metric-value">
            {insights.metrics.estimated_fix_time}
          </span>
        </div>
      </div>
    </div>
  );

  // Composant pour les comparaisons benchmark
  const BenchmarkComparison = ({ benchmark }) => (
    <div className="benchmark-comparison">
      <div className="benchmark-grid">
        <div className="benchmark-card">
          <h4>Densité de Vulnérabilités</h4>
          <div className="benchmark-value">
            <span className="current-value">{benchmark.vulnerability_density.current}</span>
            <span className="vs">vs</span>
            <span className="industry-value">{benchmark.vulnerability_density.industry_average}</span>
            <span className="label">moyenne industrie</span>
          </div>
          <div className={`status ${benchmark.vulnerability_density.status}`}>
            {benchmark.vulnerability_density.status === 'low' ? '✅ Bon' : '⚠️ À améliorer'}
          </div>
        </div>

        <div className="benchmark-card">
          <h4>Couverture Sécurité</h4>
          <div className="benchmark-value">
            <span className="current-value">{benchmark.security_coverage.current}%</span>
            <span className="vs">vs</span>
            <span className="industry-value">{benchmark.security_coverage.recommended_minimum}%</span>
            <span className="label">recommandé</span>
          </div>
          <div className={`status ${benchmark.security_coverage.status}`}>
            {benchmark.security_coverage.status === 'good' ? '✅ Bon' : '⚠️ À améliorer'}
          </div>
        </div>

        <div className="benchmark-card">
          <h4>Ratio Issues Critiques</h4>
          <div className="benchmark-value">
            <span className="current-value">{benchmark.critical_issues_ratio.current}%</span>
            <span className="vs">vs</span>
            <span className="industry-value">{benchmark.critical_issues_ratio.acceptable_threshold}%</span>
            <span className="label">seuil acceptable</span>
          </div>
          <div className={`status ${benchmark.critical_issues_ratio.status}`}>
            {benchmark.critical_issues_ratio.status === 'acceptable' ? '✅ Acceptable' : '🚨 Préoccupant'}
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="analysis-container">
      <div className="analysis-header">
        <h1>Analyse de {decodeURIComponent(repoName)}</h1>
        <button 
          onClick={() => navigate('/repositories')}
          className="back-button"
        >
          ← Retour aux dépôts
        </button>
      </div>
      
      {error && <div className="error-message">{error}</div>}
      
      {!analyzing && !result && (
        <div className="analysis-setup">
          <h2>Configuration de l'analyse</h2>
          
          <div className="model-selection">
            <h3>Sélection des modèles</h3>
            <p>Choisissez les modèles Ollama à utiliser pour l'analyse :</p>
            
            {availableModels.length > 0 ? (
              <div className="model-list">
                {availableModels.map(model => (
                  <div key={model} className="model-item">
                    <label>
                      <input
                        type="checkbox"
                        checked={selectedModels.includes(model)}
                        onChange={() => handleModelChange(model)}
                      />
                      {model}
                    </label>
                  </div>
                ))}
              </div>
            ) : (
              <p>Aucun modèle Ollama disponible. Assurez-vous qu'Ollama est en cours d'exécution.</p>
            )}
          </div>
          
          <button
            className="start-analysis-button"
            onClick={startAnalysis}
            disabled={selectedModels.length === 0}
          >
            Démarrer l'analyse
          </button>
          
          <div className="analysis-info">
            <h3>À propos de l'analyse</h3>
            <p>
              L'analyse utilisera Ollama pour examiner le code source et identifier les problèmes de sécurité,
              les mauvaises pratiques et les "code smells". Le processus peut prendre plusieurs minutes selon
              la taille du dépôt.
            </p>
            <p>
              Les modèles sélectionnés seront comparés et le meilleur résultat sera utilisé pour le rapport final.
            </p>
          </div>
        </div>
      )}
      
      {analyzing && (
        <div className="analysis-progress">
          <h2>Analyse en cours...</h2>
          <div className="progress-bar-container">
            <div className="progress-bar" style={{ width: `${progress}%` }}></div>
          </div>
          <p className="progress-text">{Math.round(progress)}% complété</p>
          <div className="analysis-steps">
            <div className={`step ${progress >= 10 ? 'completed' : progress > 0 ? 'active' : ''}`}>Clone du dépôt</div>
            <div className={`step ${progress >= 30 ? 'completed' : progress >= 20 ? 'active' : ''}`}>Préparation des modèles</div>
            <div className={`step ${progress >= 80 ? 'completed' : progress >= 30 ? 'active' : ''}`}>Analyse du code</div>
            <div className={`step ${progress >= 90 ? 'completed' : progress >= 80 ? 'active' : ''}`}>Génération du rapport</div>
            <div className={`step ${progress >= 100 ? 'completed' : progress >= 90 ? 'active' : ''}`}>Finalisation</div>
          </div>
        </div>
      )}
      
      {result && (
        <div className="analysis-results">
          <div className="results-header">
            <div className="results-summary">
              <h2>Résultats de l'analyse</h2>
              <p>
                Analyse effectuée le {new Date(result.analysis_date).toLocaleString('fr-FR')} 
                avec le modèle {result.best_model}
              </p>
              
              {/* Score de sécurité avec risque */}
              <div className="security-metrics">
                <div className="security-score">
                  <h3>Score de sécurité</h3>
                  <div 
                    className={`score-value ${
                      result.summary.security_score >= 80 ? 'high' : 
                      result.summary.security_score >= 50 ? 'medium' : 'low'
                    }`}
                    style={{ color: getSecurityScoreColor(result.summary.security_score) }}
                  >
                    {result.summary.security_score || 0}/100
                  </div>
                </div>

                {result.risk_assessment && (
                  <div className="risk-assessment">
                    <h3>Niveau de risque</h3>
                    <div 
                      className="risk-value"
                      style={{ 
                        backgroundColor: getRiskColor(result.risk_assessment.overall_risk),
                        color: 'white',
                        padding: '10px',
                        borderRadius: '8px',
                        textAlign: 'center'
                      }}
                    >
                      {result.risk_assessment.overall_risk}
                      <div className="risk-score">
                        Score: {result.risk_assessment.risk_score}/25
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
            
            <button
              className="download-pdf-button"
              onClick={downloadPDF}
              disabled={loading}
            >
              {loading ? 'Téléchargement...' : 'Télécharger le PDF'}
            </button>
          </div>

          {/* Navigation par onglets */}
          <div className="results-navigation">
            <div className="tab-buttons">
              <button 
                className={activeTab === 'overview' ? 'active' : ''}
                onClick={() => setActiveTab('overview')}
              >
                📊 Vue d'ensemble
              </button>
              <button 
                className={activeTab === 'vulnerabilities' ? 'active' : ''}
                onClick={() => setActiveTab('vulnerabilities')}
              >
                🔍 Vulnérabilités
              </button>
              <button 
                className={activeTab === 'insights' ? 'active' : ''}
                onClick={() => setActiveTab('insights')}
              >
                💡 Insights
              </button>
              <button 
                className={activeTab === 'models' ? 'active' : ''}
                onClick={() => setActiveTab('models')}
              >
                🤖 Modèles IA
              </button>
              <button 
                className={activeTab === 'benchmark' ? 'active' : ''}
                onClick={() => setActiveTab('benchmark')}
              >
                📈 Benchmark
              </button>
            </div>
          </div>

          {/* Contenu des onglets */}
          {activeTab === 'overview' && (
            <div className="tab-content">
              <div className="results-overview">
                <div className="vulnerability-counts">
                  <div className="count-item total">
                    <span className="count-value">{result.summary?.total_vulnerabilities || 0}</span>
                    <span className="count-label">Total</span>
                  </div>
                  <div className="count-item high">
                    <span className="count-value">{result.summary?.severity_counts?.Élevé || 0}</span>
                    <span className="count-label">Élevé</span>
                  </div>
                  <div className="count-item medium">
                    <span className="count-value">{result.summary?.severity_counts?.Moyen || 0}</span>
                    <span className="count-label">Moyen</span>
                  </div>
                  <div className="count-item low">
                    <span className="count-value">{result.summary?.severity_counts?.Faible || 0}</span>
                    <span className="count-label">Faible</span>
                  </div>
                </div>
              </div>
              
              <div className="results-charts">
                {getSeverityChartData() && (
                  <div className="chart-container">
                    <h3>Distribution par sévérité</h3>
                    <Pie data={getSeverityChartData()} options={{ responsive: true }} />
                  </div>
                )}
                
                {getRiskRadarData() && (
                  <div className="chart-container">
                    <h3>Analyse des facteurs de risque</h3>
                    <Radar 
                      data={getRiskRadarData()} 
                      options={{
                        responsive: true,
                        scales: {
                          r: {
                            beginAtZero: true,
                            max: 20
                          }
                        }
                      }} 
                    />
                  </div>
                )}

                {getHotspotsData() && (
                  <div className="chart-container">
                    <h3>Fichiers les plus problématiques</h3>
                    <Bar 
                      data={getHotspotsData()} 
                      options={{
                        responsive: true,
                        maintainAspectRatio: false,
                        indexAxis: 'y',
                        scales: {
                          x: {
                            beginAtZero: true,
                            ticks: { precision: 0 }
                          }
                        }
                      }} 
                    />
                  </div>
                )}
                
                {getTypeChartData() && (
                  <div className="chart-container">
                    <h3>Vulnérabilités par type</h3>
                    <Bar 
                      data={getTypeChartData()} 
                      options={{
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                          y: {
                            beginAtZero: true,
                            ticks: { precision: 0 }
                          }
                        }
                      }} 
                    />
                  </div>
                )}
                
                {getLanguageChartData() && (
                  <div className="chart-container">
                    <h3>Vulnérabilités par langage</h3>
                    <Doughnut 
                      data={getLanguageChartData()} 
                      options={{ responsive: true }} 
                    />
                  </div>
                )}
              </div>

              {/* Statistiques temporelles */}
              {result.temporal_analysis && (
                <div className="temporal-stats">
                  <h3>Statistiques de performance</h3>
                  <div className="stats-grid">
                    <div className="stat-item">
                      <span className="stat-label">Durée totale:</span>
                      <span className="stat-value">{result.temporal_analysis.total_duration}</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">Fichiers/minute:</span>
                      <span className="stat-value">{result.temporal_analysis.throughput.files_per_minute}</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">Vulnérabilités/minute:</span>
                      <span className="stat-value">{result.temporal_analysis.throughput.vulnerabilities_found_per_minute}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'vulnerabilities' && (
            <div className="tab-content">
              <div className="vulnerabilities-list">
                <h3>Vulnérabilités détectées</h3>
                
                {result.vulnerabilities?.length === 0 ? (
                  <div className="no-vulnerabilities">
                    <p>🎉 Aucune vulnérabilité détectée. Excellent travail !</p>
                  </div>
                ) : (
                  <div className="vulnerabilities-table-container">
                    <table className="vulnerabilities-table">
                      <thead>
                        <tr>
                          <th>Type</th>
                          <th>Sévérité</th>
                          <th>Fichier</th>
                          <th>Lignes</th>
                          <th>Description</th>
                          <th>Recommandation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.vulnerabilities?.map((vuln, index) => {
                          const severity = vuln.severity || vuln.severite;
                          const vulnerabilityType = vuln.vulnerability_type || vuln.type_vulnerabilite;
                          const description = vuln.description;
                          const recommendation = vuln.recommendation || vuln.recommandation;
                          const lineNumbers = vuln.line_numbers || vuln.numeros_ligne;
                          
                          let lineStr = '';
                          if (Array.isArray(lineNumbers)) {
                            lineStr = lineNumbers.join(', ');
                          } else {
                            lineStr = 'N/A';
                          }
                          
                          return (
                            <tr key={index} className={`severity-${severity === 'Élevé' ? 'high' : severity === 'Moyen' ? 'medium' : 'low'}`}>
                              <td>{vulnerabilityType}</td>
                              <td className="severity-cell">{severity}</td>
                              <td>{vuln.file_path}</td>
                              <td>{lineStr}</td>
                              <td>{description}</td>
                              <td>{recommendation}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'insights' && (
            <div className="tab-content">
              {result.actionable_insights && (
                <ActionableInsights insights={result.actionable_insights} />
              )}

              {/* Modèles de sécurité */}
              {result.security_patterns && (
                <div className="security-patterns">
                  <h3>Analyse des modèles de sécurité</h3>
                  
                  {result.security_patterns.security_debt && (
                    <div className="security-debt">
                      <h4>Dette technique de sécurité</h4>
                      <div className="debt-score">
                        <span className="score-label">Score de dette technique:</span>
                        <span className={`score-value ${
                          result.security_patterns.security_debt.technical_debt_score < 30 ? 'low' :
                          result.security_patterns.security_debt.technical_debt_score < 60 ? 'medium' : 'high'
                        }`}>
                          {result.security_patterns.security_debt.technical_debt_score}%
                        </span>
                      </div>
                      
                      {result.security_patterns.security_debt.maintenance_priority?.length > 0 && (
                        <div className="maintenance-priority">
                          <h5>Priorités de maintenance</h5>
                          <div className="priority-list">
                            {result.security_patterns.security_debt.maintenance_priority.map((item, i) => (
                              <div key={i} className={`priority-item ${item.priority.toLowerCase()}`}>
                                <span className="file-name">{item.file}</span>
                                <span className="vuln-count">{item.vulnerability_count} vulnérabilités</span>
                                <span className="priority-badge">{item.priority}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Erreurs communes */}
                  {result.security_patterns.trend_analysis?.common_mistakes && (
                    <div className="common-mistakes">
                      <h4>Erreurs les plus fréquentes</h4>
                      <div className="mistakes-grid">
                        {Object.entries(result.security_patterns.trend_analysis.common_mistakes).map(([mistake, count]) => (
                          <div key={mistake} className="mistake-item">
                            <span className="mistake-name">{mistake}</span>
                            <span className="mistake-count">{count} occurrences</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Composants affectés */}
                  {result.security_patterns.affected_components && (
                    <div className="affected-components">
                      <h4>Composants les plus affectés</h4>
                      <div className="components-list">
                        {Object.entries(result.security_patterns.affected_components)
                          .sort(([,a], [,b]) => b - a)
                          .slice(0, 5)
                          .map(([component, count]) => (
                            <div key={component} className="component-item">
                              <span className="component-name">{component}</span>
                              <span className="component-count">{count} vulnérabilités</span>
                              <div className="component-bar">
                                <div 
                                  className="bar-fill" 
                                  style={{ 
                                    width: `${(count / Math.max(...Object.values(result.security_patterns.affected_components))) * 100}%` 
                                  }}
                                ></div>
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Prédictions et tendances */}
              {result.trend_predictions && (
                <div className="trend-predictions">
                  <h3>Prédictions et tendances</h3>
                  <div className="predictions-grid">
                    <div className="prediction-card">
                      <h4>Tendance sécurité</h4>
                      <span className={`trend-value ${result.trend_predictions.security_trend}`}>
                        {result.trend_predictions.security_trend === 'improving' ? '📈 En amélioration' :
                         result.trend_predictions.security_trend === 'stable' ? '➡️ Stable' : '⚠️ Nécessite attention'}
                      </span>
                    </div>
                    
                    <div className="prediction-card">
                      <h4>Prochaine revue recommandée</h4>
                      <span className="next-review">
                        📅 {new Date(result.trend_predictions.next_review_recommended).toLocaleDateString('fr-FR')}
                      </span>
                    </div>

                    <div className="prediction-card">
                      <h4>Zones prioritaires</h4>
                      <div className="priority-areas">
                        {result.trend_predictions.priority_areas?.slice(0, 3).map(([language, count], i) => (
                          <div key={i} className="priority-area">
                            {language}: {count} vulnérabilités
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'models' && (
            <div className="tab-content">
              {result.model_performance_metrics && (
                <div className="model-analysis">
                  <h3>Performance des modèles IA</h3>
                  
                  {/* Résumé des performances */}
                  {result.model_performance_metrics.performance_summary && (
                    <div className="performance-summary">
                      <div className="summary-cards">
                        <div className="summary-card best">
                          <h4>🏆 Meilleur modèle</h4>
                          <div className="card-content">
                            <span className="model-name">{result.model_performance_metrics.performance_summary.best_performer}</span>
                            <span className="score">Score: {result.model_performance_metrics.performance_summary.best_performance_score}</span>
                          </div>
                        </div>
                        
                        <div className="summary-card reliable">
                          <h4>🛡️ Plus fiable</h4>
                          <div className="card-content">
                            <span className="model-name">{result.model_performance_metrics.performance_summary.most_reliable_model}</span>
                            <span className="reliability">{result.model_performance_metrics.performance_summary.highest_reliability}% de succès</span>
                          </div>
                        </div>
                        
                        <div className="summary-card average">
                          <h4>📊 Performance moyenne</h4>
                          <div className="card-content">
                            <span className="avg-score">{result.model_performance_metrics.performance_summary.average_performance}</span>
                            <span className="label">sur {result.model_performance_metrics.performance_summary.total_models_tested} modèles</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Graphique de performance des modèles */}
                  {getModelPerformanceData() && (
                    <div className="chart-container">
                      <h4>Comparaison des performances</h4>
                      <Bar 
                        data={getModelPerformanceData()} 
                        options={{
                          responsive: true,
                          maintainAspectRatio: false,
                          scales: {
                            y: {
                              beginAtZero: true,
                              max: 100
                            }
                          },
                          plugins: {
                            legend: {
                              position: 'top',
                            },
                          },
                        }} 
                      />
                    </div>
                  )}

                  {/* Détails des modèles */}
                  {result.model_performance_metrics.model_rankings && (
                    <div className="model-rankings">
                      <h4>Classement détaillé</h4>
                      <div className="rankings-table">
                        <table>
                          <thead>
                            <tr>
                              <th>Rang</th>
                              <th>Modèle</th>
                              <th>Performance</th>
                              <th>Qualité</th>
                              <th>Fiabilité</th>
                              <th>Analyses</th>
                            </tr>
                          </thead>
                          <tbody>
                            {result.model_performance_metrics.model_rankings.map((model, index) => (
                              <tr key={model.model} className={index === 0 ? 'best-model' : ''}>
                                <td>{index + 1}</td>
                                <td>{model.model}</td>
                                <td>
                                  <div className="performance-bar">
                                    <div 
                                      className="bar-fill" 
                                      style={{ width: `${model.performance_score}%` }}
                                    ></div>
                                    <span>{model.performance_score}</span>
                                  </div>
                                </td>
                                <td>{model.quality_score.toFixed(3)}</td>
                                <td>{model.reliability}%</td>
                                <td>{model.analyses_completed}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Recommandations */}
                  {result.model_performance_metrics.recommendation && (
                    <div className="model-recommendations">
                      <h4>Recommandations</h4>
                      <div className="recommendation-content">
                        <p><strong>Meilleur modèle global:</strong> {result.model_performance_metrics.recommendation.best_overall}</p>
                        <p><strong>Modèle le plus fiable:</strong> {result.model_performance_metrics.recommendation.most_reliable}</p>
                        
                        {result.model_performance_metrics.recommendation.reasons?.length > 0 && (
                          <div className="reasons">
                            <h5>Raisons:</h5>
                            <ul>
                              {result.model_performance_metrics.recommendation.reasons.map((reason, i) => (
                                <li key={i}>{reason}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'benchmark' && (
            <div className="tab-content">
              {result.benchmark_comparison && (
                <BenchmarkComparison benchmark={result.benchmark_comparison} />
              )}

              {/* Statistiques du dépôt */}
              {result.repository_context && (
                <div className="repository-stats">
                  <h3>Statistiques du dépôt</h3>
                  <div className="stats-grid">
                    <div className="stat-card">
                      <h4>📁 Fichiers</h4>
                      <div className="stat-value">{result.repository_context.total_files}</div>
                    </div>
                    
                    <div className="stat-card">
                      <h4>💾 Taille</h4>
                      <div className="stat-value">
                        {(result.repository_context.total_size_bytes / 1024 / 1024).toFixed(1)} MB
                      </div>
                    </div>
                    
                    <div className="stat-card">
                      <h4>📝 Lignes de code</h4>
                      <div className="stat-value">{result.repository_context.lines_of_code.total.toLocaleString()}</div>
                    </div>
                    
                    <div className="stat-card">
                      <h4>🏥 Santé du dépôt</h4>
                      <div className={`stat-value health-${
                        result.repository_context.repository_health.score >= 80 ? 'high' :
                        result.repository_context.repository_health.score >= 60 ? 'medium' : 'low'
                      }`}>
                        {result.repository_context.repository_health.score}/100
                      </div>
                    </div>
                  </div>

                  {/* Langages */}
                  {result.repository_context.languages && (
                    <div className="languages-breakdown">
                      <h4>Langages de programmation</h4>
                      <div className="languages-list">
                        {Object.entries(result.repository_context.languages)
                          .sort(([,a], [,b]) => b - a)
                          .map(([language, count]) => (
                            <div key={language} className="language-item">
                              <span className="language-name">{language}</span>
                              <span className="language-count">{count} fichiers</span>
                              <div className="language-bar">
                                <div 
                                  className="bar-fill" 
                                  style={{ 
                                    width: `${(count / Math.max(...Object.values(result.repository_context.languages))) * 100}%` 
                                  }}
                                ></div>
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {/* Fichiers de configuration */}
                  {result.repository_context.configuration_files?.length > 0 && (
                    <div className="config-files">
                      <h4>Fichiers de configuration détectés</h4>
                      <div className="config-list">
                        {result.repository_context.configuration_files.map((config, i) => (
                          <div key={i} className="config-item">
                            <span className="config-file">{config.file}</span>
                            <span className="config-type">{config.type}</span>
                            <span className="config-size">{(config.size / 1024).toFixed(1)} KB</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Statistiques d'analyse */}
              {result.analysis_stats && (
                <div className="analysis-statistics">
                  <h3>Statistiques d'analyse</h3>
                  <div className="analysis-grid">
                    <div className="analysis-stat">
                      <span className="stat-label">Fichiers trouvés:</span>
                      <span className="stat-value">{result.analysis_stats.total_files_found}</span>
                    </div>
                    <div className="analysis-stat">
                      <span className="stat-label">Fichiers analysés:</span>
                      <span className="stat-value">{result.analysis_stats.files_analyzed}</span>
                    </div>
                    <div className="analysis-stat">
                      <span className="stat-label">Fichiers ignorés:</span>
                      <span className="stat-value">{result.analysis_stats.files_ignored}</span>
                    </div>
                    <div className="analysis-stat">
                      <span className="stat-label">Erreurs:</span>
                      <span className="stat-value">{result.analysis_stats.files_with_errors}</span>
                    </div>
                    <div className="analysis-stat">
                      <span className="stat-label">Couverture:</span>
                      <span className="stat-value">{result.analysis_stats.analysis_coverage}%</span>
                    </div>
                    <div className="analysis-stat">
                      <span className="stat-label">Vitesse:</span>
                      <span className="stat-value">{result.analysis_stats.analysis_speed} fichiers/s</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default Analysis;