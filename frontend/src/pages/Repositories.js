import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './Repositories.css';

function Repositories() {
  const [repositories, setRepositories] = useState([]);
  const [filteredRepos, setFilteredRepos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('updated_at');
  const [sortDirection, setSortDirection] = useState('desc');
  const [ollamaModels, setOllamaModels] = useState([]);
  const [isOllamaAvailable, setIsOllamaAvailable] = useState(false);
  const { token, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  // Vérifier l'authentification
  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);

  // Charger les dépôts
  useEffect(() => {
    async function fetchRepositories() {
      if (!token) return;

      setLoading(true);
      try {
        const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/repos/list`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ token }),
        });

        if (!response.ok) {
          throw new Error(`Erreur HTTP ${response.status}`);
        }

        const data = await response.json();
        setRepositories(data.repositories);
        setFilteredRepos(data.repositories);
      } catch (error) {
        console.error('Erreur lors du chargement des dépôts:', error);
        setError('Impossible de charger les dépôts. Veuillez réessayer.');
      } finally {
        setLoading(false);
      }
    }

    fetchRepositories();
  }, [token]);

  // Vérifier la disponibilité d'Ollama et récupérer les modèles
  useEffect(() => {
    async function checkOllama() {
      try {
        const response = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/ollama/models`);
        
        if (response.ok) {
          const data = await response.json();
          setOllamaModels(data.models);
          setIsOllamaAvailable(data.models && data.models.length > 0);
        } else {
          setIsOllamaAvailable(false);
        }
      } catch (error) {
        console.error('Erreur lors de la vérification d\'Ollama:', error);
        setIsOllamaAvailable(false);
      }
    }

    checkOllama();
  }, []);

  // Filtrer et trier les dépôts
  useEffect(() => {
    let filtered = [...repositories];
    
    // Filtrer par terme de recherche
    if (searchTerm) {
      filtered = filtered.filter(repo => 
        repo.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (repo.description && repo.description.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }
    
    // Trier les dépôts
    filtered.sort((a, b) => {
      let valueA = a[sortBy];
      let valueB = b[sortBy];
      
      // Gestion des dates
      if (sortBy === 'created_at' || sortBy === 'updated_at' || sortBy === 'pushed_at') {
        valueA = new Date(valueA);
        valueB = new Date(valueB);
      }
      
      // Gestion des chaînes
      if (typeof valueA === 'string' && typeof valueB === 'string') {
        return sortDirection === 'asc' 
          ? valueA.localeCompare(valueB)
          : valueB.localeCompare(valueA);
      }
      
      // Gestion des nombres et dates
      return sortDirection === 'asc' ? valueA - valueB : valueB - valueA;
    });
    
    setFilteredRepos(filtered);
  }, [repositories, searchTerm, sortBy, sortDirection]);

  // Gérer le changement de tri
  const handleSort = (column) => {
    if (sortBy === column) {
      // Inverser la direction si on clique sur la même colonne
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      // Nouvelle colonne, définir le tri par défaut
      setSortBy(column);
      setSortDirection('desc');
    }
  };

  // Formater la date
  const formatDate = (dateString) => {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString('fr-FR', options);
  };

  // Démarrer l'analyse d'un dépôt
  const startAnalysis = (repoName) => {
    navigate(`/analysis/${encodeURIComponent(repoName)}`);
  };

  // Afficher l'état de chargement
  if (loading) {
    return (
      <div className="repositories-loading">
        <div className="spinner"></div>
        <p>Chargement des dépôts...</p>
      </div>
    );
  }

  return (
    <div className="repositories-container">
      <h1>Vos Dépôts GitHub</h1>
      
      {!isOllamaAvailable && (
        <div className="ollama-warning">
          <h3>⚠️ Ollama n'est pas disponible</h3>
          <p>
            Pour analyser vos dépôts, assurez-vous qu'Ollama est installé et en cours d'exécution sur votre machine.
            Aucun modèle n'a été détecté.
          </p>
          <a href="https://ollama.ai" target="_blank" rel="noopener noreferrer">
            Télécharger Ollama
          </a>
        </div>
      )}
      
      {isOllamaAvailable && (
        <div className="ollama-info">
          <h3>✅ Ollama est disponible</h3>
          <p>Modèles détectés ({ollamaModels.length}): {ollamaModels.join(', ')}</p>
        </div>
      )}

      <div className="repositories-controls">
        <div className="search-container">
          <input
            type="text"
            placeholder="Rechercher un dépôt..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>
        
        <div className="sort-info">
          <span>Tri actuel: </span>
          <span className="sort-field">{sortBy}</span>
          <span className="sort-direction">{sortDirection === 'asc' ? '↑' : '↓'}</span>
        </div>
      </div>

      {error && <div className="error-message">{error}</div>}

      {filteredRepos.length === 0 ? (
        <div className="no-repositories">
          <p>Aucun dépôt trouvé.</p>
        </div>
      ) : (
        <div className="repositories-table-container">
          <table className="repositories-table">
            <thead>
              <tr>
                <th onClick={() => handleSort('name')}>Nom {sortBy === 'name' && (sortDirection === 'asc' ? '↑' : '↓')}</th>
                <th>Description</th>
                <th onClick={() => handleSort('language')}>Langage {sortBy === 'language' && (sortDirection === 'asc' ? '↑' : '↓')}</th>
                <th onClick={() => handleSort('stargazers_count')}>Étoiles {sortBy === 'stargazers_count' && (sortDirection === 'asc' ? '↑' : '↓')}</th>
                <th onClick={() => handleSort('created_at')}>Créé le {sortBy === 'created_at' && (sortDirection === 'asc' ? '↑' : '↓')}</th>
                <th onClick={() => handleSort('updated_at')}>Mis à jour le {sortBy === 'updated_at' && (sortDirection === 'asc' ? '↑' : '↓')}</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredRepos.map((repo) => (
                <tr key={repo.id}>
                  <td>
                    <a href={repo.html_url} target="_blank" rel="noopener noreferrer">
                      {repo.name}
                    </a>
                  </td>
                  <td className="description">{repo.description || 'Pas de description'}</td>
                  <td>{repo.language || 'N/A'}</td>
                  <td className="center">{repo.stargazers_count}</td>
                  <td>{formatDate(repo.created_at)}</td>
                  <td>{formatDate(repo.updated_at)}</td>
                  <td>
                    <button
                      className="analyze-button"
                      onClick={() => startAnalysis(repo.full_name)}
                      disabled={!isOllamaAvailable}
                    >
                      Analyser
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default Repositories;