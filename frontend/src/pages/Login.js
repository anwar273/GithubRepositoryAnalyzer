import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './Login.css';

function Login() {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    // Rediriger vers la page des dépôts si déjà authentifié
    if (isAuthenticated) {
      navigate('/repositories');
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!token.trim()) {
      setError('Veuillez entrer un token GitHub');
      return;
    }

    setLoading(true);
    setError('');

    try {
      await login(token);
      navigate('/repositories');
    } catch (error) {
      setError(error.message || 'Échec de l\'authentification. Vérifiez votre token GitHub.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h1>Analyseur de Vulnérabilités GitHub</h1>
        <p className="login-description">
          Analysez vos dépôts GitHub pour détecter les vulnérabilités de sécurité et les mauvaises pratiques
          en utilisant l'intelligence artificielle.
        </p>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="github-token">Token d'accès GitHub</label>
            <input
              type="password"
              id="github-token"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="ghp_votre_token_personnel"
              disabled={loading}
            />
            <p className="help-text">
              Pour créer un token, allez dans Paramètres &gt; Paramètres Développeur &gt; Tokens d'accès personnel dans GitHub.
              Assurez-vous d'activer la portée "repo" pour accéder à vos dépôts.
            </p>
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" className="login-button" disabled={loading}>
            {loading ? 'Connexion en cours...' : 'Se connecter'}
          </button>
        </form>

        <div className="login-features">
          <h2>Fonctionnalités</h2>
          <ul>
            <li>Analyse de code avec des modèles d'IA locaux via Ollama</li>
            <li>Détection de vulnérabilités, de mauvaises pratiques et de code smells</li>
            <li>Rapports détaillés avec graphiques et visualisations</li>
            <li>Recommandations pour corriger les problèmes identifiés</li>
            <li>Export de rapports au format PDF</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default Login;