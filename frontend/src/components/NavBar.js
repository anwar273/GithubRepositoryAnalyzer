import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import './NavBar.css';

function NavBar() {
  const { isAuthenticated, user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Ne pas afficher la barre de navigation sur la page de connexion
  if (location.pathname === '/login') {
    return null;
  }

  return (
    <nav className="navbar">
      <div className="navbar-container">
        <div className="navbar-brand">
          <Link to="/" className="navbar-logo">
            <span className="logo-icon">🔍</span>
            <span className="logo-text">Analyseur de Vulnérabilités GitHub</span>
          </Link>
        </div>

        <div className="navbar-menu">
          {isAuthenticated ? (
            <>
              <Link 
                to="/repositories" 
                className={`navbar-item ${location.pathname === '/repositories' ? 'active' : ''}`}
              >
                Dépôts
              </Link>
              
              <div className="navbar-divider"></div>
              
              <div className="navbar-user">
                {user && (
                  <div className="user-info">
                    {user.avatar_url && (
                      <img 
                        src={user.avatar_url} 
                        alt={user.login}
                        className="user-avatar" 
                      />
                    )}
                    <span className="user-name">{user.login}</span>
                  </div>
                )}
                
                <button 
                  onClick={handleLogout}
                  className="logout-button"
                >
                  Déconnexion
                </button>
              </div>
            </>
          ) : (
            <Link to="/login" className="navbar-item">Connexion</Link>
          )}
        </div>
      </div>
    </nav>
  );
}

export default NavBar;