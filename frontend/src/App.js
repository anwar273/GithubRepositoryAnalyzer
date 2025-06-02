import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';
import Login from './pages/Login';
import Repositories from './pages/Repositories';
import Analysis from './pages/Analysis';
import NavBar from './components/NavBar';
import { AuthProvider } from './context/AuthContext';

function App() {
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    // Vérifier si le serveur backend est accessible
    fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/health`)
      .then(response => response.json())
      .then(data => {
        console.log('Serveur backend accessible:', data);
        setInitialized(true);
      })
      .catch(error => {
        console.error('Erreur de connexion au serveur backend:', error);
        setInitialized(true); // Initialisation quand même pour afficher les erreurs dans l'UI
      });
  }, []);

  if (!initialized) {
    return (
      <div className="app-loading">
        <div className="spinner"></div>
        <p>Initialisation de l'application...</p>
      </div>
    );
  }

  return (
    <AuthProvider>
      <Router>
        <div className="app">
          <NavBar />
          <main className="app-content">
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/repositories" element={<Repositories />} />
              <Route path="/analysis/:repoName" element={<Analysis />} />
              <Route path="/" element={<Navigate to="/login" replace />} />
            </Routes>
          </main>
          <footer className="app-footer">
            <p>© 2025 Analyseur de Vulnérabilités GitHub</p>
          </footer>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;