// src/App.tsx

import { useState, useEffect } from 'react';
import { initializeModules } from './crypto';
import AuthPage from './components/AuthPage';
import Dashboard from './components/Dashboard';
import AdminDashboard from './components/admin/AdminDashboard'; // --- NEW IMPORT ---
import { jwtDecode } from 'jwt-decode';

interface DecodedToken {
  sub: string; // username
  exp: number;
  role: 'user' | 'admin'; // --- NEW: role is now in the token ---
}

function App() {
  const [isInitialized, setIsInitialized] = useState(false);
  const [token, setToken] = useState<string | null>(localStorage.getItem('sentinel_token'));
  const [sessionKeys, setSessionKeys] = useState<{publicKey: Uint8Array, secretKey: Uint8Array} | null>(null);
  
  // --- MODIFIED: This function now also returns the role ---
  const getSessionFromToken = (t: string | null): { username: string; role: 'user' | 'admin' } | null => {
    if (!t) return null;
    try {
      const decoded: DecodedToken = jwtDecode(t);
      if (Date.now() >= decoded.exp * 1000) {
        localStorage.removeItem('sentinel_token');
        return null;
      }
      return { username: decoded.sub, role: decoded.role || 'user' };
    } catch (error) {
      return null;
    }
  };

  const [session, setSession] = useState(getSessionFromToken(token));

  useEffect(() => {
    initializeModules()
      .then(() => setIsInitialized(true))
      .catch(console.error);
  }, []);

  const handleLoginSuccess = (newToken: string, decryptedKeys: {publicKey: Uint8Array, secretKey: Uint8Array}) => {
    localStorage.setItem('sentinel_token', newToken);
    setToken(newToken);
    setSession(getSessionFromToken(newToken));
    setSessionKeys(decryptedKeys);
  };

  const handleLogout = () => {
    localStorage.removeItem('sentinel_token');
    setToken(null);
    setSession(null);
    setSessionKeys(null);
  };

  if (!isInitialized) {
    return <div>Loading cryptographic modules...</div>;
  }

  const renderDashboard = () => {
    if (session && token && sessionKeys) {
      if (session.role === 'admin') {
        return <AdminDashboard token={token} username={session.username} onLogout={handleLogout} />;
      }
      return <Dashboard token={token} username={session.username} keys={sessionKeys} onLogout={handleLogout} />;
    }
    return <AuthPage onLoginSuccess={handleLoginSuccess} />;
  };

  return (
    <>
      {renderDashboard()}
    </>
  );
}

export default App;