import React, { useState } from 'react';
import { deriveKeyFromPassword, decryptSymmetric, base64ToUint8Array, generateKeyPair, encryptSymmetric, uint8ArrayToBase64 } from '../crypto';

const METADATA_API_URL = 'http://localhost:8000';

interface AuthPageProps {
  onLoginSuccess: (token: string, keys: { publicKey: Uint8Array; secretKey: Uint8Array }) => void;
}

export default function AuthPage({ onLoginSuccess }: AuthPageProps) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      alert("Username and password are required.");
      return;
    }
    setIsProcessing(true);
    setMessage('Processing...');
    
    try {
      if (isLogin) {
        // --- Login Flow (Unchanged) ---
        setMessage('Authenticating...');
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);

        const loginResponse = await fetch(`${METADATA_API_URL}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData,
        });
        const loginData = await loginResponse.json();
        if (!loginResponse.ok) throw new Error(loginData.detail || "Login failed.");
        
        const token = loginData.access_token;
        setMessage('Authentication successful. Decrypting session keys...');

        const meResponse = await fetch(`${METADATA_API_URL}/me`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const meData = await meResponse.json();
        if (!meResponse.ok) throw new Error(meData.detail || "Could not fetch user keys.");

        const salt = new Uint8Array(16).fill(1);
        const passwordKey = await deriveKeyFromPassword(password, salt);
        const [nonceB64, encryptedSkB64] = meData.encrypted_private_key.split(':');
        const decryptedSk = decryptSymmetric(base64ToUint8Array(encryptedSkB64), base64ToUint8Array(nonceB64), passwordKey);
        
        if (!decryptedSk) throw new Error("Failed to decrypt private key. Incorrect password.");

        const keys = {
          publicKey: base64ToUint8Array(meData.public_key),
          secretKey: decryptedSk
        };

        onLoginSuccess(token, keys);

      } else {
        // --- Registration Flow (Unchanged) ---
        setMessage('Generating cryptographic keys...');
        const keyPair = generateKeyPair();
        
        setMessage('Encrypting your private key with your password...');
        const salt = new Uint8Array(16).fill(1);
        const passwordKey = await deriveKeyFromPassword(password, salt);
        const { ciphertext: encryptedPrivateKey, nonce } = encryptSymmetric(keyPair.secretKey, passwordKey);

        const payload = {
          username,
          password,
          public_key: uint8ArrayToBase64(keyPair.publicKey),
          encrypted_private_key: `${uint8ArrayToBase64(nonce)}:${uint8ArrayToBase64(encryptedPrivateKey)}`
        };

        const response = await fetch(`${METADATA_API_URL}/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Registration failed.");
        
        setMessage('Registration successful! Please log in.');
        setIsLogin(true);
      }
    } catch (error: any) {
      setMessage(`Error: ${error.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="card" style={{ maxWidth: '400px', margin: '5rem auto' }}>
      <h2>{isLogin ? 'Login' : 'Register'}</h2>
      <form onSubmit={handleSubmit}>
        <div className="input-group">
          <label htmlFor="username">Username</label>
          {/* --- START OF MODIFICATION --- */}
          <input id="username" type="text" value={username} onChange={(e) => setUsername(e.target.value)} required minLength={3} />
          {/* --- END OF MODIFICATION --- */}
        </div>
        <div className="input-group">
          <label htmlFor="password">Password</label>
          {/* --- START OF MODIFICATION --- */}
          <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={6} />
          {/* --- END OF MODIFICATION --- */}
        </div>
        <button type="submit" disabled={isProcessing}>{isProcessing ? 'Processing...' : (isLogin ? 'Login' : 'Register')}</button>
      </form>
      <p style={{ marginTop: '1rem', textAlign: 'center' }}>
        {isLogin ? "Don't have an account?" : 'Already have an account?'}
        <button onClick={() => setIsLogin(!isLogin)} style={{ background: 'none', border: 'none', color: '#646cff', cursor: 'pointer', marginLeft: '0.5rem' }}>
          {isLogin ? 'Register' : 'Login'}
        </button>
      </p>
      {message && <p style={{ textAlign: 'center', fontStyle: 'italic' }}>{message}</p>}
    </div>
  );
}