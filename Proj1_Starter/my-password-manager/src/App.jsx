import React, { useState, useEffect } from 'react';
import { Keychain } from '../utils/password-manager';

export default function App() {
  const [keychain, setKeychain] = useState(null);
  const [masterPassword, setMasterPassword] = useState('');
  const [isDbExists, setIsDbExists] = useState(false);
  const [status, setStatus] = useState('');

  // Check if DB has data on load
  useEffect(() => {
    fetch('http://localhost:3001/keychain')
      .then(r => r.json())
      .then(data => setIsDbExists(data.exists));
  }, []);

  const handleLogin = async () => {
    try {
      if (isDbExists) {
        const res = await fetch('http://localhost:3001/keychain');
        const { repr, checksum } = await res.json();
        // Load triggers integrity check and password verification
        const loadedKeychain = await Keychain.load(masterPassword, repr, checksum);
        setKeychain(loadedKeychain);
      } else {
        // Initialize new keychain if none exists
        const newKeychain = await Keychain.init(masterPassword);
        setKeychain(newKeychain);
      }
      setStatus('Keychain loaded successfully');
    } catch (e) {
      setStatus(`Error: ${e.message}`);
    }
  };

  const handleSave = async () => {
    if (!keychain) return;
    const [repr, checksum] = await keychain.dump(); // Generates serialization + SHA-256 hash
    await fetch('http://localhost:3001/keychain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repr, checksum })
    });
    setStatus('Saved encrypted database to server.');
  };

  if (!keychain) {
    return (
      <div className="p-10 max-w-md mx-auto">
        <h1 className="text-2xl mb-4">Secure Password Manager</h1>
        <input 
          type="password" 
          placeholder="Master Password" 
          className="border p-2 w-full mb-4"
          value={masterPassword} 
          onChange={e => setMasterPassword(e.target.value)} 
        />
        <button onClick={handleLogin} className="bg-blue-500 text-white p-2 w-full rounded">
          {isDbExists ? "Load Keychain" : "Initialize New Keychain"}
        </button>
        <p className="text-red-500 mt-2">{status}</p>
      </div>
    );
  }

  return (
    <div className="p-10">
      <div className="flex justify-between mb-6">
        <h1 className="text-2xl">My Passwords</h1>
        <button onClick={handleSave} className="bg-green-500 text-white px-4 py-2 rounded">
          Sync to Database
        </button>
      </div>
      <PasswordList keychain={keychain} />
    </div>
  );
}

function PasswordList({ keychain }) {
  const [domain, setDomain] = useState('');
  const [password, setPassword] = useState('');
  const [viewing, setViewing] = useState({});
  const [items, setItems] = useState(Object.keys(keychain.data.kvs)); // Direct access to keys

  const addPassword = async () => {
    await keychain.set(domain, password); // Encrypts and sets IV/Ciphertext
    setItems(Object.keys(keychain.data.kvs)); // Refresh list
    setDomain('');
    setPassword('');
  };

  const revealPassword = async (encodedDomain) => {
    // We need the original domain string to query 'get'. 
    // Since KVS keys are HMAC hashed, we can't reverse them easily to show the name.
    // Note: A real production app would store a plaintext domain map or store the domain encrypted separately.
    // For this specific repo, you might have to prompt the user for the domain name to retrieve it, 
    // OR store the domain inside the encrypted value.
    
    alert("Due to security design (HMAC keys), you must know the domain name to retrieve the password.");
  };
  
  // Improved retrieval for Demo purposes:
  // Use a local mapping or assume the user types the domain to 'get' it.
  const handleGet = async () => {
      try {
        const pass = await keychain.get(domain);
        alert(`Password for ${domain}: ${pass}`);
      } catch(e) {
        alert("Not found or integrity error");
      }
  }

  return (
    <div>
      <div className="mb-6 p-4 bg-gray-100 rounded">
        <h3 className="font-bold mb-2">Add / Retrieve</h3>
        <input 
            className="border p-2 mr-2" 
            placeholder="Domain (e.g. google.com)" 
            value={domain} 
            onChange={e => setDomain(e.target.value)} 
        />
        <input 
            className="border p-2 mr-2" 
            type="password" 
            placeholder="Password" 
            value={password} 
            onChange={e => setPassword(e.target.value)} 
        />
        <button onClick={addPassword} className="bg-blue-500 text-white px-4 py-2 rounded mr-2">Add</button>
        <button onClick={handleGet} className="bg-gray-500 text-white px-4 py-2 rounded">Retrieve</button>
      </div>

      <h3 className="font-bold">Stored Records (HMAC of Domains)</h3>
      <ul>
        {items.map(k => <li key={k} className="border-b p-2 font-mono text-sm">{k}</li>)}
      </ul>
    </div>
  );
}