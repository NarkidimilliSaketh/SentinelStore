import React, { useState, useEffect, useMemo } from 'react';
import FileDetailsModal from './FileDetailsModal';
import {
  //initializeModules,
  //deriveKeyFromPassword,
  generateSymmetricKey,
  encryptSymmetric,
  decryptSymmetric,
  encryptAsymmetric,
  decryptAsymmetric,
  createShares,
  combineShares,
  hashData,
  uint8ArrayToBase64,
  base64ToUint8Array
} from '../crypto';

const P2P_NODE_URLS = (import.meta.env.VITE_P2P_NODE_URLS || 'http://localhost:8001,http://localhost:8002,http://localhost:8003').split(',');
const METADATA_API_URL = 'http://localhost:8000';

function getRandomNodeUrl(): string {
  return P2P_NODE_URLS[Math.floor(Math.random() * P2P_NODE_URLS.length)];
}

type ImportanceLevel = 'Normal' | 'Important' | 'Critical';

function getShamirParams(importance: ImportanceLevel): { n: number; k: number } {
  switch (importance) {
    case 'Normal': return { n: 5, k: 3 };
    case 'Important': return { n: 7, k: 5 };
    case 'Critical': return { n: 10, k: 7 };
  }
}

type SortKey = 'filename' | 'createdAt';
type SortDirection = 'ascending' | 'descending';

interface DashboardProps {
  token: string;
  username: string;
  keys: { publicKey: Uint8Array; secretKey: Uint8Array };
  onLogout: () => void;
}

export default function Dashboard({ token, username, keys, onLogout }: DashboardProps) {
  const [filesToUpload, setFilesToUpload] = useState<FileList | null>(null);
  const [importance, setImportance] = useState<ImportanceLevel>('Normal');
  const [isProcessing, setIsProcessing] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [myFiles, setMyFiles] = useState<any[]>([]);
  const [sharedFiles, setSharedFiles] = useState<any[]>([]);
  const [selectedFileDetails, setSelectedFileDetails] = useState<any>(null);
  const [isDetailsModalOpen, setIsDetailsModalOpen] = useState(false);
  const [nodeHealth, setNodeHealth] = useState<any[]>([]);
  const [selectedFileIds, setSelectedFileIds] = useState<Set<string>>(new Set());
  const [myFilesSearch, setMyFilesSearch] = useState('');
  const [sharedFilesSearch, setSharedFilesSearch] = useState('');
  const [sortConfig, setSortConfig] = useState<{ key: SortKey; direction: SortDirection }>({ key: 'createdAt', direction: 'descending' });

  const log = (message: string) => setLogs(prev => [`[${new Date().toLocaleTimeString()}] ${message}`, ...prev]);

  const fetchUserFiles = async () => {
    try {
      const response = await fetch(`${METADATA_API_URL}/files`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!response.ok) throw new Error('Failed to fetch files.');
      const files = await response.json();
      setMyFiles(files);
    } catch (error) {
      console.error(`Error fetching files: ${error}`);
    }
  };

  const fetchSharedFiles = async () => {
    try {
      const response = await fetch(`${METADATA_API_URL}/files/shared-with-me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!response.ok) throw new Error('Failed to fetch shared files.');
      const files = await response.json();
      setSharedFiles(files);
    } catch (error) {
      console.error(`Error fetching shared files: ${error}`);
    }
  };

  useEffect(() => {
    log("✅ Session ready. Fetching files...");
    fetchUserFiles();
    fetchSharedFiles();
  }, [token]);

  useEffect(() => {
    const fetchNodeHealth = async () => {
      const healthPromises = P2P_NODE_URLS.map((url: string) =>
        fetch(`${url}/health`)
          .then(res => res.ok ? res.json() : { status: 'offline', public_url: url })
          .catch(() => ({ status: 'offline', public_url: url }))
      );
      const healthResults = await Promise.all(healthPromises);
      setNodeHealth(healthResults);
    };

    fetchNodeHealth();
    const intervalId = setInterval(fetchNodeHealth, 5000);
    return () => clearInterval(intervalId);
  }, []);

  const handleMultiUpload = async () => {
    if (!filesToUpload || !keys) return;
    const password = prompt(`Please enter your account password to encrypt and upload ${filesToUpload.length} file(s):`);
    if (!password) return;

    setIsProcessing(true);
    setLogs([]);
    log(`Starting bulk upload of ${filesToUpload.length} file(s)...`);
    
    for (let i = 0; i < filesToUpload.length; i++) {
      const file = filesToUpload[i];
      log(`\n--- Uploading file ${i + 1} of ${filesToUpload.length}: "${file.name}" ---`);
      try {
        log('1. Generating file key...');
        const fileKey = generateSymmetricKey();
        
        log('2. Encrypting file...');
        const fileBuffer = await file.arrayBuffer();
        const fileData = new Uint8Array(fileBuffer);
        const { ciphertext, nonce } = encryptSymmetric(fileData, fileKey);

        const { n, k } = getShamirParams(importance);
        log(`3. Applying Shamir's Sharing (n=${n}, k=${k})...`);
        const allShares = createShares(ciphertext, n, k);

        log('4. Uploading shares to P2P network...');
        const shareHashes: string[] = [];
        for (const share of allShares) {
          const hash = await hashData(share);
          shareHashes.push(hash);
          const nodeUrl = getRandomNodeUrl();
          await fetch(`${nodeUrl}/p2p/store`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: hash, value: uint8ArrayToBase64(share) })
          });
        }

        log('5. Encrypting file key for owner...');
        const encryptedFileKey = encryptAsymmetric(fileKey, keys.publicKey);

        log('6. Creating and uploading manifest...');
        const manifest = { name: file.name, type: file.type, erasure: { n, k }, shards: shareHashes, crypto: { nonce: uint8ArrayToBase64(nonce) } };
        const manifestData = new TextEncoder().encode(JSON.stringify(manifest));
        const finalRootHash = await hashData(manifestData);
        const nodeUrl = getRandomNodeUrl();
        await fetch(`${nodeUrl}/p2p/store`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: finalRootHash, value: uint8ArrayToBase64(manifestData) })
        });

        log('7. Saving file metadata...');
        await fetch(`${METADATA_API_URL}/files`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body: JSON.stringify({
            filename: file.name,
            root_hash: finalRootHash,
            encrypted_file_key: uint8ArrayToBase64(encryptedFileKey),
            erasure: { n, k }
          })
        });
        log(`✅ Successfully uploaded "${file.name}".`);
      } catch (error) {
        log(`❌ An error occurred while uploading "${file.name}": ${error}`);
        break; 
      }
    }
    log(`\n🎉 BULK UPLOAD COMPLETE!`);
    fetchUserFiles();
    setIsProcessing(false);
  };

  const handleMultiDownload = async () => {
    if (selectedFileIds.size === 0 || !keys) return;
    
    setIsProcessing(true);
    setLogs([]);
    log(`Starting bulk download of ${selectedFileIds.size} file(s)...`);
    
    const selectedFiles = myFiles.filter(f => selectedFileIds.has(f._id));

    for (let i = 0; i < selectedFiles.length; i++) {
      const file = selectedFiles[i];
      log(`\n--- Downloading file ${i + 1} of ${selectedFiles.length}: "${file.filename}" ---`);
      try {
        const fileId = file._id;
        log("1. Verifying permission and fetching access key...");
        const keyRes = await fetch(`${METADATA_API_URL}/files/${fileId}/access-key`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!keyRes.ok) {
          const errData = await keyRes.json();
          throw new Error(errData.detail || "Permission check failed.");
        }
        const keyData = await keyRes.json();
        const encryptedFileKey = base64ToUint8Array(keyData.encrypted_file_key);
        log("✅ Permission verified.");

        log("2. Decrypting File Key...");
        const fileKey = decryptAsymmetric(encryptedFileKey, keys.secretKey);
        if (!fileKey) throw new Error("Failed to decrypt file key.");
        log('✅ File key decrypted.');

        log("3. Fetching manifest...");
        const res = await fetch(`${getRandomNodeUrl()}/p2p/get/${file.root_hash}`);
        if (!res.ok) throw new Error('Manifest not found.');
        const json = await res.json();
        const manifestData = JSON.parse(new TextDecoder().decode(base64ToUint8Array(json.value)));
        log('✅ Manifest retrieved.');

        const { k } = manifestData.erasure;
        log(`4. Fetching shares (need at least ${k})...`);
        const promises = manifestData.shards.map((hash: string) => 
          fetch(`${getRandomNodeUrl()}/p2p/get/${hash}`).then(res => res.ok ? res.json() : null)
        );
        const results = await Promise.all(promises);
        const retrievedShares = results.filter(Boolean).map((json: any) => base64ToUint8Array(json.value));

        if (retrievedShares.length < k) throw new Error(`Failed to retrieve enough shares. Needed ${k}, got ${retrievedShares.length}.`);
        log(`✅ Retrieved ${retrievedShares.length} shares.`);

        log('5. Reconstructing and decrypting file...');
        const ciphertext = combineShares(retrievedShares.slice(0, k));
        const nonce = base64ToUint8Array(manifestData.crypto.nonce);
        const plaintext = decryptSymmetric(ciphertext, nonce, fileKey);
        if (!plaintext) throw new Error('DECRYPTION FAILED.');
        log('✅ Decryption successful!');

        log('6. Triggering download...');
        const blob = new Blob([plaintext as BlobPart], { type: manifestData.type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = manifestData.name;
        a.click();
        URL.revokeObjectURL(url);
        log(`✅ Successfully downloaded "${file.filename}".`);

      } catch (error: any) {
        log(`❌ Download Error for "${file.filename}": ${error.message}`);
        break;
      }
    }
    log(`\n🎉 BULK DOWNLOAD COMPLETE!`);
    setSelectedFileIds(new Set());
    setIsProcessing(false);
  };
  // --- RESTORED: Single-file download logic ---
  const handleDownload = async (file: any) => {
    if (!keys) return;
    setIsProcessing(true);
    setLogs([]);
    log(`Starting download for ${file.filename}...`);
    try {
      const fileId = file._id || file.file_id;
      if (!fileId) throw new Error("File ID is missing.");

      log("1. Verifying permission and fetching access key...");
      const keyRes = await fetch(`${METADATA_API_URL}/files/${fileId}/access-key`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!keyRes.ok) {
        const errData = await keyRes.json();
        throw new Error(errData.detail || "Permission check failed.");
      }
      const keyData = await keyRes.json();
      const encryptedFileKey = base64ToUint8Array(keyData.encrypted_file_key);
      log("✅ Permission verified and key received.");

      log(`\n2. Decrypting File Key...`);
      const fileKey = decryptAsymmetric(encryptedFileKey, keys.secretKey);
      if (!fileKey) throw new Error("Failed to decrypt file key.");
      log('✅ File key decrypted.');

      log(`\n3. Fetching manifest...`);
      const nodeUrl = getRandomNodeUrl();
      const res = await fetch(`${nodeUrl}/p2p/get/${file.root_hash}`);
      if (!res.ok) throw new Error('Manifest not found on P2P network.');
      const json = await res.json();
      const manifestData = JSON.parse(new TextDecoder().decode(base64ToUint8Array(json.value)));
      log('✅ Manifest retrieved.');

      const { k } = manifestData.erasure;
      log(`\n4. Fetching shares (need at least ${k})...`);
      const promises = manifestData.shards.map((hash: string) => 
        fetch(`${getRandomNodeUrl()}/p2p/get/${hash}`).then(res => res.ok ? res.json() : null)
      );
      const results = await Promise.all(promises);
      const retrievedShares = results.filter(Boolean).map((json: any) => base64ToUint8Array(json.value));

      if (retrievedShares.length < k) throw new Error(`Failed to retrieve enough shares. Needed ${k}, got ${retrievedShares.length}.`);
      log(`✅ Retrieved ${retrievedShares.length} shares.`);

      log('\n5. Reconstructing and decrypting file...');
      const ciphertext = combineShares(retrievedShares.slice(0, k));
      const nonce = base64ToUint8Array(manifestData.crypto.nonce);
      const plaintext = decryptSymmetric(ciphertext, nonce, fileKey);
      if (!plaintext) throw new Error('DECRYPTION FAILED. Data may be corrupt.');
      log('✅ Decryption successful!');

      log('\n6. Triggering download...');
      const blob = new Blob([plaintext as BlobPart], { type: manifestData.type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = manifestData.name;
      a.click();
      URL.revokeObjectURL(url);
      log('🎉 DOWNLOAD COMPLETE!');

      await fetch(`${METADATA_API_URL}/logs/record`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          action: "DOWNLOAD_FILE",
          file_id: fileId,
          filename: file.filename
        })
      });

    } catch (error: any) {
      log(`❌ Download Error: ${error.message}`);
      alert(`Download Error: ${error.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleMultiShare = async () => {
    if (selectedFileIds.size === 0 || !keys) return;
    const recipientUsernamesRaw = prompt(`Enter usernames to share ${selectedFileIds.size} file(s) with, separated by commas (e.g., bob, charlie):`);
    if (!recipientUsernamesRaw) return;

    const recipientUsernames = recipientUsernamesRaw.split(',').map(u => u.trim()).filter(Boolean);
    if (recipientUsernames.length === 0) return;

    setIsProcessing(true);
    setLogs([]);
    log(`Starting bulk share to ${recipientUsernames.join(', ')}...`);
    try {
      log("1. Fetching recipient public keys...");
      const pubKeysRes = await fetch(`${METADATA_API_URL}/users/public-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ usernames: recipientUsernames })
      });
      if (!pubKeysRes.ok) throw new Error("Could not fetch recipient public keys.");
      const recipients: {username: string, public_key: string}[] = await pubKeysRes.json();
      
      const foundUsernames = new Set(recipients.map(r => r.username));
      const notFoundUsernames = recipientUsernames.filter(u => !foundUsernames.has(u));
      if (notFoundUsernames.length > 0) {
        log(`⚠️ Warning: The following users were not found and will be skipped: ${notFoundUsernames.join(', ')}`);
      }
      log(`✅ Found public keys for ${recipients.length} user(s).`);

      const selectedFiles = myFiles.filter(f => selectedFileIds.has(f._id));
      for (const file of selectedFiles) {
        log(`\n--- Sharing file: "${file.filename}" ---`);
        
        log("  - Decrypting file key with your private key...");
        const encryptedFileKey = base64ToUint8Array(file.encrypted_file_key);
        const fileKey = decryptAsymmetric(encryptedFileKey, keys.secretKey);
        if (!fileKey) {
          log("  - ❌ Could not decrypt the file key. Skipping.");
          continue;
        }
        log("  - ✅ File key decrypted.");

        for (const recipient of recipients) {
          log(`  - Re-encrypting file key for ${recipient.username}...`);
          const recipientPublicKey = base64ToUint8Array(recipient.public_key);
          const encryptedKeyForRecipient = encryptAsymmetric(fileKey, recipientPublicKey);
          
          log(`  - Granting access to ${recipient.username} via API...`);
          const shareRes = await fetch(`${METADATA_API_URL}/files/${file._id}/share`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({
              share_with_username: recipient.username,
              encrypted_file_key_for_recipient: uint8ArrayToBase64(encryptedKeyForRecipient)
            })
          });
          if (shareRes.ok) {
            log(`    ✅ Successfully shared with ${recipient.username}.`);
          } else {
            const errData = await shareRes.json();
            log(`    ❌ Failed to share with ${recipient.username}: ${errData.detail}`);
          }
        }
      }
      log(`\n🎉 BULK SHARE COMPLETE!`);
    } catch (error: any) {
      log(`❌ An error occurred during bulk share: ${error.message}`);
    } finally {
      setSelectedFileIds(new Set());
      setIsProcessing(false);
    }
  };

  const handleMultiDelete = async () => {
    if (selectedFileIds.size === 0) return;
    const password = prompt(`To confirm deletion of ${selectedFileIds.size} file(s), please enter your account password:`);
    if (!password) {
      log("Deletion cancelled.");
      return;
    }
    
    setIsProcessing(true);
    setLogs([]);
    log(`Attempting to delete ${selectedFileIds.size} file(s)...`);
    try {
      const response = await fetch(`${METADATA_API_URL}/files/delete-bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ 
          file_ids: Array.from(selectedFileIds),
          password: password 
        })
      });

      if (response.status === 401) {
        const errData = await response.json();
        throw new Error(errData.detail || 'Incorrect password.');
      }
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || 'Failed to delete files.');
      }
      
      log(`✅ ${selectedFileIds.size} file entries deleted successfully.`);
      fetchUserFiles();
      setSelectedFileIds(new Set());
    } catch (error: any) {
      log(`❌ Error deleting files: ${error.message}`);
      alert(`Error: ${error.message}`);
    } finally {
      setIsProcessing(false);
    }
  };
  
    // --- CORRECTED: Single-file unshare logic ---
  const handleUnshare = async (usernameToUnshare: string) => {
    if (!selectedFileDetails) return;
    log(`Attempting to unshare "${selectedFileDetails.filename}" from ${usernameToUnshare}...`);
    try {
      const response = await fetch(`${METADATA_API_URL}/files/${selectedFileDetails._id}/unshare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ username: usernameToUnshare })
      });
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || "Failed to unshare file.");
      }
      alert(`Successfully unshared with ${usernameToUnshare}`);
      log(`✅ Successfully unshared "${selectedFileDetails.filename}" from ${usernameToUnshare}.`);
      // Refresh the details modal to show the change
      handleDetails(selectedFileDetails._id);
    } catch (error: any) {
      log(`❌ Error unsharing file: ${error.message}`);
      alert(`Error: ${error.message}`);
    }
  };

  // --- CORRECTED: Multi-unshare logic ---
const handleMultiUnshare = async () => {
  if (selectedFileIds.size === 0) return;
  const usernameToUnshare = prompt(`Enter the username to unshare ${selectedFileIds.size} file(s) from:`);
  if (!usernameToUnshare) return;

  setIsProcessing(true);
  setLogs([]);
  log(`Attempting to unshare ${selectedFileIds.size} file(s) from ${usernameToUnshare}...`);
  try {
    // Call the correct bulk endpoint
    const response = await fetch(`${METADATA_API_URL}/files/unshare-bulk`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ 
        file_ids: Array.from(selectedFileIds),
        username: usernameToUnshare 
      })
    });
    if (!response.ok) {
      const errData = await response.json();
      throw new Error(errData.detail || 'Failed to unshare files.');
    }
    log(`✅ Successfully unshared files from ${usernameToUnshare}.`);
    alert(`Successfully unshared files from ${usernameToUnshare}.`);
    // We don't need to refresh file lists here, as the ownership hasn't changed, only permissions
    // which are visible in the details modal.
  } catch (error: any) {
    log(`❌ Error unsharing files: ${error.message}`);
    alert(`Error: ${error.message}`);
  } finally {
    setSelectedFileIds(new Set());
    setIsProcessing(false);
  }
};

  const handleDetails = async (fileId: string) => {
    setIsProcessing(true);
    try {
      const response = await fetch(`${METADATA_API_URL}/files/${fileId}/details`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!response.ok) throw new Error("Failed to fetch file details.");
      const details = await response.json();
      setSelectedFileDetails(details);
      setIsDetailsModalOpen(true);
    } catch (error: any) {
      alert(`Error: ${error.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  
  const handleFileSelect = (fileId: string) => {
    setSelectedFileIds(prevSelected => {
      const newSelected = new Set(prevSelected);
      if (newSelected.has(fileId)) {
        newSelected.delete(fileId);
      } else {
        newSelected.add(fileId);
      }
      return newSelected;
    });
  };

  const sortedAndFilteredMyFiles = useMemo(() => {
    return myFiles
      .filter(f => f.filename.toLowerCase().includes(myFilesSearch.toLowerCase()))
      .sort((a, b) => {
        if (sortConfig.key === 'createdAt') {
          const dateA = new Date(a.createdAt).getTime();
          const dateB = new Date(b.createdAt).getTime();
          return sortConfig.direction === 'ascending' ? dateA - dateB : dateB - dateA;
        }
        if (a[sortConfig.key] < b[sortConfig.key]) {
          return sortConfig.direction === 'ascending' ? -1 : 1;
        }
        if (a[sortConfig.key] > b[sortConfig.key]) {
          return sortConfig.direction === 'ascending' ? 1 : -1;
        }
        return 0;
      });
  }, [myFiles, myFilesSearch, sortConfig]);

  const filteredSharedFiles = sharedFiles.filter(f => 
    f.filename.toLowerCase().includes(sharedFilesSearch.toLowerCase()) ||
    f.owner.toLowerCase().includes(sharedFilesSearch.toLowerCase())
  );

  const isAllSelected = sortedAndFilteredMyFiles.length > 0 && selectedFileIds.size === sortedAndFilteredMyFiles.length;

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      const allFileIds = new Set(sortedAndFilteredMyFiles.map(f => f._id));
      setSelectedFileIds(allFileIds);
    } else {
      setSelectedFileIds(new Set());
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Welcome, {username}</h1>
        <button onClick={onLogout} style={{backgroundColor: '#444'}}>Logout</button>
      </div>
      
      <div className="card">
        <h2>P2P Network Status</h2>
        <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem'}}>
          {nodeHealth.map((node, index) => (
            <div key={index} className="card" style={{margin: 0, backgroundColor: '#1a1a1a'}}>
              <strong>Node URL:</strong> {node.public_url} <br/>
              <strong>Status:</strong> 
              <span style={{color: node.status === 'ok' ? '#4ade80' : '#f87171', fontWeight: 'bold'}}>
                {node.status === 'ok' ? ' Online' : ' Offline'}
              </span> <br/>
              {node.status === 'ok' && (
                <>
                  <strong>Connected Peers:</strong> {node.known_peers} <br/>
                  <strong>Stored Shares:</strong> {node.stored_shards_count}
                </>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h2>Upload Files</h2>
        <div className="input-group">
          <input type="file" multiple onChange={(e) => setFilesToUpload(e.target.files)} />
        </div>
        <div className="input-group">
          <label>Importance Level for this batch</label>
          <div className="radio-group">
            {(['Normal', 'Important', 'Critical'] as ImportanceLevel[]).map(level => (
              <label key={level}>
                <input type="radio" name="importance" value={level} checked={importance === level} onChange={() => setImportance(level)} /> {level}
              </label>
            ))}
          </div>
        </div>
        <button onClick={handleMultiUpload} disabled={isProcessing || !filesToUpload}>{isProcessing ? 'Processing...' : 'Upload File(s)'}</button>
      </div>

      <div className="card">
        <h2>My Files</h2>
        <div style={{display: 'flex', justifyContent: 'space-between', gap: '1rem', marginBottom: '1rem'}}>
          <input 
            type="text" 
            placeholder="Filter by name..." 
            value={myFilesSearch}
            onChange={(e) => setMyFilesSearch(e.target.value)}
            style={{flexGrow: 1}}
          />
          <select 
            value={`${sortConfig.key}-${sortConfig.direction}`} 
            onChange={(e) => {
              const [key, direction] = e.target.value.split('-') as [SortKey, SortDirection];
              setSortConfig({ key, direction });
            }}
            style={{padding: '12px', backgroundColor: '#1a1a1a', border: '1px solid #444', borderRadius: '8px', color: 'white'}}
          >
            <option value="createdAt-descending">Date (Newest)</option>
            <option value="createdAt-ascending">Date (Oldest)</option>
            <option value="filename-ascending">Name (A-Z)</option>
            <option value="filename-descending">Name (Z-A)</option>
          </select>
        </div>

        {selectedFileIds.size > 0 && (
          <div style={{ backgroundColor: '#1d4ed8', padding: '1rem', borderRadius: '8px', marginBottom: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span>{selectedFileIds.size} file(s) selected</span>
            <div>
              <button onClick={handleMultiDownload} disabled={isProcessing} style={{ marginRight: '0.5rem' }}>Download Selected</button>
              <button onClick={handleMultiShare} disabled={isProcessing} style={{ marginRight: '0.5rem', backgroundColor: '#166534' }}>Share Selected</button>
              <button onClick={handleMultiUnshare} disabled={isProcessing} style={{ marginRight: '0.5rem', backgroundColor: '#ca8a04' }}>Unshare Selected</button>
              <button onClick={handleMultiDelete} disabled={isProcessing} style={{ backgroundColor: '#b91c1c' }}>Delete Selected</button>
            </div>
          </div>
        )}
        {sortedAndFilteredMyFiles.length > 0 ? (
          <ul style={{listStyle: 'none', padding: 0}}>
            <li style={{display: 'flex', alignItems: 'center', padding: '0.5rem', borderBottom: '1px solid #555', fontWeight: 'bold'}}>
              <input type="checkbox" style={{marginRight: '1rem'}} checked={isAllSelected} onChange={handleSelectAll} />
              <span style={{flexGrow: 1}}>Filename</span>
              <span>Date Created</span>
            </li>
            {sortedAndFilteredMyFiles.map(f => (
              <li key={f._id} style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', borderBottom: '1px solid #333'}}>
                <div style={{display: 'flex', alignItems: 'center', flexGrow: 1}}>
                  <input type="checkbox" style={{marginRight: '1rem'}} checked={selectedFileIds.has(f._id)} onChange={() => handleFileSelect(f._id)} />
                  <span>{f.filename}</span>
                </div>
                <span style={{marginRight: '1rem', color: '#888', fontSize: '0.9em'}}>{new Date(f.createdAt).toLocaleDateString()}</span>
                <div>
                  <button onClick={() => handleDetails(f._id)} disabled={isProcessing} style={{backgroundColor: '#1d4ed8'}}>Details</button>
                </div>
              </li>
            ))}
          </ul>
        ) : <p>No files match your search.</p>}
      </div>

      <div className="card">
        <h2>Files Shared With Me</h2>
        <div className="input-group">
          <input 
            type="text" 
            placeholder="Search shared files by name or owner..." 
            value={sharedFilesSearch}
            onChange={(e) => setSharedFilesSearch(e.target.value)}
          />
        </div>
        {filteredSharedFiles.length > 0 ? (
          <ul style={{listStyle: 'none', padding: 0}}>
            {filteredSharedFiles.map(f => (
              <li key={f.file_id} style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', borderBottom: '1px solid #333'}}>
                <span>{f.filename} (from {f.owner})</span>
                <div>
                  <button onClick={() => handleDetails(f.file_id)} disabled={isProcessing} style={{marginRight: '0.5rem', backgroundColor: '#1d4ed8'}}>Details</button>
                  <button onClick={() => handleDownload(f)} disabled={isProcessing}>Download</button>
                </div>
              </li>
            ))}
          </ul>
        ) : <p>No shared files match your search.</p>}
      </div>

      {logs.length > 0 && 
        <div className="card">
          <h2>Activity Logs</h2>
          <div className="logs">{logs.join('\n')}</div>
        </div>
      }

      {isDetailsModalOpen && (
        <FileDetailsModal 
          fileDetails={selectedFileDetails}
          onClose={() => setIsDetailsModalOpen(false)}
          onUnshare={handleUnshare}
          isOwner={selectedFileDetails?.owner === username}
        />
      )}
    </div>
  );
}