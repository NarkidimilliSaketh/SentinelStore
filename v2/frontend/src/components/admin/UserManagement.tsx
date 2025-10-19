// src/components/admin/UserManagement.tsx

import React, { useState, useEffect } from 'react';
import { FaTrash, FaChevronDown, FaChevronUp, FaSyncAlt } from 'react-icons/fa';
// --- CORRECTED IMPORT PATH ---
import { getShamirParams } from '../../crypto';
import type { ImportanceLevel } from '../../crypto';

const METADATA_API_URL = 'http://localhost:8000';

interface UserManagementProps {
  token: string;
}

export default function UserManagement({ token }: UserManagementProps) {
  const [users, setUsers] = useState<any[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedUser, setExpandedUser] = useState<string | null>(null);
  const [userFiles, setUserFiles] = useState<any[]>([]);
  const [isLoadingFiles, setIsLoadingFiles] = useState(false);

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${METADATA_API_URL}/admin/users`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) setUsers(await res.json());
    } catch (error) {
      console.error("Failed to fetch users:", error);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [token]);

  const handleToggleUser = async (username: string) => {
    if (expandedUser === username) {
      setExpandedUser(null);
      setUserFiles([]);
    } else {
      setExpandedUser(username);
      setIsLoadingFiles(true);
      try {
        // --- CORRECTED: Call the new admin-specific endpoint ---
        const res = await fetch(`${METADATA_API_URL}/admin/users/${username}/files`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          setUserFiles(await res.json());
        } else {
          throw new Error("Failed to fetch user's files.");
        }
      } catch (error) {
        console.error(`Failed to fetch files for ${username}:`, error);
        setUserFiles([]); // Clear files on error
      } finally {
        setIsLoadingFiles(false);
      }
    }
  };

 const handleReShard = async (file: any) => {
    const newLevel = prompt(`Re-shard "${file.filename}" to new importance level (Normal, Important, Critical):`, "Critical");
    if (!newLevel || !['Normal', 'Important', 'Critical'].includes(newLevel as string)) {
      alert("Invalid level.");
      return;
    }
    
    // --- CORRECTED: Prompt for the password instead of hardcoding it ---
    const ownerPassword = prompt(`CRITICAL ACTION: Enter the password for user "${file.owner}" to proceed with re-sharding.`);
    if (!ownerPassword) {
      alert("Password not provided. Re-sharding cancelled.");
      return;
    }
    
    const params = getShamirParams(newLevel as ImportanceLevel);
    
    try {
      const res = await fetch(`${METADATA_API_URL}/admin/files/${file._id}/re-shard`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ ...params, owner_password: ownerPassword })
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail);
      }
      alert("File re-sharding initiated successfully. Check server logs for progress.");
      // Refresh the files for the user to see the change
      // Note: We need to re-toggle to trigger the fetch
      await handleToggleUser(file.owner); // Close it
      await handleToggleUser(file.owner); // And re-open it to refresh
    } catch (error) {
      alert(`Error: ${error}`);
    }
  };

  const handleDelete = async (username: string) => {
    if (!confirm(`Are you sure you want to delete the user "${username}"? This will also delete all of their files.`)) return;
    
    try {
      const res = await fetch(`${METADATA_API_URL}/admin/users/${username}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        alert(`User "${username}" deleted successfully.`);
        fetchUsers();
      } else {
        const err = await res.json();
        throw new Error(err.detail || "Failed to delete user.");
      }
    } catch (error) {
      alert(`Error: ${error}`);
    }
  };

  const filteredUsers = users.filter(u => 
    u.username.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="card">
      <h2>👥 User Management</h2>
      <div className="input-group">
        <input 
          type="text" 
          placeholder="Search users..." 
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
      </div>
      <ul style={{ listStyle: 'none', padding: 0 }}>
        {filteredUsers.map(user => (
          <React.Fragment key={user._id}>
            <li style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', borderBottom: '1px solid #333' }}>
              <div style={{display: 'flex', alignItems: 'center', cursor: 'pointer', flexGrow: 1}} onClick={() => handleToggleUser(user.username)}>
                {expandedUser === user.username ? <FaChevronUp /> : <FaChevronDown />}
                <strong style={{marginLeft: '1rem'}}>{user.username}</strong>
                <span style={{ marginLeft: '1rem', padding: '0.2rem 0.5rem', backgroundColor: user.role === 'admin' ? '#166534' : '#1d4ed8', borderRadius: '4px', fontSize: '0.8em' }}>
                  {user.role}
                </span>
              </div>
              <button onClick={() => handleDelete(user.username)} disabled={user.role === 'admin'} style={{ backgroundColor: '#b91c1c' }}>
                <FaTrash />
              </button>
            </li>
            {expandedUser === user.username && (
              <div style={{padding: '1rem', backgroundColor: '#1a1a1a'}}>
                {isLoadingFiles ? <p>Loading files...</p> : (
                  <>
                    <h4>Files owned by {user.username}</h4>
                    {userFiles.length > 0 ? (
                      userFiles.map(file => (
                        <div key={file._id} style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.2rem'}}>
                          <span>{file.filename} (n={file.erasure.n}, k={file.erasure.k})</span>
                          <button onClick={() => handleReShard(file)} style={{fontSize: '0.8em', padding: '0.4em 0.8em'}}>
                            <FaSyncAlt style={{marginRight: '0.5rem'}}/> Re-shard
                          </button>
                        </div>
                      ))
                    ) : <p>No files found for this user.</p>}
                  </>
                )}
              </div>
            )}
          </React.Fragment>
        ))}
      </ul>
    </div>
  );
}