import { useState, useEffect } from 'react';
import { FaTrash } from 'react-icons/fa';

const METADATA_API_URL = 'http://localhost:8000';

interface UserManagementProps {
  token: string;
}

export default function UserManagement({ token }: UserManagementProps) {
  const [users, setUsers] = useState<any[]>([]);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${METADATA_API_URL}/admin/users`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      }
    } catch (error) {
      console.error("Failed to fetch users:", error);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [token]);

  const handleDelete = async (username: string) => {
    if (!confirm(`Are you sure you want to delete the user "${username}"? This will also delete all of their files.`)) return;
    
    try {
      const res = await fetch(`${METADATA_API_URL}/admin/users/${username}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        alert(`User "${username}" deleted successfully.`);
        fetchUsers(); // Refresh the list
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
          <li key={user._id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', borderBottom: '1px solid #333' }}>
            <div>
              <strong>{user.username}</strong>
              <span style={{ marginLeft: '1rem', padding: '0.2rem 0.5rem', backgroundColor: user.role === 'admin' ? '#166534' : '#1d4ed8', borderRadius: '4px', fontSize: '0.8em' }}>
                {user.role}
              </span>
            </div>
            <button onClick={() => handleDelete(user.username)} style={{ backgroundColor: '#b91c1c' }}>
              <FaTrash />
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}