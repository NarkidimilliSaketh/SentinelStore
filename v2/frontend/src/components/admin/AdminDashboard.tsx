import { useState, useEffect } from 'react';
import StatCard from './StatCard';
import UserManagement from './UserManagement';
import { FaUsers, FaSignInAlt, FaUserPlus, FaFileAlt, FaTrashRestore } from 'react-icons/fa';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const METADATA_API_URL = 'http://localhost:8000';
const P2P_NODE_URLS = (import.meta.env.VITE_P2P_NODE_URLS || 'http://localhost:8001,http://localhost:8002,http://localhost:8003').split(',');

interface AdminDashboardProps {
  token: string;
  username: string;
  onLogout: () => void;
}

export default function AdminDashboard({ token, username, onLogout }: AdminDashboardProps) {
  const [stats, setStats] = useState<any>(null);
  const [nodeHealth, setNodeHealth] = useState<any[]>([]);
  const [isGcRunning, setIsGcRunning] = useState(false);

  useEffect(() => {
    const fetchAdminData = async () => {
      try {
        const statsRes = await fetch(`${METADATA_API_URL}/admin/stats`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (statsRes.ok) setStats(await statsRes.json());

        const healthPromises = P2P_NODE_URLS.map((url: string) =>
          fetch(`${url}/health`)
            .then(res => res.ok ? res.json() : { status: 'offline', public_url: url })
            .catch(() => ({ status: 'offline', public_url: url }))
        );
        setNodeHealth(await Promise.all(healthPromises));
      } catch (error) {
        console.error("Failed to fetch admin data:", error);
      }
    };
    fetchAdminData();
    const intervalId = setInterval(fetchAdminData, 10000);
    return () => clearInterval(intervalId);
  }, [token]);

  const handleTriggerGc = async () => {
    if (!confirm("Are you sure you want to trigger a network-wide garbage collection? This will permanently delete any orphaned file shares.")) return;
    setIsGcRunning(true);
    try {
      const res = await fetch(`${METADATA_API_URL}/admin/trigger-gc`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      console.log("GC Results:", data);
      alert("Garbage collection cycle completed. Check console and node health panel for results.");
    } catch (error) {
      alert(`Error triggering GC: ${error}`);
    } finally {
      setIsGcRunning(false);
    }
  };

  const pieChartData = stats ? [
    { name: 'Active Users', value: stats.active_users },
    { name: 'Inactive Users', value: stats.total_users - stats.active_users },
  ] : [];

  const barChartData = stats ? [
    { name: 'Activity Today', logins: stats.logins_today, registrations: stats.registrations_today },
  ] : [];

  const COLORS = ['#646cff', '#555'];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Admin Panel</h1>
        <button onClick={onLogout} style={{backgroundColor: '#444'}}>Logout ({username})</button>
      </div>

      <div className="card">
        <h2>📊 Key Metrics</h2>
        <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem'}}>
          <StatCard title="Total Users" value={stats?.total_users ?? '...'} icon={<FaUsers />} />
          <StatCard title="Active Users (7d)" value={stats?.active_users ?? '...'} icon={<FaSignInAlt />} />
          <StatCard title="New Users (24h)" value={stats?.registrations_today ?? '...'} icon={<FaUserPlus />} />
          <StatCard title="Total Files Stored" value={stats?.total_files ?? '...'} icon={<FaFileAlt />} />
        </div>
      </div>
      
      <div className="card">
        <h2>🌐 P2P Network Health</h2>
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
        <h2>📈 User Activity Overview</h2>
        <div style={{display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '2rem', height: '300px'}}>
          <div>
            <h4>User Status</h4>
            <ResponsiveContainer>
              <PieChart>
                <Pie data={pieChartData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                  {pieChartData.map((_entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                </Pie>
                <Tooltip wrapperStyle={{backgroundColor: '#333'}} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div>
            <h4>Activity in Last 24 Hours</h4>
            <ResponsiveContainer>
              <BarChart data={barChartData}>
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip wrapperStyle={{backgroundColor: '#333'}} />
                <Legend />
                <Bar dataKey="logins" fill="#8884d8" />
                <Bar dataKey="registrations" fill="#82ca9d" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card">
        <h2>⚙️ Administrative Actions</h2>
        <button onClick={handleTriggerGc} disabled={isGcRunning}>
          <FaTrashRestore style={{marginRight: '0.5rem'}}/> {isGcRunning ? 'GC in Progress...' : 'Trigger Network Garbage Collection'}
        </button>
      </div>
      
      <UserManagement token={token} />
    </div>
  );
}