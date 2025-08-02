import React from 'react';

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
}

export default function StatCard({ title, value, icon }: StatCardProps) {
  return (
    <div className="card" style={{ margin: 0, backgroundColor: '#1a1a1a', textAlign: 'left' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ fontSize: '2rem', color: '#646cff' }}>{icon}</div>
        <div>
          <h4 style={{ margin: 0, color: '#888' }}>{title}</h4>
          <p style={{ margin: 0, fontSize: '1.5em', fontWeight: 'bold' }}>{value}</p>
        </div>
      </div>
    </div>
  );
}