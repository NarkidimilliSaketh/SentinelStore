// src/components/FileDetailsModal.tsx
import React from 'react';

interface FileDetailsModalProps {
  fileDetails: any;
  onClose: () => void;
  onUnshare: (username: string) => void;
  isOwner: boolean;
}

// --- NEW: Helper function to format log messages ---
const formatLogMessage = (log: any) => {
  const actionText = log.action.replace(/_/g, ' ').toLowerCase();
  let detailsText = '';

  if (log.action === 'SHARE_FILE' && log.details.shared_with) {
    detailsText = ` with ${log.details.shared_with}`;
  } else if (log.action === 'UNSHARE_FILE' && log.details.unshared_from) {
    detailsText = ` from ${log.details.unshared_from}`;
  } else if (log.action === 'DOWNLOAD_FILE') {
    // No extra details needed for download
  }

  return `${log.username} ${actionText}${detailsText}.`;
};

export default function FileDetailsModal({ fileDetails, onClose, onUnshare, isOwner }: FileDetailsModalProps) {
  if (!fileDetails) return null;

  return (
    <div style={styles.overlay}>
      <div style={styles.modal}>
        <button onClick={onClose} style={styles.closeButton}>×</button>
        <h2>File Details: {fileDetails.filename}</h2>
        
        <div style={styles.section}>
          <h3>Properties</h3>
          <p><strong>Owner:</strong> {fileDetails.owner}</p>
          <p><strong>Root Hash:</strong> <span style={{wordBreak: 'break-all'}}>{fileDetails.root_hash}</span></p>
          <p><strong>Fault Tolerance:</strong> {fileDetails.erasure.n} total shares, {fileDetails.erasure.k} required</p>
        </div>

        {isOwner && (
          <div style={styles.section}>
            <h3>Sharing Status</h3>
            {fileDetails.sharing_info.length > 0 ? (
              <ul>
                {fileDetails.sharing_info.map((share: any) => (
                  <li key={share.shared_with_user} style={styles.shareItem}>
                    <span>Shared with: <strong>{share.shared_with_user}</strong></span>
                    <button onClick={() => onUnshare(share.shared_with_user)} style={styles.unshareBtn}>Unshare</button>
                  </li>
                ))}
              </ul>
            ) : <p>Not shared with anyone.</p>}
          </div>
        )}

        <div style={styles.section}>
          <h3>Activity Log</h3>
          <div style={styles.logBox}>
            {fileDetails.activity_log.length > 0 ? (
              fileDetails.activity_log.map((log: any) => (
                <p key={log.timestamp} style={styles.logEntry}>
                  <strong>{new Date(log.timestamp).toLocaleString()}:</strong>
                  {/* --- MODIFIED: Use the formatting function --- */}
                  <span> {formatLogMessage(log)}</span>
                </p>
              ))
            ) : <p>No activity recorded for this file.</p>}
          </div>
        </div>
      </div>
    </div>
  );
}

// ... (styles object remains the same) ...
const styles: { [key: string]: React.CSSProperties } = {
  overlay: { position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.7)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 },
  modal: { backgroundColor: '#242424', padding: '2rem', borderRadius: '12px', width: '90%', maxWidth: '600px', maxHeight: '90vh', overflowY: 'auto', position: 'relative' },
  closeButton: { position: 'absolute', top: '1rem', right: '1rem', background: 'none', border: 'none', color: 'white', fontSize: '1.5rem', cursor: 'pointer' },
  section: { marginTop: '1.5rem', borderTop: '1px solid #444', paddingTop: '1rem' },
  shareItem: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' },
  unshareBtn: { backgroundColor: '#b91c1c', padding: '0.4em 0.8em', fontSize: '0.9em' },
  logBox: { maxHeight: '200px', overflowY: 'auto', backgroundColor: '#1a1a1a', padding: '0.5rem', borderRadius: '8px' },
  logEntry: { margin: '0.5rem 0', fontSize: '0.9em', borderBottom: '1px solid #333', paddingBottom: '0.5rem' }
};