import { Play, Square, Terminal } from 'lucide-react'

export default function ScanConsole() {
  return (
    <div>
      <div className="page-header">
        <h1>Scan Console</h1>
        <p>Configure and run vulnerability scans against mapped endpoints</p>
      </div>

      {/* Scan Configuration */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h3 className="card-title">Scan Configuration</h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div className="form-group">
            <label className="form-label">Target URL</label>
            <input
              type="url"
              className="form-input"
              placeholder="http://localhost:8888"
              disabled
            />
          </div>
          <div className="form-group">
            <label className="form-label">Scan Name</label>
            <input
              type="text"
              className="form-input"
              placeholder="crAPI Security Scan"
              disabled
            />
          </div>
        </div>

        {/* Attack module checkboxes — Phase 2 */}
        <div className="form-group">
          <label className="form-label">Attack Modules</label>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
            {['BOLA', 'Broken Auth', 'Excessive Data', 'Rate Limiting', 'Mass Assignment'].map(mod => (
              <label key={mod} style={{
                display: 'flex', alignItems: 'center', gap: '0.4rem',
                fontSize: '0.85rem', color: 'var(--text-secondary)',
                cursor: 'not-allowed', opacity: 0.5,
              }}>
                <input type="checkbox" disabled checked />
                {mod}
              </label>
            ))}
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.5rem' }}>
            Attack modules will be enabled in Phase 2
          </p>
        </div>

        {/* Authorization checkbox (hard constraint) */}
        <div style={{
          background: 'rgba(234, 179, 8, 0.08)',
          border: '1px solid rgba(234, 179, 8, 0.2)',
          borderRadius: 'var(--radius-md)',
          padding: '0.75rem 1rem',
          marginTop: '1rem',
          fontSize: '0.85rem',
          color: 'var(--severity-medium)',
        }}>
          ⚠️ You must confirm that you own or have written authorization to test the target API.
        </div>

        <div style={{ marginTop: '1.5rem', display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-primary" disabled>
            <Play size={16} />
            Start Scan
          </button>
          <button className="btn btn-danger" disabled>
            <Square size={16} />
            Stop
          </button>
        </div>
      </div>

      {/* Live console output — Phase 2 */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Terminal size={18} />
            Live Output
          </h3>
        </div>
        <div style={{
          background: 'var(--bg-primary)',
          borderRadius: 'var(--radius-md)',
          padding: '1rem',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '0.8rem',
          color: 'var(--text-muted)',
          minHeight: '200px',
          border: '1px solid var(--border-subtle)',
        }}>
          <p style={{ color: 'var(--text-muted)' }}>
            {'>'} Waiting for scan to start...
          </p>
        </div>
      </div>
    </div>
  )
}
