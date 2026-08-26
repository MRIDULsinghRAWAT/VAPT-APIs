import React from 'react'
import { Link } from 'react-router-dom'
import {
  Shield,
  Target,
  AlertTriangle,
  Activity,
  ArrowRight,
  CheckCircle,
  Code,
  Database,
  Calendar,
  Download,
} from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import SecurityDiagrams from '../components/SecurityDiagrams'

export default function Dashboard() {
  const { parsedSpec, scans, latestFindings } = useAppContext()

  const totalFindingsCount = scans.reduce((acc, s) => acc + (s.total_findings || 0), 0)
  const lastScan = scans.length > 0 ? scans[0] : null

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h1>Security Dashboard</h1>
            <p>Real-time attack surface intelligence and automated pentest posture overview</p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#0f172a', border: '1px solid #1e293b', padding: '0.4rem 0.8rem', borderRadius: '8px', fontSize: '0.78rem', color: '#94a3b8' }}>
            <Database size={14} style={{ color: 'var(--accent-cyan)' }} />
            <span>Database Storage: </span>
            <strong style={{ color: '#22c55e' }}>PERSISTED ({scans.length} Saved Scans)</strong>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-icon purple">
            <Target size={24} />
          </div>
          <div>
            <div className="stat-value">{scans.length}</div>
            <div className="stat-label">Total Scans Executed</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon cyan">
            <Code size={24} />
          </div>
          <div>
            <div className="stat-value">{parsedSpec?.total_endpoints || (lastScan?.total_endpoints || 0)}</div>
            <div className="stat-label">Endpoints Mapped</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon red">
            <AlertTriangle size={24} />
          </div>
          <div>
            <div className="stat-value">{totalFindingsCount}</div>
            <div className="stat-label">Total Flaws Discovered</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon green">
            <Activity size={24} />
          </div>
          <div>
            <div className="stat-value" style={{ fontSize: '1rem', marginTop: '0.2rem' }}>
              {lastScan ? new Date(lastScan.created_at).toLocaleDateString() : '—'}
            </div>
            <div className="stat-label">Latest Assessment Date</div>
          </div>
        </div>
      </div>

      {/* Loaded Spec Info */}
      {parsedSpec ? (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card-header">
            <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle size={18} style={{ color: 'var(--severity-low)' }} />
              Active Target — {parsedSpec.title}
            </h3>
            <Link to="/endpoints" className="btn btn-primary" style={{ fontSize: '0.8rem' }}>
              View Endpoint Map <ArrowRight size={14} />
            </Link>
          </div>
          <div style={{ display: 'flex', gap: '2rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            <span><strong>Version:</strong> {parsedSpec.version}</span>
            <span><strong>Spec:</strong> {parsedSpec.spec_version}</span>
            {parsedSpec.base_url && <span><strong>Base URL:</strong> <code>{parsedSpec.base_url}</code></span>}
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem', flexWrap: 'wrap' }}>
            {Object.entries(parsedSpec.methods_breakdown || {}).map(([method, count]) => (
              <span key={method} className={`method-badge method-${method}`}>
                {method} × {count}
              </span>
            ))}
          </div>
        </div>
      ) : (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card-header">
            <h3 className="card-title">Quick Start</h3>
          </div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem', fontSize: '0.9rem' }}>
            Get started by uploading an OpenAPI/Swagger spec to map the attack surface and generate visual architecture diagrams.
          </p>
          <Link to="/upload" className="btn btn-primary">
            Upload API Spec
            <ArrowRight size={16} />
          </Link>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          HISTORICAL SCANS FROM DATABASE
          ───────────────────────────────────────────────────────────── */}
      {scans.length > 0 && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card-header">
            <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Database size={18} style={{ color: 'var(--accent-cyan)' }} />
              Historical Scan Records (Database Vault)
            </h3>
            <Link to="/reports" className="btn btn-secondary" style={{ fontSize: '0.78rem' }}>
              View All Reports <ArrowRight size={14} />
            </Link>
          </div>

          <div className="table-container" style={{ border: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>Scan Title</th>
                  <th>Target Host</th>
                  <th>Execution Date</th>
                  <th>Vulnerabilities</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 4).map((s) => (
                  <tr key={s.id}>
                    <td><strong>{s.name}</strong></td>
                    <td><code>{s.target_url}</code></td>
                    <td style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                    <td>
                      <span className="badge badge-critical">
                        {s.total_findings || 0} Vulnerabilities
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-low">{s.status || 'completed'}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          INTERACTIVE SECURITY DIAGRAMS & TOPOLOGY VISUALIZATIONS
          ───────────────────────────────────────────────────────────── */}
      {parsedSpec && (
        <SecurityDiagrams
          parsedSpec={parsedSpec}
          findings={latestFindings}
        />
      )}
    </div>
  )
}
