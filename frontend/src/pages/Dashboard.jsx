import { Link } from 'react-router-dom'
import {
  Shield,
  Target,
  AlertTriangle,
  Activity,
  ArrowRight,
  CheckCircle,
  Code,
} from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import SecurityDiagrams from '../components/SecurityDiagrams'

export default function Dashboard() {
  const { parsedSpec, latestFindings } = useAppContext()

  return (
    <div>
      <div className="page-header">
        <h1>Security Dashboard</h1>
        <p>Real-time attack surface intelligence and automated pentest posture overview</p>
      </div>

      {/* Stats Grid */}
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-icon purple">
            <Target size={24} />
          </div>
          <div>
            <div className="stat-value">{parsedSpec ? 1 : 0}</div>
            <div className="stat-label">Specs Loaded</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon cyan">
            <Code size={24} />
          </div>
          <div>
            <div className="stat-value">{parsedSpec?.total_endpoints || 0}</div>
            <div className="stat-label">Endpoints Mapped</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon red">
            <AlertTriangle size={24} />
          </div>
          <div>
            <div className="stat-value">{parsedSpec?.auth_coverage?.unprotected || 0}</div>
            <div className="stat-label">Unprotected Endpoints</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon green">
            <Shield size={24} />
          </div>
          <div>
            <div className="stat-value">{parsedSpec?.auth_coverage?.protected || 0}</div>
            <div className="stat-label">Protected Endpoints</div>
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
