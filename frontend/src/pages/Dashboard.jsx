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

export default function Dashboard() {
  const { parsedSpec } = useAppContext()

  return (
    <div>
      <div className="page-header">
        <h1>Dashboard</h1>
        <p>Overview of your API security testing activity</p>
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
              Spec Loaded — {parsedSpec.title}
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

          {/* Methods breakdown */}
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem', flexWrap: 'wrap' }}>
            {Object.entries(parsedSpec.methods_breakdown).map(([method, count]) => (
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
            Get started by uploading an OpenAPI/Swagger spec to map the attack surface.
          </p>
          <Link to="/upload" className="btn btn-primary">
            Upload API Spec
            <ArrowRight size={16} />
          </Link>
        </div>
      )}

      {/* Recent Activity */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Recent Activity</h3>
        </div>
        {parsedSpec ? (
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: '0.75rem',
              padding: '0.75rem', borderRadius: 'var(--radius-md)',
              background: 'var(--bg-primary)',
            }}>
              <CheckCircle size={16} style={{ color: 'var(--severity-low)' }} />
              <span>Parsed <strong>{parsedSpec.title}</strong> — {parsedSpec.total_endpoints} endpoints, {parsedSpec.total_params} parameters</span>
            </div>
          </div>
        ) : (
          <div className="empty-state">
            <Activity size={48} />
            <h3>No activity yet</h3>
            <p>Upload an API spec and run your first scan to see results here.</p>
          </div>
        )}
      </div>
    </div>
  )
}
