import React, { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Map, Lock, Unlock, Filter, Upload, Shield, Code, ChevronDown, ChevronRight } from 'lucide-react'
import { useAppContext } from '../context/AppContext'

export default function EndpointMap() {
  const { parsedSpec } = useAppContext()
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [authFilter, setAuthFilter] = useState('ALL') // ALL, AUTH, NO_AUTH
  const [expandedRow, setExpandedRow] = useState(null)

  const filteredEndpoints = useMemo(() => {
    if (!parsedSpec || !parsedSpec.endpoints) return []
    return parsedSpec.endpoints.filter(ep => {
      if (methodFilter !== 'ALL' && ep.method !== methodFilter) return false
      if (authFilter === 'AUTH' && !ep.auth_required) return false
      if (authFilter === 'NO_AUTH' && ep.auth_required) return false
      return true
    })
  }, [parsedSpec, methodFilter, authFilter])

  const methods = ['ALL', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH']

  if (!parsedSpec) {
    return (
      <div>
        <div className="page-header">
          <h1>Endpoint Map</h1>
          <p>Interactive attack surface map from parsed API spec</p>
        </div>
        <div className="card">
          <div className="empty-state">
            <Map size={48} />
            <h3>No endpoints mapped yet</h3>
            <p>Upload an API spec first to see the full endpoint map.</p>
            <Link to="/upload" className="btn btn-primary" style={{ marginTop: '1rem' }}>
              <Upload size={16} />
              Upload Spec
            </Link>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <h1>Endpoint Map — {parsedSpec.title}</h1>
        <p>{parsedSpec.description || `${parsedSpec.spec_version} • ${parsedSpec.total_endpoints} endpoints`}</p>
      </div>

      {/* Spec Stats */}
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-icon purple"><Code size={24} /></div>
          <div>
            <div className="stat-value">{parsedSpec.total_endpoints}</div>
            <div className="stat-label">Total Endpoints</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon cyan"><Shield size={24} /></div>
          <div>
            <div className="stat-value">{parsedSpec.auth_coverage?.protected ?? 0}</div>
            <div className="stat-label">Auth Protected</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon red"><Unlock size={24} /></div>
          <div>
            <div className="stat-value">{parsedSpec.auth_coverage?.unprotected ?? 0}</div>
            <div className="stat-label">No Auth (Exposed)</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon green"><Filter size={24} /></div>
          <div>
            <div className="stat-value">{parsedSpec.total_params}</div>
            <div className="stat-label">Total Parameters</div>
          </div>
        </div>
      </div>

      {/* Methods Breakdown */}
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <Filter size={16} style={{ color: 'var(--text-muted)' }} />

          {methods.map(m => (
            <button
              key={m}
              className={`btn ${methodFilter === m ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
              onClick={() => setMethodFilter(m)}
            >
              {m === 'ALL' ? 'All Methods' : m}
              {m !== 'ALL' && parsedSpec.methods_breakdown?.[m] ? ` (${parsedSpec.methods_breakdown[m]})` : ''}
            </button>
          ))}

          <span style={{ width: '1px', height: '24px', background: 'var(--border-subtle)', margin: '0 0.25rem' }} />

          <button
            className={`btn ${authFilter === 'AUTH' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
            onClick={() => setAuthFilter(authFilter === 'AUTH' ? 'ALL' : 'AUTH')}
          >
            <Lock size={14} /> Protected
          </button>
          <button
            className={`btn ${authFilter === 'NO_AUTH' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
            onClick={() => setAuthFilter(authFilter === 'NO_AUTH' ? 'ALL' : 'NO_AUTH')}
          >
            <Unlock size={14} /> Unprotected
          </button>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1rem 1.5rem', borderBottom: '1px solid var(--border-subtle)' }}>
          <h3 className="card-title">
            {filteredEndpoints.length} Endpoint{filteredEndpoints.length !== 1 ? 's' : ''}
            {(methodFilter !== 'ALL' || authFilter !== 'ALL') ? ' (filtered)' : ''}
          </h3>
        </div>

        <div className="table-container" style={{ border: 'none' }}>
          <table>
            <thead>
              <tr>
                <th style={{ width: '30px' }}></th>
                <th style={{ width: '90px' }}>Method</th>
                <th>Path</th>
                <th>Summary</th>
                <th style={{ width: '70px' }}>Auth</th>
                <th style={{ width: '80px' }}>Params</th>
                <th>Tags</th>
              </tr>
            </thead>
            <tbody>
              {filteredEndpoints.map((ep, idx) => {
                const key = `${ep.method}-${ep.path}-${idx}`
                const isExpanded = expandedRow === key
                return (
                  <React.Fragment key={key}>
                    <tr
                      onClick={() => setExpandedRow(isExpanded ? null : key)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        {isExpanded
                          ? <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />
                          : <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
                        }
                      </td>
                      <td>
                        <span className={`method-badge method-${ep.method}`}>{ep.method}</span>
                      </td>
                      <td>
                        <code style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>{ep.path}</code>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                        {ep.summary || '—'}
                      </td>
                      <td>
                        {ep.auth_required
                          ? <Lock size={14} style={{ color: 'var(--severity-low)' }} />
                          : <Unlock size={14} style={{ color: 'var(--severity-critical)' }} />
                        }
                      </td>
                      <td style={{ textAlign: 'center', fontSize: '0.85rem' }}>
                        {(ep.parameters?.length || 0) + (ep.request_body_schema ? 1 : 0)}
                      </td>
                      <td>
                        {(ep.tags || []).map(tag => (
                          <span key={tag} className="badge badge-info" style={{ marginRight: '0.25rem' }}>
                            {tag}
                          </span>
                        ))}
                      </td>
                    </tr>

                    {/* Expanded Row — Details */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={7} style={{ background: 'var(--bg-primary)', padding: '1rem 1.5rem' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                            {/* Parameters */}
                            <div>
                              <h4 style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                Parameters
                              </h4>
                              {ep.parameters && ep.parameters.length > 0 ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                                  {ep.parameters.map(p => (
                                    <div key={p.name} style={{
                                      display: 'flex', alignItems: 'center', gap: '0.5rem',
                                      fontSize: '0.8rem', padding: '0.35rem 0.5rem',
                                      background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)',
                                    }}>
                                      <code style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>{p.name}</code>
                                      <span style={{ color: 'var(--text-muted)' }}>({p.location})</span>
                                      <span style={{ color: 'var(--text-muted)' }}>• {p.param_type}</span>
                                      {p.required && <span className="badge badge-critical" style={{ fontSize: '0.65rem' }}>required</span>}
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>No path/query params</p>
                              )}
                            </div>

                            {/* Request Body / Auth */}
                            <div>
                              <h4 style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                Security & Body
                              </h4>
                              <div style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                                <div style={{ padding: '0.35rem 0.5rem', background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)' }}>
                                  <span style={{ color: 'var(--text-muted)' }}>Auth: </span>
                                  {ep.auth_required
                                    ? <span style={{ color: 'var(--severity-low)' }}>🔒 {(ep.auth_schemes || []).join(', ') || 'Required'}</span>
                                    : <span style={{ color: 'var(--severity-critical)' }}>🔓 None</span>
                                  }
                                </div>
                                <div style={{ padding: '0.35rem 0.5rem', background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)' }}>
                                  <span style={{ color: 'var(--text-muted)' }}>Request Body: </span>
                                  {ep.request_body_schema
                                    ? <span style={{ color: 'var(--accent-cyan)' }}>
                                        {Object.keys(ep.request_body_schema.properties || {}).join(', ') || 'JSON body'}
                                      </span>
                                    : <span style={{ color: 'var(--text-muted)' }}>None</span>
                                  }
                                </div>
                                {ep.response_schema && (
                                  <div style={{ padding: '0.35rem 0.5rem', background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)' }}>
                                    <span style={{ color: 'var(--text-muted)' }}>Response Fields: </span>
                                    <span style={{ color: 'var(--accent-primary)' }}>
                                      {Object.keys(ep.response_schema.properties || ep.response_schema.items?.properties || {}).join(', ') || ep.response_schema.type || 'Object'}
                                    </span>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
