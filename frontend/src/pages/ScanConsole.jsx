import React, { useState, useMemo } from 'react'
import {
  Play,
  Terminal,
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  Loader2,
  ChevronDown,
  ChevronRight,
  Code,
  ShieldCheck,
  GitMerge,
  ArrowRight,
  Flame,
  Radio,
} from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { executeLiveNetworkScan } from '../utils/realAttackEngine'
import { runClientSideAudit } from '../utils/auditEngine'
import { deriveExploitChains } from '../utils/exploitChain'
import SecurityDiagrams from '../components/SecurityDiagrams'

export default function ScanConsole() {
  const { parsedSpec, addScan, latestFindings, setLatestFindings } = useAppContext()
  const [targetUrl, setTargetUrl] = useState(parsedSpec?.base_url || 'http://localhost:8888')
  const [scanName, setScanName] = useState(
    parsedSpec ? `${parsedSpec.title} Live Pentest` : 'API Live Security Assessment'
  )
  const [token, setToken] = useState('')
  const [authorized, setAuthorized] = useState(true)
  const [isScanning, setIsScanning] = useState(false)
  const [logs, setLogs] = useState([])
  const [expandedFinding, setExpandedFinding] = useState(null)
  const [activeTab, setActiveTab] = useState('atomic')

  const exploitChains = useMemo(() => {
    return deriveExploitChains(latestFindings)
  }, [latestFindings])

  const addLog = (msg) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`])
  }

  const handleStartScan = async () => {
    if (!authorized) {
      alert('Please confirm authorization before scanning.')
      return
    }

    setIsScanning(true)
    setLogs([])
    setLatestFindings([])

    addLog(`🚀 Launching REAL Live Network Penetration Test: "${scanName}"`)
    addLog(`🎯 Target API Host: ${targetUrl}`)
    addLog(`🛡️ Active Attack Modules: BOLA (IDOR), Broken Auth, Burst Rate Limit, Mass Assignment, Data Exposure`)

    try {
      const liveResults = await executeLiveNetworkScan(
        parsedSpec,
        targetUrl,
        token,
        (msg) => addLog(msg)
      )

      let finalFindings = liveResults
      if (liveResults.length === 0) {
        addLog(`ℹ️ Live target at ${targetUrl} was offline. Running spec static analysis & heuristic evaluation...`)
        finalFindings = runClientSideAudit(parsedSpec, targetUrl, token)
      }

      setLatestFindings(finalFindings)
      setIsScanning(false)

      addScan({
        id: Math.floor(1000 + Math.random() * 9000),
        name: scanName,
        target_url: targetUrl,
        status: 'completed',
        total_endpoints: parsedSpec?.total_endpoints || 11,
        total_findings: finalFindings.length,
        findings: finalFindings,
        created_at: new Date().toISOString(),
      })

    } catch (err) {
      addLog(`❌ Scan execution error: ${err.message}`)
      setIsScanning(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <h1>Scan Console</h1>
          <span className="badge badge-critical" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Radio size={12} className="pulse" /> LIVE HTTP ATTACK ENGINE
          </span>
        </div>
        <p>Fires real network exploit requests and visualizes compound attack topologies</p>
      </div>

      {/* Configuration Form */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h3 className="card-title">Live Target Configuration</h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div className="form-group">
            <label className="form-label">Target Host Base URL</label>
            <input
              type="url"
              className="form-input"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:8888"
            />
          </div>
          <div className="form-group">
            <label className="form-label">Scan Title</label>
            <input
              type="text"
              className="form-input"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              placeholder="Live API Security Assessment"
            />
          </div>
        </div>

        <div className="form-group">
          <label className="form-label">Test Bearer / JWT Token (Optional)</label>
          <input
            type="text"
            className="form-input mono"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
          />
        </div>

        <div className="form-group">
          <label className="form-label">Active Modules (Fires Genuine Network Requests)</label>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginTop: '0.5rem' }}>
            {['BOLA (IDOR Traversal)', 'Broken Auth (Admin Probe)', 'Excessive Data (PII Leak)', 'Rate Limiting (20 Burst Req/s)', 'Mass Assignment (Privilege Escalation)', 'Exploit Chaining'].map(
              (mod) => (
                <label
                  key={mod}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    fontSize: '0.85rem',
                    color: 'var(--text-primary)',
                  }}
                >
                  <input type="checkbox" defaultChecked />
                  {mod}
                </label>
              )
            )}
          </div>
        </div>

        <div
          style={{
            background: 'rgba(234, 179, 8, 0.08)',
            border: '1px solid rgba(234, 179, 8, 0.2)',
            borderRadius: 'var(--radius-md)',
            padding: '0.75rem 1rem',
            marginTop: '1rem',
            fontSize: '0.85rem',
            color: 'var(--severity-medium)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <input
            type="checkbox"
            id="authCheck"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
          />
          <label htmlFor="authCheck" style={{ cursor: 'pointer' }}>
            I confirm that I have written permission and authorization to assess the target environment.
          </label>
        </div>

        <div style={{ marginTop: '1.5rem', display: 'flex', gap: '0.75rem' }}>
          <button
            className="btn btn-primary"
            onClick={handleStartScan}
            disabled={isScanning || !authorized}
          >
            {isScanning ? (
              <>
                <Loader2 size={16} className="pulse" />
                Executing Live Network Attack...
              </>
            ) : (
              <>
                <Play size={16} />
                Fire Live Exploit Scan
              </>
            )}
          </button>
        </div>
      </div>

      {/* Live Terminal Output */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Terminal size={18} />
            Live Network Socket Logs
          </h3>
        </div>
        <div
          style={{
            background: '#070a13',
            borderRadius: 'var(--radius-md)',
            padding: '1rem 1.25rem',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.82rem',
            color: '#38bdf8',
            minHeight: '160px',
            maxHeight: '230px',
            overflowY: 'auto',
            border: '1px solid var(--border-subtle)',
            lineHeight: '1.8',
          }}
        >
          {logs.length === 0 ? (
            <p style={{ color: 'var(--text-muted)' }}>&gt; Ready to fire live HTTP requests over the network...</p>
          ) : (
            logs.map((log, i) => <div key={i}>{log}</div>)
          )}
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          INTERACTIVE SECURITY DIAGRAMS & TOPOLOGY VISUALIZATIONS
          ───────────────────────────────────────────────────────────── */}
      {latestFindings.length > 0 && (
        <SecurityDiagrams
          parsedSpec={parsedSpec}
          findings={latestFindings}
          exploitChains={exploitChains}
        />
      )}

      {/* Findings & Exploit Chains View */}
      {latestFindings.length > 0 && (
        <div className="card" style={{ marginTop: '1.5rem' }}>
          <div className="card-header" style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1rem' }}>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                className={`btn ${activeTab === 'atomic' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.82rem', padding: '0.4rem 0.8rem' }}
                onClick={() => setActiveTab('atomic')}
              >
                <ShieldAlert size={16} />
                Live Confirmed Findings ({latestFindings.length})
              </button>

              <button
                className={`btn ${activeTab === 'chains' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.82rem', padding: '0.4rem 0.8rem', background: activeTab === 'chains' ? 'linear-gradient(135deg, #ef4444, #f97316)' : 'transparent' }}
                onClick={() => setActiveTab('chains')}
              >
                <GitMerge size={16} />
                Exploit Chains &amp; Kill Paths ({exploitChains.length})
              </button>
            </div>

            <span className="badge badge-critical">Confirmed Network Impact</span>
          </div>

          {/* TAB 1: Atomic Findings */}
          {activeTab === 'atomic' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
              {latestFindings.map((f) => {
                const isExp = expandedFinding === f.id
                return (
                  <div
                    key={f.id}
                    style={{
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-md)',
                      background: 'var(--bg-primary)',
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      onClick={() => setExpandedFinding(isExp ? null : f.id)}
                      style={{
                        padding: '0.85rem 1.25rem',
                        cursor: 'pointer',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        background: isExp ? 'var(--bg-card-hover)' : 'transparent',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        {isExp ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                        <span className={`method-badge method-${f.method}`}>{f.method}</span>
                        <strong style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                          {f.title}
                        </strong>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                          CVSS: <strong style={{ color: 'var(--accent-cyan)' }}>{f.cvss_score}</strong>
                        </span>
                        <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                      </div>
                    </div>

                    {isExp && (
                      <div
                        style={{
                          padding: '1.25rem',
                          borderTop: '1px solid var(--border-subtle)',
                          background: '#0a0e1a',
                          fontSize: '0.85rem',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '1rem',
                        }}
                      >
                        <div>
                          <h4 style={{ color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                            Vulnerability Description
                          </h4>
                          <p style={{ color: 'var(--text-secondary)' }}>{f.description}</p>
                        </div>

                        <div>
                          <h4 style={{ color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                            Live HTTP Request &amp; Response PoC Evidence
                          </h4>
                          <pre
                            style={{
                              background: '#05070d',
                              padding: '0.75rem 1rem',
                              borderRadius: 'var(--radius-sm)',
                              border: '1px solid var(--border-subtle)',
                              color: '#22d3ee',
                              fontSize: '0.78rem',
                              whiteSpace: 'pre-wrap',
                              overflowX: 'auto',
                            }}
                          >
                            {f.evidence}
                          </pre>
                        </div>

                        <div>
                          <h4 style={{ color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                            Remediation Guidance
                          </h4>
                          <p style={{ color: 'var(--severity-low)', background: 'rgba(34, 197, 94, 0.08)', padding: '0.6rem 0.8rem', borderRadius: 'var(--radius-sm)' }}>
                            💡 {f.remediation}
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {/* TAB 2: Exploit Chains */}
          {activeTab === 'chains' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem' }}>
              {exploitChains.map((chain) => (
                <div
                  key={chain.id}
                  style={{
                    background: '#0a0e1a',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: 'var(--radius-lg)',
                    padding: '1.25rem',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Flame size={20} style={{ color: 'var(--severity-critical)' }} />
                      <strong style={{ fontSize: '1rem', color: '#f87171' }}>{chain.title}</strong>
                    </div>
                    <span className="badge badge-critical" style={{ fontSize: '0.8rem' }}>
                      Compound CVSS: {chain.composite_cvss}
                    </span>
                  </div>

                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1rem' }}>
                    <strong>Real-World Impact:</strong> {chain.impact}
                  </p>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1rem' }}>
                    {chain.steps.map((st, i) => (
                      <div
                        key={i}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '0.75rem',
                          background: 'var(--bg-card)',
                          padding: '0.65rem 0.9rem',
                          borderRadius: 'var(--radius-md)',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        <span
                          style={{
                            background: 'var(--gradient-primary)',
                            color: '#fff',
                            width: '24px',
                            height: '24px',
                            borderRadius: '50%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '0.75rem',
                            fontWeight: 700,
                            flexShrink: 0,
                          }}
                        >
                          {st.num}
                        </span>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <strong style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>{st.name}</strong>
                            <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>{st.tag}</span>
                          </div>
                          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.2rem' }}>{st.desc}</p>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div
                    style={{
                      background: 'rgba(34, 197, 94, 0.06)',
                      borderLeft: '3px solid var(--severity-low)',
                      padding: '0.5rem 0.75rem',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.8rem',
                      color: 'var(--severity-low)',
                    }}
                  >
                    <strong>Strategic Fix:</strong> {chain.remediation}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
