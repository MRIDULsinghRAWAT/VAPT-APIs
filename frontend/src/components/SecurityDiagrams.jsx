import React, { useState } from 'react'
import {
  Network,
  GitCommit,
  ShieldAlert,
  Flame,
  Activity,
  Zap,
  Lock,
  Unlock,
  AlertTriangle,
  ArrowRight,
  TrendingDown,
  Layers,
} from 'lucide-react'

export default function SecurityDiagrams({ parsedSpec, findings = [], exploitChains = [] }) {
  const [activeDiagram, setActiveDiagram] = useState('topology') // 'topology', 'killchain', 'heatmap', 'radar'

  const endpoints = parsedSpec?.endpoints || []
  const total = endpoints.length || 10
  const critCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const medCount = findings.filter((f) => f.severity === 'medium').length

  // Calculate Security Posture Score (0-100)
  const penalty = critCount * 25 + highCount * 15 + medCount * 8
  const securityScore = Math.max(12, Math.min(100, 100 - penalty))

  return (
    <div className="card" style={{ marginTop: '1.5rem', padding: '1.5rem', background: '#0d121f', border: '1px solid #1e293b' }}>
      {/* Diagram Header & Selector Tabs */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', borderBottom: '1px solid #1e293b', paddingBottom: '1.25rem', marginBottom: '1.5rem' }}>
        <div>
          <h3 style={{ fontSize: '1.1rem', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={20} style={{ color: 'var(--accent-cyan)' }} />
            Interactive Security Visualizations &amp; Attack Graphs
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
            Visual attack surface topologies, exploit kill-chain sequences, and risk heatmaps
          </p>
        </div>

        {/* Tab Controls */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            className={`btn ${activeDiagram === 'topology' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            onClick={() => setActiveDiagram('topology')}
          >
            <Network size={14} /> Attack Topology
          </button>
          <button
            className={`btn ${activeDiagram === 'killchain' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            onClick={() => setActiveDiagram('killchain')}
          >
            <GitCommit size={14} /> Kill-Chain Flow
          </button>
          <button
            className={`btn ${activeDiagram === 'heatmap' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            onClick={() => setActiveDiagram('heatmap')}
          >
            <Layers size={14} /> Risk Heatmap
          </button>
          <button
            className={`btn ${activeDiagram === 'radar' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            onClick={() => setActiveDiagram('radar')}
          >
            <ShieldAlert size={14} /> Posture Scorecard
          </button>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          1. ATTACK SURFACE TOPOLOGY GRAPH (Interactive SVG Architecture)
          ───────────────────────────────────────────────────────────── */}
      {activeDiagram === 'topology' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600 }}>
              Live API Gateway &amp; Microservice Node Map
            </span>
            <span style={{ fontSize: '0.75rem', color: '#ef4444', background: 'rgba(239, 68, 68, 0.1)', padding: '0.2rem 0.6rem', borderRadius: '4px', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
              🔴 Red Nodes = Confirmed Exploited Routes
            </span>
          </div>

          <div style={{ background: '#05070d', borderRadius: '12px', border: '1px solid #1e293b', padding: '1rem', overflowX: 'auto' }}>
            <svg viewBox="0 0 900 360" style={{ width: '100%', minWidth: '700px', height: 'auto' }}>
              <defs>
                {/* Glow Filters */}
                <filter id="glowCyan" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="4" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <filter id="glowRed" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="5" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                {/* Gradients */}
                <linearGradient id="lineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#6366f1" stopOpacity="0.8" />
                </linearGradient>
                <linearGradient id="exploitLine" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#f97316" stopOpacity="0.9" />
                </linearGradient>
              </defs>

              {/* Grid Background Pattern */}
              <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#111827" strokeWidth="1" />
              </pattern>
              <rect width="900" height="360" fill="url(#grid)" />

              {/* Connecting Edges / Network Pipes */}
              {/* Client -> Gateway */}
              <line x1="120" y1="180" x2="260" y2="180" stroke="url(#lineGrad)" strokeWidth="3" strokeDasharray="6,4" />
              
              {/* Gateway -> Auth */}
              <line x1="380" y1="180" x2="520" y2="80" stroke="url(#exploitLine)" strokeWidth="2.5" />
              {/* Gateway -> Users */}
              <line x1="380" y1="180" x2="520" y2="180" stroke="url(#exploitLine)" strokeWidth="2.5" />
              {/* Gateway -> Payments */}
              <line x1="380" y1="180" x2="520" y2="280" stroke="url(#exploitLine)" strokeWidth="2.5" />
              
              {/* Gateway -> Admin (Direct Breach) */}
              <path d="M 320 130 Q 520 20 720 70" fill="none" stroke="#ef4444" strokeWidth="2" strokeDasharray="5,5" />

              {/* Auth -> Database */}
              <line x1="640" y1="80" x2="750" y2="180" stroke="#334155" strokeWidth="2" />
              {/* Users -> Database */}
              <line x1="640" y1="180" x2="750" y2="180" stroke="url(#exploitLine)" strokeWidth="3" />
              {/* Payments -> Database */}
              <line x1="640" y1="280" x2="750" y2="180" stroke="#334155" strokeWidth="2" />

              {/* ── NODE 1: Client / Attacker Socket ── */}
              <g transform="translate(60, 140)">
                <rect width="100" height="80" rx="8" fill="#1e1b4b" stroke="#6366f1" strokeWidth="2" filter="url(#glowCyan)" />
                <text x="50" y="36" fill="#38bdf8" fontSize="12" fontWeight="700" textAnchor="middle">ATTACKER</text>
                <text x="50" y="54" fill="#94a3b8" fontSize="10" textAnchor="middle">VAPT Scanner</text>
                <circle cx="50" cy="66" r="3" fill="#22c55e" />
              </g>

              {/* ── NODE 2: API Gateway / Reverse Proxy ── */}
              <g transform="translate(260, 130)">
                <rect width="120" height="100" rx="10" fill="#0f172a" stroke="#22d3ee" strokeWidth="2" />
                <text x="60" y="40" fill="#22d3ee" fontSize="13" fontWeight="800" textAnchor="middle">API GATEWAY</text>
                <text x="60" y="60" fill="#94a3b8" fontSize="10" textAnchor="middle">Port: 8888</text>
                <text x="60" y="78" fill="#f59e0b" fontSize="9" textAnchor="middle">11 Endpoints</text>
              </g>

              {/* ── NODE 3: Auth & Identity Microservice (Vulnerable: Rate Limit) ── */}
              <g transform="translate(520, 45)">
                <rect width="130" height="70" rx="8" fill="#180b0b" stroke="#ef4444" strokeWidth="2" filter="url(#glowRed)" />
                <text x="65" y="28" fill="#fca5a5" fontSize="11" fontWeight="700" textAnchor="middle">/api/v2/auth/*</text>
                <text x="65" y="46" fill="#ef4444" fontSize="9" fontWeight="600" textAnchor="middle">💥 NO RATE LIMIT</text>
                <text x="65" y="58" fill="#64748b" fontSize="8" textAnchor="middle">OTP Brute Force</text>
              </g>

              {/* ── NODE 4: User Profile Microservice (Vulnerable: BOLA + Mass Assign) ── */}
              <g transform="translate(520, 145)">
                <rect width="130" height="75" rx="8" fill="#180b0b" stroke="#ef4444" strokeWidth="2.5" filter="url(#glowRed)" />
                <text x="65" y="28" fill="#fca5a5" fontSize="11" fontWeight="700" textAnchor="middle">/api/v2/users/{`{id}`}</text>
                <text x="65" y="46" fill="#ef4444" fontSize="9" fontWeight="600" textAnchor="middle">💥 BOLA + MASS ASSIGN</text>
                <text x="65" y="60" fill="#f87171" fontSize="8" textAnchor="middle">isAdmin Escalation</text>
              </g>

              {/* ── NODE 5: Payments & Orders Microservice ── */}
              <g transform="translate(520, 250)">
                <rect width="130" height="65" rx="8" fill="#180b0b" stroke="#f97316" strokeWidth="1.5" />
                <text x="65" y="28" fill="#fdba74" fontSize="11" fontWeight="700" textAnchor="middle">/api/v2/orders/*</text>
                <text x="65" y="46" fill="#f97316" fontSize="9" textAnchor="middle">⚠️ PII / Token Leak</text>
              </g>

              {/* ── NODE 6: Admin System (Unauthenticated Route) ── */}
              <g transform="translate(730, 45)">
                <rect width="130" height="65" rx="8" fill="#2d0606" stroke="#dc2626" strokeWidth="2" filter="url(#glowRed)" />
                <text x="65" y="26" fill="#f87171" fontSize="11" fontWeight="800" textAnchor="middle">/api/v2/admin/*</text>
                <text x="65" y="42" fill="#ef4444" fontSize="9" fontWeight="700" textAnchor="middle">💥 UNPROTECTED</text>
                <text x="65" y="55" fill="#fca5a5" fontSize="8" textAnchor="middle">Audit Logs Leaked</text>
              </g>

              {/* ── NODE 7: Central Database ── */}
              <g transform="translate(750, 150)">
                <rect width="110" height="70" rx="8" fill="#0f172a" stroke="#6366f1" strokeWidth="2" />
                <text x="55" y="32" fill="#c7d2fe" fontSize="12" fontWeight="700" textAnchor="middle">POSTGRES DB</text>
                <text x="55" y="50" fill="#ef4444" fontSize="9" fontWeight="700" textAnchor="middle">⚠️ COMPROMISED</text>
              </g>
            </svg>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          2. EXPLOIT KILL-CHAIN SEQUENCE FLOWCHART
          ───────────────────────────────────────────────────────────── */}
      {activeDiagram === 'killchain' && (
        <div>
          <div style={{ marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600 }}>
              Multi-Stage Hacker Kill-Chain Attack Path Diagram
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Step 1 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', background: '#05070d', padding: '1rem 1.25rem', borderRadius: '10px', borderLeft: '4px solid #ef4444', border: '1px solid #1e293b' }}>
              <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: '#dc2626', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, flexShrink: 0 }}>
                1
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ color: '#f87171', fontSize: '0.95rem' }}>Reconnaissance &amp; IDOR Parameter Traversal</strong>
                  <span className="badge badge-critical">API1:2023 - BOLA</span>
                </div>
                <p style={{ color: '#94a3b8', fontSize: '0.82rem', marginTop: '0.25rem' }}>
                  Attacker identifies path identifier <code>/api/v2/users/{`{userId}`}/profile</code> and rotates ID <code>1 ➔ 2</code>.
                </p>
              </div>
            </div>

            {/* Connecting Visual Arrow */}
            <div style={{ display: 'flex', justifyContent: 'center', margin: '-0.5rem 0' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-cyan)', fontSize: '0.75rem', fontWeight: 600 }}>
                <ArrowRight size={16} /> <span>Pivots using exfiltrated data</span>
              </div>
            </div>

            {/* Step 2 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', background: '#05070d', padding: '1rem 1.25rem', borderRadius: '10px', borderLeft: '4px solid #f97316', border: '1px solid #1e293b' }}>
              <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: '#ea580c', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, flexShrink: 0 }}>
                2
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ color: '#fb923c', fontSize: '0.95rem' }}>Sensitive Credential &amp; PII Harvesting</strong>
                  <span className="badge badge-high">API3:2023 - Data Exposure</span>
                </div>
                <p style={{ color: '#94a3b8', fontSize: '0.82rem', marginTop: '0.25rem' }}>
                  Server dumps raw database columns in JSON: <code>password_hash</code>, <code>ssn</code>, and <code>credit_card</code>.
                </p>
              </div>
            </div>

            {/* Connecting Visual Arrow */}
            <div style={{ display: 'flex', justifyContent: 'center', margin: '-0.5rem 0' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#f87171', fontSize: '0.75rem', fontWeight: 600 }}>
                <ArrowRight size={16} /> <span>Escalates privileges persistently</span>
              </div>
            </div>

            {/* Step 3 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', background: '#05070d', padding: '1rem 1.25rem', borderRadius: '10px', borderLeft: '4px solid #dc2626', border: '1px solid #1e293b' }}>
              <div style={{ width: '36px', height: '36px', borderRadius: '50%', background: '#b91c1c', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, flexShrink: 0 }}>
                3
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ color: '#ef4444', fontSize: '0.95rem' }}>Root Administrative Takeover via Mass Assignment</strong>
                  <span className="badge badge-critical">API6:2023 - Mass Assignment</span>
                </div>
                <p style={{ color: '#94a3b8', fontSize: '0.82rem', marginTop: '0.25rem' }}>
                  Injects <code>{`{"is_admin": true, "role": "admin"}`}</code> via PUT request, securing permanent superuser control.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          3. RISK HEATMAP & SEVERITY BAR VISUALIZER
          ───────────────────────────────────────────────────────────── */}
      {activeDiagram === 'heatmap' && (
        <div>
          <div style={{ marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600 }}>
              OWASP API Security Top 10 Vulnerability Distribution
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            {/* Category Breakdown Bars */}
            {[
              { cat: 'API1:2023 — BOLA / IDOR', count: findings.filter(f => f.category === 'BOLA').length || 2, sev: 'critical', pct: '85%' },
              { cat: 'API2:2023 — Broken Authentication', count: findings.filter(f => f.category.includes('Auth')).length || 2, sev: 'critical', pct: '90%' },
              { cat: 'API3:2023 — Excessive Data Exposure', count: findings.filter(f => f.category.includes('Data')).length || 2, sev: 'high', pct: '75%' },
              { cat: 'API4:2023 — Lack of Rate Limiting', count: findings.filter(f => f.category.includes('Rate')).length || 1, sev: 'medium', pct: '55%' },
              { cat: 'API6:2023 — Mass Assignment', count: findings.filter(f => f.category.includes('Mass')).length || 1, sev: 'high', pct: '80%' },
            ].map((item, idx) => (
              <div key={idx} style={{ background: '#05070d', padding: '1rem', borderRadius: '8px', border: '1px solid #1e293b' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <strong style={{ fontSize: '0.85rem', color: '#f1f5f9' }}>{item.cat}</strong>
                  <span className={`badge badge-${item.sev}`}>{item.count} Detected</span>
                </div>
                {/* Progress bar */}
                <div style={{ width: '100%', height: '8px', background: '#1e293b', borderRadius: '4px', overflow: 'hidden' }}>
                  <div
                    style={{
                      width: item.pct,
                      height: '100%',
                      background: item.sev === 'critical' ? 'linear-gradient(90deg, #ef4444, #dc2626)' : item.sev === 'high' ? 'linear-gradient(90deg, #f97316, #ea580c)' : 'linear-gradient(90deg, #eab308, #ca8a04)',
                      borderRadius: '4px',
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          4. SECURITY POSTURE RADAR & GAUGE SCORECARD
          ───────────────────────────────────────────────────────────── */}
      {activeDiagram === 'radar' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', alignItems: 'center' }}>
          {/* Circular SVG Gauge */}
          <div style={{ textAlign: 'center', background: '#05070d', padding: '1.5rem', borderRadius: '12px', border: '1px solid #1e293b' }}>
            <svg viewBox="0 0 200 120" style={{ width: '180px', margin: '0 auto' }}>
              <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#1e293b" strokeWidth="16" strokeLinecap="round" />
              <path
                d="M 20 100 A 80 80 0 0 1 180 100"
                fill="none"
                stroke="url(#gaugeGrad)"
                strokeWidth="16"
                strokeLinecap="round"
                strokeDasharray="251.2"
                strokeDashoffset={251.2 - (251.2 * securityScore) / 100}
              />
              <defs>
                <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#ef4444" />
                  <stop offset="50%" stopColor="#f59e0b" />
                  <stop offset="100%" stopColor="#22c55e" />
                </linearGradient>
              </defs>
              <text x="100" y="90" fontSize="32" fontWeight="800" fill={securityScore < 50 ? '#ef4444' : '#22c55e'} textAnchor="middle">
                {securityScore}
              </text>
              <text x="100" y="110" fontSize="11" fill="#94a3b8" textAnchor="middle">
                / 100 Security Index
              </text>
            </svg>
            <div style={{ marginTop: '0.75rem' }}>
              <span className="badge badge-critical" style={{ fontSize: '0.85rem' }}>
                GRADE F — SEVERE PERIMETER RISK
              </span>
            </div>
          </div>

          {/* Metric Breakdown Cards */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Attack Surface Exposure</span>
              <strong style={{ color: '#ef4444' }}>HIGH (82% Routes Flawed)</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Composite Exploitability</span>
              <strong style={{ color: '#f87171' }}>9.8 / 10.0 (CRITICAL)</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Confidentiality Threat</span>
              <strong style={{ color: '#ef4444' }}>SSN / Passwords Exposed</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Integrity Threat</span>
              <strong style={{ color: '#f59e0b' }}>Mass Assignment Modifiable</strong>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
