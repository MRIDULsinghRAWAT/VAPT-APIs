import React, { useState, useMemo } from 'react'
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
  ShieldOff,
  ShieldCheck,
} from 'lucide-react'

export default function SecurityDiagrams({ parsedSpec, findings = [], exploitChains = [] }) {
  const [activeDiagram, setActiveDiagram] = useState('topology') // 'topology', 'killchain', 'heatmap', 'radar'

  const endpoints = parsedSpec?.endpoints || []
  const total = endpoints.length || 1
  const critCount = findings.filter((f) => f.severity === 'critical').length
  const highCount = findings.filter((f) => f.severity === 'high').length
  const medCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount = findings.filter((f) => f.severity === 'low').length
  const totalFindings = findings.length

  // Calculate Security Posture Score (0-100)
  const penalty = critCount * 25 + highCount * 15 + medCount * 8 + lowCount * 3
  const securityScore = Math.max(0, Math.min(100, 100 - penalty))

  // ─── Derived Data for Topology ───
  const topologyData = useMemo(() => {
    // Group findings by endpoint path to identify compromised routes
    const compromisedEndpoints = new Map()
    findings.forEach((f) => {
      const key = f.endpoint || 'unknown'
      if (!compromisedEndpoints.has(key)) {
        compromisedEndpoints.set(key, { path: key, methods: new Set(), vulns: [], maxSeverity: 'low' })
      }
      const entry = compromisedEndpoints.get(key)
      if (f.method) entry.methods.add(f.method)
      entry.vulns.push(f.category)
      // Track max severity
      const sevOrder = { critical: 4, high: 3, medium: 2, low: 1 }
      if ((sevOrder[f.severity] || 0) > (sevOrder[entry.maxSeverity] || 0)) {
        entry.maxSeverity = f.severity
      }
    })

    // Group endpoints into service clusters by path prefix
    const serviceClusters = new Map()
    endpoints.forEach((ep) => {
      const parts = ep.path.split('/').filter(Boolean)
      const clusterKey = parts.length >= 2 ? `/${parts[0]}/${parts[1]}` : `/${parts[0] || 'root'}`
      if (!serviceClusters.has(clusterKey)) {
        serviceClusters.set(clusterKey, { prefix: clusterKey, endpoints: [], compromised: false, vulnCount: 0, worstSeverity: 'safe' })
      }
      const cluster = serviceClusters.get(clusterKey)
      cluster.endpoints.push(ep)
      if (compromisedEndpoints.has(ep.path)) {
        cluster.compromised = true
        cluster.vulnCount += compromisedEndpoints.get(ep.path).vulns.length
        const epSev = compromisedEndpoints.get(ep.path).maxSeverity
        const sevOrder = { critical: 4, high: 3, medium: 2, low: 1, safe: 0 }
        if ((sevOrder[epSev] || 0) > (sevOrder[cluster.worstSeverity] || 0)) {
          cluster.worstSeverity = epSev
        }
      }
    })

    return {
      compromisedEndpoints,
      serviceClusters: Array.from(serviceClusters.values()).slice(0, 5), // Max 5 service nodes
      compromisedRouteCount: compromisedEndpoints.size,
      totalRoutes: endpoints.length,
    }
  }, [findings, endpoints])

  // ─── Derived Data for Heatmap ───
  const heatmapData = useMemo(() => {
    const categoryMap = [
      { key: 'BOLA', label: 'API1:2023 — BOLA / IDOR', filter: (f) => /BOLA|IDOR/i.test(f.category) },
      { key: 'Auth', label: 'API2:2023 — Broken Authentication', filter: (f) => /Broken Auth/i.test(f.category) },
      { key: 'Data', label: 'API3:2023 — Excessive Data Exposure', filter: (f) => /Data Exposure|Excessive/i.test(f.category) },
      { key: 'Rate', label: 'API4:2023 — Lack of Rate Limiting', filter: (f) => /Rate Limit/i.test(f.category) },
      { key: 'Mass', label: 'API6:2023 — Mass Assignment', filter: (f) => /Mass Assignment/i.test(f.category) },
    ]

    return categoryMap.map((cat) => {
      const matched = findings.filter(cat.filter)
      const count = matched.length
      // Severity is based on the worst finding in this category
      const hasCritical = matched.some((f) => f.severity === 'critical')
      const hasHigh = matched.some((f) => f.severity === 'high')
      const sev = hasCritical ? 'critical' : hasHigh ? 'high' : count > 0 ? 'medium' : 'none'
      // Percentage bar is relative: max finding count across categories drives 100%
      return { ...cat, count, sev, matched }
    }).filter((cat) => cat.count > 0) // Only show categories that have findings
  }, [findings])

  const maxCatCount = Math.max(1, ...heatmapData.map((c) => c.count))

  // ─── Derived Data for Scorecard ───
  const scorecardMetrics = useMemo(() => {
    const flawedRoutes = topologyData.compromisedRouteCount
    const exposurePct = total > 0 ? Math.round((flawedRoutes / total) * 100) : 0

    // Max CVSS from findings
    const maxCvss = findings.length > 0
      ? Math.max(...findings.map((f) => f.cvss_score || 0)).toFixed(1)
      : '0.0'

    // Determine confidentiality threat from data exposure findings
    const dataLeakFindings = findings.filter((f) => /Data Exposure|Excessive/i.test(f.category))
    let confThreat = 'No Data Leaks Detected'
    let confColor = '#22c55e'
    if (dataLeakFindings.length > 0) {
      const evidence = dataLeakFindings.map((f) => f.evidence || f.description || '').join(' ').toLowerCase()
      const leakedFields = []
      if (/ssn|social.?security/i.test(evidence)) leakedFields.push('SSN')
      if (/password|passwd|pwd/i.test(evidence)) leakedFields.push('Passwords')
      if (/credit.?card|card.?number/i.test(evidence)) leakedFields.push('Credit Cards')
      if (/token|api.?key|secret/i.test(evidence)) leakedFields.push('API Keys/Tokens')
      if (/email/i.test(evidence) && leakedFields.length === 0) leakedFields.push('Emails')
      confThreat = leakedFields.length > 0 ? `${leakedFields.join(' / ')} Exposed` : 'Sensitive Fields Leaked'
      confColor = '#ef4444'
    }

    // Determine integrity threat
    const massAssign = findings.filter((f) => /Mass Assignment/i.test(f.category))
    let intThreat = 'No Integrity Threats'
    let intColor = '#22c55e'
    if (massAssign.length > 0) {
      intThreat = `Mass Assignment on ${massAssign.length} Endpoint${massAssign.length > 1 ? 's' : ''}`
      intColor = '#f59e0b'
    }

    // Determine availability threat
    const rateLimit = findings.filter((f) => /Rate Limit/i.test(f.category))
    let availThreat = 'Rate Limiting Enforced'
    let availColor = '#22c55e'
    if (rateLimit.length > 0) {
      availThreat = `No Throttling on ${rateLimit.length} Endpoint${rateLimit.length > 1 ? 's' : ''}`
      availColor = '#f97316'
    }

    // Grade calculation
    let grade, gradeLabel, gradeColor
    if (securityScore >= 90) { grade = 'A'; gradeLabel = 'EXCELLENT SECURITY POSTURE'; gradeColor = '#22c55e' }
    else if (securityScore >= 75) { grade = 'B'; gradeLabel = 'MODERATE RISK — PATCHES NEEDED'; gradeColor = '#84cc16' }
    else if (securityScore >= 50) { grade = 'C'; gradeLabel = 'ELEVATED RISK — ACTION REQUIRED'; gradeColor = '#f59e0b' }
    else if (securityScore >= 25) { grade = 'D'; gradeLabel = 'HIGH RISK — IMMEDIATE ACTION'; gradeColor = '#f97316' }
    else { grade = 'F'; gradeLabel = 'SEVERE PERIMETER RISK'; gradeColor = '#ef4444' }

    return {
      exposurePct, maxCvss, flawedRoutes,
      confThreat, confColor,
      intThreat, intColor,
      availThreat, availColor,
      grade, gradeLabel, gradeColor,
    }
  }, [findings, topologyData, total, securityScore])

  // ─── No findings state ───
  if (findings.length === 0) {
    return (
      <div className="card" style={{ marginTop: '1.5rem', padding: '2rem', background: '#0d121f', border: '1px solid #1e293b', textAlign: 'center' }}>
        <ShieldCheck size={48} style={{ color: '#22c55e', margin: '0 auto 1rem' }} />
        <h3 style={{ color: '#f8fafc', marginBottom: '0.5rem' }}>No Scan Results Available</h3>
        <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
          Run a vulnerability scan from the Scan Console to populate interactive security visualizations.
        </p>
      </div>
    )
  }

  // ─── Severity color helpers ───
  const sevColor = (sev) => {
    switch (sev) {
      case 'critical': return '#ef4444'
      case 'high': return '#f97316'
      case 'medium': return '#eab308'
      case 'low': return '#22c55e'
      default: return '#64748b'
    }
  }

  const sevBg = (sev) => {
    switch (sev) {
      case 'critical': return '#180b0b'
      case 'high': return '#18120b'
      case 'medium': return '#18170b'
      default: return '#0b180b'
    }
  }

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
            Visual attack surface topologies, exploit kill-chain sequences, and risk heatmaps — driven by live scan data
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
          1. ATTACK SURFACE TOPOLOGY GRAPH (Dynamic from scan data)
          ───────────────────────────────────────────────────────────── */}
      {activeDiagram === 'topology' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600 }}>
              API Attack Surface — {topologyData.compromisedRouteCount} / {topologyData.totalRoutes} Routes Compromised
            </span>
            <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem' }}>
              <span style={{ color: '#ef4444', background: 'rgba(239, 68, 68, 0.1)', padding: '0.2rem 0.6rem', borderRadius: '4px', border: '1px solid rgba(239, 68, 68, 0.2)' }}>
                🔴 Compromised
              </span>
              <span style={{ color: '#22c55e', background: 'rgba(34, 197, 94, 0.1)', padding: '0.2rem 0.6rem', borderRadius: '4px', border: '1px solid rgba(34, 197, 94, 0.2)' }}>
                🟢 Secure
              </span>
            </div>
          </div>

          <div style={{ background: '#05070d', borderRadius: '12px', border: '1px solid #1e293b', padding: '1rem', overflowX: 'auto' }}>
            <svg viewBox="0 0 900 360" style={{ width: '100%', minWidth: '700px', height: 'auto' }}>
              <defs>
                <filter id="glowCyan" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="4" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <filter id="glowRed" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="5" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
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

              {/* ── NODE 1: Attacker / Scanner ── */}
              <g transform="translate(30, 140)">
                <rect width="110" height="80" rx="8" fill="#1e1b4b" stroke="#6366f1" strokeWidth="2" filter="url(#glowCyan)" />
                <text x="55" y="30" fill="#38bdf8" fontSize="11" fontWeight="700" textAnchor="middle">VAPT SCANNER</text>
                <text x="55" y="48" fill="#94a3b8" fontSize="9" textAnchor="middle">{totalFindings} Findings</text>
                <text x="55" y="62" fill="#94a3b8" fontSize="9" textAnchor="middle">{exploitChains.length} Kill-Chain{exploitChains.length !== 1 ? 's' : ''}</text>
                <circle cx="55" cy="72" r="3" fill="#22c55e" />
              </g>

              {/* Client -> Gateway */}
              <line x1="140" y1="180" x2="220" y2="180" stroke="url(#lineGrad)" strokeWidth="3" strokeDasharray="6,4" />

              {/* ── NODE 2: API Gateway ── */}
              <g transform="translate(220, 130)">
                <rect width="120" height="100" rx="10" fill="#0f172a" stroke="#22d3ee" strokeWidth="2" />
                <text x="60" y="35" fill="#22d3ee" fontSize="12" fontWeight="800" textAnchor="middle">API GATEWAY</text>
                <text x="60" y="55" fill="#94a3b8" fontSize="10" textAnchor="middle">{parsedSpec?.base_url ? new URL(parsedSpec.base_url).host : 'Target'}</text>
                <text x="60" y="72" fill="#f59e0b" fontSize="9" textAnchor="middle">{total} Endpoints</text>
                <text x="60" y="88" fill={topologyData.compromisedRouteCount > 0 ? '#ef4444' : '#22c55e'} fontSize="8" textAnchor="middle">
                  {topologyData.compromisedRouteCount > 0 ? `⚠ ${topologyData.compromisedRouteCount} Vulnerable` : '✓ All Secure'}
                </text>
              </g>

              {/* ── Dynamic Service Cluster Nodes ── */}
              {topologyData.serviceClusters.map((cluster, idx) => {
                const nodeCount = topologyData.serviceClusters.length
                const yPositions = nodeCount <= 1 ? [180] :
                  nodeCount <= 2 ? [110, 250] :
                  nodeCount <= 3 ? [65, 180, 295] :
                  nodeCount <= 4 ? [45, 135, 225, 315] :
                  [35, 105, 180, 255, 325]
                const yPos = yPositions[idx] || 180
                const xPos = 440
                const nodeW = 160
                const nodeH = 72
                const isCompromised = cluster.compromised
                const nodeColor = isCompromised ? sevColor(cluster.worstSeverity) : '#22c55e'
                const nodeBgColor = isCompromised ? sevBg(cluster.worstSeverity) : '#0b180e'

                // Truncate prefix for display
                const displayPrefix = cluster.prefix.length > 18 ? cluster.prefix.slice(0, 18) + '…' : cluster.prefix

                return (
                  <g key={idx}>
                    {/* Gateway -> Service line */}
                    <line
                      x1="340" y1="180"
                      x2={xPos} y2={yPos}
                      stroke={isCompromised ? 'url(#exploitLine)' : '#334155'}
                      strokeWidth={isCompromised ? 2.5 : 1.5}
                    />
                    {/* Service Node */}
                    <g transform={`translate(${xPos}, ${yPos - nodeH / 2})`}>
                      <rect
                        width={nodeW} height={nodeH} rx="8"
                        fill={nodeBgColor}
                        stroke={nodeColor}
                        strokeWidth={isCompromised ? 2 : 1.5}
                        filter={isCompromised && cluster.worstSeverity === 'critical' ? 'url(#glowRed)' : undefined}
                      />
                      <text x={nodeW / 2} y="22" fill={nodeColor} fontSize="10" fontWeight="700" textAnchor="middle">
                        {displayPrefix}/*
                      </text>
                      <text x={nodeW / 2} y="38" fill="#94a3b8" fontSize="9" textAnchor="middle">
                        {cluster.endpoints.length} route{cluster.endpoints.length !== 1 ? 's' : ''}
                      </text>
                      {isCompromised ? (
                        <text x={nodeW / 2} y="54" fill={nodeColor} fontSize="8" fontWeight="600" textAnchor="middle">
                          💥 {cluster.vulnCount} vuln{cluster.vulnCount !== 1 ? 's' : ''} ({cluster.worstSeverity.toUpperCase()})
                        </text>
                      ) : (
                        <text x={nodeW / 2} y="54" fill="#22c55e" fontSize="8" textAnchor="middle">
                          ✓ No vulnerabilities
                        </text>
                      )}
                    </g>
                  </g>
                )
              })}

              {/* ── Database Node ── */}
              {(() => {
                const dbX = 700
                const dbY = 150
                const hasDataLeak = findings.some((f) => /Data Exposure|Excessive/i.test(f.category))
                return (
                  <g>
                    {/* Lines from service clusters to DB */}
                    {topologyData.serviceClusters.map((cluster, idx) => {
                      const nodeCount = topologyData.serviceClusters.length
                      const yPositions = nodeCount <= 1 ? [180] :
                        nodeCount <= 2 ? [110, 250] :
                        nodeCount <= 3 ? [65, 180, 295] :
                        nodeCount <= 4 ? [45, 135, 225, 315] :
                        [35, 105, 180, 255, 325]
                      const yPos = yPositions[idx] || 180
                      return (
                        <line key={`db-line-${idx}`}
                          x1="600" y1={yPos}
                          x2={dbX} y2={dbY + 35}
                          stroke={cluster.compromised ? '#ef444466' : '#334155'}
                          strokeWidth={1.5}
                        />
                      )
                    })}
                    <g transform={`translate(${dbX}, ${dbY})`}>
                      <rect width="130" height="70" rx="8" fill="#0f172a" stroke={hasDataLeak ? '#ef4444' : '#6366f1'} strokeWidth="2" />
                      <text x="65" y="28" fill={hasDataLeak ? '#fca5a5' : '#c7d2fe'} fontSize="12" fontWeight="700" textAnchor="middle">DATA STORE</text>
                      {hasDataLeak ? (
                        <text x="65" y="48" fill="#ef4444" fontSize="9" fontWeight="700" textAnchor="middle">⚠️ DATA LEAKING</text>
                      ) : (
                        <text x="65" y="48" fill="#22c55e" fontSize="9" textAnchor="middle">✓ PROTECTED</text>
                      )}
                    </g>
                  </g>
                )
              })()}

              {/* Legend */}
              <g transform="translate(20, 335)">
                <text fill="#64748b" fontSize="9">
                  {parsedSpec?.title || 'API'} — {total} endpoints scanned, {topologyData.compromisedRouteCount} compromised
                </text>
              </g>
            </svg>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          2. EXPLOIT KILL-CHAIN SEQUENCE FLOWCHART (Dynamic from chains)
          ───────────────────────────────────────────────────────────── */}
      {activeDiagram === 'killchain' && (
        <div>
          <div style={{ marginBottom: '1rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600 }}>
              {exploitChains.length > 0
                ? `${exploitChains.length} Multi-Stage Kill-Chain${exploitChains.length !== 1 ? 's' : ''} Detected`
                : 'No Exploit Chains Detected — Vulnerabilities Are Isolated'
              }
            </span>
          </div>

          {exploitChains.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', background: '#05070d', borderRadius: '10px', border: '1px solid #1e293b' }}>
              <ShieldCheck size={40} style={{ color: '#22c55e', margin: '0 auto 0.75rem' }} />
              <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                No multi-stage exploit chains were identified. Individual findings do not correlate into compound attack paths.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              {exploitChains.map((chain, chainIdx) => {
                const chainColors = [
                  { border: '#ef4444', stepBg: '#dc2626', arrowColor: '#f87171' },
                  { border: '#f97316', stepBg: '#ea580c', arrowColor: '#fb923c' },
                  { border: '#8b5cf6', stepBg: '#7c3aed', arrowColor: '#a78bfa' },
                ]
                const colors = chainColors[chainIdx % chainColors.length]

                return (
                  <div key={chain.id} style={{ background: '#05070d', borderRadius: '10px', border: '1px solid #1e293b', padding: '1.25rem' }}>
                    {/* Chain Header */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                      <div>
                        <strong style={{ color: colors.arrowColor, fontSize: '0.95rem' }}>
                          {chain.id}: {chain.title}
                        </strong>
                        <p style={{ color: '#64748b', fontSize: '0.8rem', marginTop: '0.15rem' }}>{chain.impact}</p>
                      </div>
                      <span className={`badge badge-${chain.severity}`}>
                        CVSS {chain.composite_cvss}
                      </span>
                    </div>

                    {/* Chain Steps */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {chain.steps.map((step, stepIdx) => (
                        <React.Fragment key={stepIdx}>
                          <div style={{
                            display: 'flex', alignItems: 'center', gap: '1rem',
                            padding: '0.85rem 1rem', borderRadius: '8px',
                            borderLeft: `4px solid ${colors.border}`,
                            border: '1px solid #1e293b', background: '#0a0e1a',
                          }}>
                            <div style={{
                              width: '32px', height: '32px', borderRadius: '50%',
                              background: colors.stepBg, color: '#fff',
                              display: 'flex', alignItems: 'center', justifyContent: 'center',
                              fontWeight: 800, fontSize: '0.85rem', flexShrink: 0,
                            }}>
                              {step.num}
                            </div>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <strong style={{ color: '#e2e8f0', fontSize: '0.88rem' }}>{step.name}</strong>
                                <span style={{
                                  fontSize: '0.7rem', color: colors.arrowColor,
                                  background: `${colors.border}15`, padding: '0.15rem 0.5rem',
                                  borderRadius: '4px', border: `1px solid ${colors.border}30`,
                                }}>
                                  {step.tag}
                                </span>
                              </div>
                              <p style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '0.2rem' }}>{step.desc}</p>
                            </div>
                          </div>

                          {/* Arrow between steps */}
                          {stepIdx < chain.steps.length - 1 && (
                            <div style={{ display: 'flex', justifyContent: 'center', margin: '-0.25rem 0' }}>
                              <ArrowRight size={14} style={{ color: colors.arrowColor, transform: 'rotate(90deg)' }} />
                            </div>
                          )}
                        </React.Fragment>
                      ))}
                    </div>

                    {/* Remediation */}
                    <div style={{
                      marginTop: '0.75rem', padding: '0.6rem 0.85rem',
                      background: 'rgba(34, 197, 94, 0.06)', borderRadius: '6px',
                      border: '1px solid rgba(34, 197, 94, 0.15)', fontSize: '0.8rem', color: '#86efac',
                    }}>
                      <strong>Remediation:</strong> {chain.remediation}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          3. RISK HEATMAP & SEVERITY BAR VISUALIZER (Dynamic from findings)
          ───────────────────────────────────────────────────────────── */}
      {activeDiagram === 'heatmap' && (
        <div>
          <div style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', color: '#94a3b8', fontWeight: 600 }}>
              OWASP API Security Top 10 — {totalFindings} Total Finding{totalFindings !== 1 ? 's' : ''} Across {heatmapData.length} Categor{heatmapData.length !== 1 ? 'ies' : 'y'}
            </span>
          </div>

          {heatmapData.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', background: '#05070d', borderRadius: '10px', border: '1px solid #1e293b' }}>
              <ShieldCheck size={40} style={{ color: '#22c55e', margin: '0 auto 0.75rem' }} />
              <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
                No OWASP API Top 10 vulnerabilities detected in this scan.
              </p>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
              {heatmapData.map((item, idx) => {
                const barPct = Math.round((item.count / maxCatCount) * 100)
                return (
                  <div key={idx} style={{ background: '#05070d', padding: '1rem', borderRadius: '8px', border: '1px solid #1e293b' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                      <strong style={{ fontSize: '0.85rem', color: '#f1f5f9' }}>{item.label}</strong>
                      <span className={`badge badge-${item.sev}`}>{item.count} Detected</span>
                    </div>
                    {/* Progress bar */}
                    <div style={{ width: '100%', height: '8px', background: '#1e293b', borderRadius: '4px', overflow: 'hidden' }}>
                      <div
                        style={{
                          width: `${barPct}%`,
                          height: '100%',
                          background: item.sev === 'critical' ? 'linear-gradient(90deg, #ef4444, #dc2626)' : item.sev === 'high' ? 'linear-gradient(90deg, #f97316, #ea580c)' : 'linear-gradient(90deg, #eab308, #ca8a04)',
                          borderRadius: '4px',
                          transition: 'width 0.5s ease',
                        }}
                      />
                    </div>
                    {/* Affected endpoints */}
                    <div style={{ marginTop: '0.4rem', fontSize: '0.75rem', color: '#64748b' }}>
                      Endpoints: {[...new Set(item.matched.map((f) => f.endpoint))].slice(0, 3).join(', ')}
                      {[...new Set(item.matched.map((f) => f.endpoint))].length > 3 ? ` +${[...new Set(item.matched.map((f) => f.endpoint))].length - 3} more` : ''}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          4. SECURITY POSTURE RADAR & GAUGE SCORECARD (Dynamic from findings)
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
              <text x="100" y="90" fontSize="32" fontWeight="800" fill={scorecardMetrics.gradeColor} textAnchor="middle">
                {securityScore}
              </text>
              <text x="100" y="110" fontSize="11" fill="#94a3b8" textAnchor="middle">
                / 100 Security Index
              </text>
            </svg>
            <div style={{ marginTop: '0.75rem' }}>
              <span style={{
                fontSize: '0.85rem', fontWeight: 700,
                color: scorecardMetrics.gradeColor,
                background: `${scorecardMetrics.gradeColor}15`,
                padding: '0.3rem 0.8rem', borderRadius: '6px',
                border: `1px solid ${scorecardMetrics.gradeColor}30`,
              }}>
                GRADE {scorecardMetrics.grade} — {scorecardMetrics.gradeLabel}
              </span>
            </div>
          </div>

          {/* Metric Breakdown Cards */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Attack Surface Exposure</span>
              <strong style={{ color: scorecardMetrics.exposurePct > 50 ? '#ef4444' : scorecardMetrics.exposurePct > 20 ? '#f59e0b' : '#22c55e' }}>
                {scorecardMetrics.exposurePct > 0 ? `${scorecardMetrics.exposurePct}% Routes Flawed (${scorecardMetrics.flawedRoutes}/${total})` : 'No Routes Flawed'}
              </strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Peak Exploitability</span>
              <strong style={{ color: parseFloat(scorecardMetrics.maxCvss) >= 9.0 ? '#ef4444' : parseFloat(scorecardMetrics.maxCvss) >= 7.0 ? '#f97316' : '#f59e0b' }}>
                {scorecardMetrics.maxCvss} / 10.0 ({parseFloat(scorecardMetrics.maxCvss) >= 9.0 ? 'CRITICAL' : parseFloat(scorecardMetrics.maxCvss) >= 7.0 ? 'HIGH' : parseFloat(scorecardMetrics.maxCvss) >= 4.0 ? 'MEDIUM' : 'LOW'})
              </strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Confidentiality Threat</span>
              <strong style={{ color: scorecardMetrics.confColor }}>{scorecardMetrics.confThreat}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Integrity Threat</span>
              <strong style={{ color: scorecardMetrics.intColor }}>{scorecardMetrics.intThreat}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem 1rem', background: '#05070d', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <span style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Availability Threat</span>
              <strong style={{ color: scorecardMetrics.availColor }}>{scorecardMetrics.availThreat}</strong>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
