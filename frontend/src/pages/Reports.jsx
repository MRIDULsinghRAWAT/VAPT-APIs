import React, { useState, useEffect } from 'react'
import { FileText, Download, ShieldAlert, GitMerge, CheckCircle, BarChart3 } from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { listScans } from '../services/api'
import { deriveExploitChains } from '../utils/exploitChain'

export default function Reports() {
  const { scans: contextScans, latestFindings } = useAppContext()
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)

  useEffect(() => {
    async function loadScans() {
      try {
        const backendScans = await listScans()
        const combined = [...contextScans, ...(backendScans || [])]
        const unique = Array.from(new Map(combined.map((s) => [s.id, s])).values())
        setScans(unique)
        if (unique.length > 0 && !selectedScan) setSelectedScan(unique[0])
      } catch {
        setScans(contextScans)
        if (contextScans.length > 0 && !selectedScan) setSelectedScan(contextScans[0])
      }
    }
    loadScans()
  }, [contextScans])

  const handleExportPentestReport = (scan) => {
    const findingsList = scan.findings?.length ? scan.findings : latestFindings || []
    const exploitChains = deriveExploitChains(findingsList)

    const criticalCount = findingsList.filter((f) => f.severity === 'critical').length
    const highCount = findingsList.filter((f) => f.severity === 'high').length
    const mediumCount = findingsList.filter((f) => f.severity === 'medium').length

    const reportHtml = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>API Penetration Testing Report — ${scan.name}</title>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono&display=swap');
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body { font-family: 'Inter', sans-serif; color: #0f172a; line-height: 1.6; padding: 40px; background: #ffffff; }
          
          /* Cover & Header */
          .header { border-bottom: 4px solid #6366f1; padding-bottom: 24px; margin-bottom: 32px; }
          .title { font-size: 28px; font-weight: 800; color: #0f172a; }
          .subtitle { font-size: 14px; color: #64748b; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
          
          .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid #e2e8f0; }
          .meta-item strong { display: block; font-size: 11px; text-transform: uppercase; color: #64748b; margin-bottom: 2px; }
          .meta-item span { font-size: 14px; font-weight: 600; color: #1e293b; }

          /* Risk Summary Matrix */
          .section-title { font-size: 18px; font-weight: 700; color: #1e293b; margin: 32px 0 16px; border-left: 4px solid #6366f1; padding-left: 10px; }
          .stats-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
          .stat-box { padding: 16px; border-radius: 8px; text-align: center; border: 1px solid #e2e8f0; }
          .stat-box.crit { background: #fef2f2; border-color: #fecaca; color: #dc2626; }
          .stat-box.high { background: #fff7ed; border-color: #fed7aa; color: #ea580c; }
          .stat-box.med { background: #fefce8; border-color: #fef08a; color: #ca8a04; }
          .stat-box.total { background: #f1f5f9; border-color: #cbd5e1; color: #0f172a; }
          .stat-val { font-size: 26px; font-weight: 800; }
          .stat-lbl { font-size: 11px; text-transform: uppercase; font-weight: 600; margin-top: 2px; }

          /* Exploit Chains */
          .chain-box { background: #0f172a; color: #f8fafc; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 6px solid #ef4444; }
          .chain-title { font-size: 16px; font-weight: 700; color: #f87171; display: flex; justify-content: space-between; }
          .chain-step { background: #1e293b; padding: 10px 14px; border-radius: 6px; margin: 8px 0; border: 1px solid #334155; font-size: 13px; }
          
          /* Findings */
          .finding { border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 24px; page-break-inside: avoid; }
          .finding-hdr { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
          .badge { padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
          .badge-critical { background: #fee2e2; color: #991b1b; }
          .badge-high { background: #ffedd5; color: #9a3412; }
          .badge-medium { background: #fef9c3; color: #854d0e; }
          
          code, pre { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
          pre { background: #0f172a; color: #38bdf8; padding: 14px; border-radius: 6px; overflow-x: auto; margin: 10px 0; }
          .remediation { background: #f0fdf4; border-left: 4px solid #22c55e; padding: 14px; border-radius: 4px; color: #14532d; font-size: 13px; margin-top: 10px; }

          @media print {
            body { padding: 0; }
            .finding { page-break-inside: avoid; }
          }
        </style>
      </head>
      <body>
        <div class="header">
          <div class="title">🛡️ Web API Penetration Testing &amp; Vulnerability Assessment Report</div>
          <div class="subtitle">Automated Security Audit Deliverable • OWASP API Top 10 Framework</div>
        </div>

        <div class="meta-grid">
          <div class="meta-item">
            <strong>Target Base URL</strong>
            <span>${scan.target_url}</span>
          </div>
          <div class="meta-item">
            <strong>Assessment Name</strong>
            <span>${scan.name}</span>
          </div>
          <div class="meta-item">
            <strong>Execution Timestamp</strong>
            <span>${new Date(scan.created_at).toLocaleString()}</span>
          </div>
          <div class="meta-item">
            <strong>Overall Status</strong>
            <span style="color: #dc2626;">VULNERABILITIES DETECTED</span>
          </div>
        </div>

        <div class="section-title">1. Executive Risk Summary</div>
        <div class="stats-cards">
          <div class="stat-box crit">
            <div class="stat-val">${criticalCount}</div>
            <div class="stat-lbl">Critical Risk</div>
          </div>
          <div class="stat-box high">
            <div class="stat-val">${highCount}</div>
            <div class="stat-lbl">High Risk</div>
          </div>
          <div class="stat-box med">
            <div class="stat-val">${mediumCount}</div>
            <div class="stat-lbl">Medium Risk</div>
          </div>
          <div class="stat-box total">
            <div class="stat-val">${findingsList.length}</div>
            <div class="stat-lbl">Total Flaws</div>
          </div>
        </div>

        <div class="section-title">2. Compound Exploit Chaining &amp; Kill Paths</div>
        <p style="font-size: 13px; color: #475569; margin-bottom: 16px;">
          The engine correlated isolated findings into multi-stage attack chains demonstrating full real-world impact.
        </p>

        ${exploitChains
          .map(
            (c) => `
          <div class="chain-box">
            <div class="chain-title">
              <span>🔥 ${c.title}</span>
              <span>Composite CVSS: ${c.composite_cvss}</span>
            </div>
            <p style="font-size: 13px; color: #cbd5e1; margin: 8px 0 12px;"><strong>Impact:</strong> ${c.impact}</p>
            ${c.steps
              .map(
                (st) => `
              <div class="chain-step">
                <strong>Stage ${st.num} [${st.tag}]:</strong> ${st.name} — <span style="color: #94a3b8;">${st.desc}</span>
              </div>
            `
              )
              .join('')}
            <div style="font-size: 12px; color: #86efac; margin-top: 8px;">
              <strong>Strategic Mitigation:</strong> ${c.remediation}
            </div>
          </div>
        `
          )
          .join('')}

        <div class="section-title">3. Detailed Technical Findings &amp; PoC Evidence</div>

        ${findingsList
          .map(
            (f, idx) => `
          <div class="finding">
            <div class="finding-hdr">
              <div>
                <span style="font-size: 11px; color: #64748b; font-weight: 700;">#FINDING-0${idx + 1}</span>
                <h3 style="font-size: 16px; color: #0f172a; margin-top: 2px;">${f.title}</h3>
              </div>
              <span class="badge badge-${f.severity}">${f.severity} (CVSS ${f.cvss_score || 'N/A'})</span>
            </div>

            <p style="font-size: 13px; color: #334155; margin-bottom: 8px;">
              <strong>Affected Endpoint:</strong> <code>${f.method} ${f.endpoint}</code> | <strong>Category:</strong> ${f.category}
            </p>
            <p style="font-size: 13px; color: #475569; margin-bottom: 12px;">${f.description}</p>

            <h4 style="font-size: 12px; text-transform: uppercase; color: #64748b; margin-top: 10px;">Proof of Concept (PoC Evidence)</h4>
            <pre>${f.evidence || 'N/A'}</pre>

            <h4 style="font-size: 12px; text-transform: uppercase; color: #64748b; margin-top: 10px;">Remediation &amp; Patch Code</h4>
            <div class="remediation">
              <strong>Developer Fix:</strong> ${f.remediation || 'Enforce strict authorization and DTO validation.'}
            </div>
          </div>
        `
          )
          .join('')}

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #cbd5e1; font-size: 11px; color: #94a3b8; text-align: center;">
          Generated by Automated VAPT for Web APIs Framework • Confidential Client Deliverable
        </div>
      </body>
      </html>
    `

    const blob = new Blob([reportHtml], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `VAPT_Report_${scan.name.replace(/\s+/g, '_')}.html`
    a.click()
  }

  return (
    <div>
      <div className="page-header">
        <h1>Reports &amp; Pentest Deliverables</h1>
        <p>Review completed scans, inspect compound attack paths, and export client-ready reports</p>
      </div>

      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h3 className="card-title">Completed Security Assessments</h3>
        </div>

        {scans.length > 0 ? (
          <div className="table-container" style={{ border: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>Scan Name</th>
                  <th>Target URL</th>
                  <th>Status</th>
                  <th>Endpoints</th>
                  <th>Findings</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <strong>{s.name}</strong>
                    </td>
                    <td>
                      <code>{s.target_url}</code>
                    </td>
                    <td>
                      <span className="badge badge-low">{s.status}</span>
                    </td>
                    <td>{s.total_endpoints}</td>
                    <td>
                      <span
                        style={{
                          color: s.total_findings > 0 ? 'var(--severity-critical)' : 'var(--severity-low)',
                          fontWeight: 700,
                        }}
                      >
                        {s.total_findings} Flaws
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-primary"
                        style={{ fontSize: '0.75rem', padding: '0.35rem 0.75rem' }}
                        onClick={() => handleExportPentestReport(s)}
                      >
                        <Download size={14} /> Export Pentest Report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <FileText size={48} />
            <h3>No completed assessments yet</h3>
            <p>Run an assessment from the Scan Console to generate full audit reports.</p>
          </div>
        )}
      </div>
    </div>
  )
}
