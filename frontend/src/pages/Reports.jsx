import React, { useState, useEffect } from 'react'
import { FileText, Download, ShieldCheck, AlertTriangle, ShieldAlert } from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { listScans } from '../services/api'

export default function Reports() {
  const { scans: contextScans, latestFindings } = useAppContext()
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)

  useEffect(() => {
    async function loadScans() {
      try {
        const backendScans = await listScans()
        const combined = [...contextScans, ...(backendScans || [])]
        // Deduplicate by ID
        const unique = Array.from(new Map(combined.map((s) => [s.id, s])).values())
        setScans(unique)
        if (unique.length > 0) setSelectedScan(unique[0])
      } catch {
        setScans(contextScans)
        if (contextScans.length > 0) setSelectedScan(contextScans[0])
      }
    }
    loadScans()
  }, [contextScans])

  const handleExportHTML = (scan) => {
    const findingsList = scan.findings || latestFindings || []
    const reportHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>${scan.name} — Pentest Report</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; color: #1e293b; line-height: 1.6; }
          h1 { color: #0f172a; border-bottom: 3px solid #6366f1; padding-bottom: 8px; }
          .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
          .critical { background: #fee2e2; color: #b91c1c; }
          .high { background: #ffedd5; color: #c2410c; }
          .medium { background: #fef9c3; color: #a16207; }
          .finding { border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
          pre { background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
          .remediation { background: #f0fdf4; color: #166534; padding: 12px; border-radius: 6px; border-left: 4px solid #22c55e; }
        </style>
      </head>
      <body>
        <h1>🛡️ API Penetration Testing & Vulnerability Assessment Report</h1>
        <p><strong>Target API:</strong> ${scan.target_url}</p>
        <p><strong>Assessment Date:</strong> ${new Date(scan.created_at).toLocaleString()}</p>
        <p><strong>Total Findings:</strong> ${findingsList.length} Vulnerabilities Identified</p>
        <hr style="margin: 24px 0; border: 0; border-top: 1px solid #cbd5e1;" />
        <h2>Vulnerability Findings Summary</h2>
        ${findingsList
          .map(
            (f) => `
          <div class="finding">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <h3 style="margin: 0;">${f.title}</h3>
              <span class="badge ${f.severity}">${f.severity} (CVSS: ${f.cvss_score || 'N/A'})</span>
            </div>
            <p style="margin-top: 10px;"><strong>Endpoint:</strong> <code>${f.method} ${f.endpoint}</code></p>
            <p>${f.description}</p>
            <h4>Proof of Concept (PoC Evidence)</h4>
            <pre>${f.evidence || 'N/A'}</pre>
            <h4>Remediation Guidance</h4>
            <div class="remediation">${f.remediation || 'Apply standard access control and schema validation.'}</div>
          </div>
        `
          )
          .join('')}
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
        <h1>Reports &amp; Findings</h1>
        <p>Review completed vulnerability scans and export client-ready pentest reports</p>
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
                        {s.total_findings}
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary"
                        style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                        onClick={() => handleExportHTML(s)}
                      >
                        <Download size={14} /> Export HTML Report
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
            <p>Run a scan from the Scan Console to generate full audit reports.</p>
          </div>
        )}
      </div>
    </div>
  )
}
