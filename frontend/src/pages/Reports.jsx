import { FileText, Download } from 'lucide-react'

export default function Reports() {
  return (
    <div>
      <div className="page-header">
        <h1>Reports</h1>
        <p>View and export pentest-style vulnerability reports</p>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Scan Reports</h3>
          <button className="btn btn-secondary" disabled>
            <Download size={16} />
            Export PDF
          </button>
        </div>

        <div className="empty-state">
          <FileText size={48} />
          <h3>No reports generated yet</h3>
          <p>Complete a scan to generate a professional pentest report with CVSS scores and remediation guidance.</p>
        </div>
      </div>
    </div>
  )
}
