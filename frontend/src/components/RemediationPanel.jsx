import React, { useState } from 'react'
import { Sparkles, Loader2, X, Code, ShieldCheck, AlertTriangle, BookOpen, FileWarning } from 'lucide-react'
import { getAIRemediation } from '../services/aiApi'

/**
 * AI Remediation Panel — slides open when user clicks "AI Fix" on a finding.
 *
 * Props:
 *   finding  - the vulnerability finding object
 *   onClose  - callback to close the panel
 */
export default function RemediationPanel({ finding, onClose }) {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleGenerate = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getAIRemediation({
        title: finding.title,
        category: finding.category,
        severity: finding.severity,
        cvss_score: finding.cvss_score,
        endpoint: finding.endpoint,
        method: finding.method,
        description: finding.description,
        evidence: finding.evidence || '',
      })
      setResult(data)
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setLoading(false)
    }
  }

  // Auto-generate on mount
  React.useEffect(() => {
    handleGenerate()
  }, [])

  return (
    <div
      style={{
        background: '#080c18',
        border: '1px solid rgba(99, 102, 241, 0.3)',
        borderRadius: 'var(--radius-lg)',
        padding: '1.5rem',
        marginTop: '0.75rem',
        position: 'relative',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Sparkles size={18} style={{ color: '#818cf8' }} />
          <strong style={{ fontSize: '0.95rem', color: '#c7d2fe' }}>AI-Powered Remediation</strong>
          <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>GEMINI</span>
        </div>
        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: '0.25rem',
          }}
        >
          <X size={18} />
        </button>
      </div>

      {/* Loading State */}
      {loading && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.75rem',
            padding: '2rem',
            color: 'var(--accent-cyan)',
            fontSize: '0.9rem',
          }}
        >
          <Loader2 size={20} className="pulse" />
          Analyzing vulnerability with Gemini AI...
        </div>
      )}

      {/* Error State */}
      {error && (
        <div
          style={{
            background: 'rgba(239, 68, 68, 0.08)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 'var(--radius-md)',
            padding: '0.75rem 1rem',
            color: 'var(--severity-high)',
            fontSize: '0.85rem',
          }}
        >
          ⚠️ {error}
          <button
            className="btn btn-secondary"
            style={{ marginLeft: '1rem', fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
            onClick={handleGenerate}
          >
            Retry
          </button>
        </div>
      )}

      {/* Result */}
      {result && !loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Explanation */}
          <Section icon={<AlertTriangle size={16} />} title="What's Going On" color="#fbbf24">
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', lineHeight: '1.7' }}>
              {result.explanation}
            </p>
          </Section>

          {/* Risk Analysis */}
          <Section icon={<FileWarning size={16} />} title="Risk Analysis" color="#f87171">
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', lineHeight: '1.7' }}>
              {result.risk_analysis}
            </p>
          </Section>

          {/* Fix Code */}
          <Section icon={<Code size={16} />} title="Fix Code" color="#34d399">
            <pre
              style={{
                background: '#05070d',
                padding: '0.85rem 1rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-subtle)',
                color: '#6ee7b7',
                fontSize: '0.78rem',
                whiteSpace: 'pre-wrap',
                overflowX: 'auto',
                lineHeight: '1.6',
              }}
            >
              {result.fix_code}
            </pre>
          </Section>

          {/* OWASP Reference + CWE */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <Section icon={<BookOpen size={16} />} title="OWASP Reference" color="#60a5fa">
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>{result.owasp_reference}</p>
            </Section>
            <Section icon={<ShieldCheck size={16} />} title="CWE ID" color="#c084fc">
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>{result.cwe_id}</p>
            </Section>
          </div>
        </div>
      )}
    </div>
  )
}

/** Small helper for consistent section styling */
function Section({ icon, title, color, children }) {
  return (
    <div
      style={{
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-md)',
        padding: '0.85rem 1rem',
      }}
    >
      <h4
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.4rem',
          color,
          fontSize: '0.75rem',
          textTransform: 'uppercase',
          marginBottom: '0.5rem',
          letterSpacing: '0.03em',
        }}
      >
        {icon}
        {title}
      </h4>
      {children}
    </div>
  )
}

