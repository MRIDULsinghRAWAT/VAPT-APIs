import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, FileJson, Link as LinkIcon, Loader2, CheckCircle, AlertCircle } from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { parseSpec } from '../utils/specParser'

export default function SpecUpload() {
  const [mode, setMode] = useState('file')
  const [file, setFile] = useState(null)
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const fileInput = useRef(null)
  const navigate = useNavigate()
  const { setParsedSpec } = useAppContext()

  const handleFileDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const dropped = e.dataTransfer.files[0]
    if (dropped) {
      setFile(dropped)
      setError(null)
    }
  }

  const handleFileSelect = (e) => {
    if (e.target.files[0]) {
      setFile(e.target.files[0])
      setError(null)
    }
  }

  const handleSubmit = async () => {
    setLoading(true)
    setError(null)

    try {
      let rawContent = ''

      if (mode === 'file' && file) {
        rawContent = await file.text()
      } else if (mode === 'url' && url) {
        // Try backend first, fall back to fetch
        try {
          const resp = await fetch(url)
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
          rawContent = await resp.text()
        } catch (fetchErr) {
          throw new Error(`Failed to fetch spec from URL: ${fetchErr.message}`)
        }
      }

      if (!rawContent.trim()) {
        throw new Error('Empty spec file')
      }

      // Parse the spec client-side
      const parsed = parseSpec(rawContent, file?.name || 'remote_spec')
      setParsedSpec(parsed)

      // Navigate to endpoint map
      navigate('/endpoints')
    } catch (err) {
      setError(err.message || 'Failed to parse spec')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Upload API Spec</h1>
        <p>Upload an OpenAPI/Swagger spec to map the attack surface</p>
      </div>

      {/* Mode Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
        <button
          className={`btn ${mode === 'file' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => { setMode('file'); setError(null) }}
        >
          <Upload size={16} />
          Upload File
        </button>
        <button
          className={`btn ${mode === 'url' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => { setMode('url'); setError(null) }}
        >
          <LinkIcon size={16} />
          Fetch from URL
        </button>
      </div>

      <div className="card">
        {mode === 'file' ? (
          <div
            className={`upload-area ${dragOver ? 'dragover' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleFileDrop}
            onClick={() => fileInput.current?.click()}
          >
            <input
              ref={fileInput}
              type="file"
              accept=".json,.yaml,.yml"
              onChange={handleFileSelect}
              style={{ display: 'none' }}
            />
            <FileJson size={48} style={{ color: 'var(--accent-primary)', marginBottom: '1rem' }} />
            {file ? (
              <div>
                <h3 style={{ color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                  <CheckCircle size={20} />
                  {file.name}
                </h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  {(file.size / 1024).toFixed(1)} KB — Click or drop to replace
                </p>
              </div>
            ) : (
              <div>
                <h3>Drop your API spec here</h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  Supports OpenAPI 3.x and Swagger 2.0 — JSON or YAML
                </p>
              </div>
            )}
          </div>
        ) : (
          <div className="form-group">
            <label className="form-label">Spec URL</label>
            <input
              type="url"
              className="form-input"
              placeholder="https://petstore3.swagger.io/api/v3/openapi.json"
              value={url}
              onChange={(e) => { setUrl(e.target.value); setError(null) }}
            />
            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '0.5rem' }}>
              Most APIs expose their spec at <code>/swagger.json</code> or <code>/openapi.json</code>
            </p>
          </div>
        )}

        {/* Error message */}
        {error && (
          <div style={{
            marginTop: '1rem',
            padding: '0.75rem 1rem',
            background: 'var(--severity-critical-bg)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--severity-critical)',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}>
            <AlertCircle size={16} />
            {error}
          </div>
        )}

        <div style={{ marginTop: '1.5rem', display: 'flex', gap: '0.75rem' }}>
          <button
            className="btn btn-primary"
            onClick={handleSubmit}
            disabled={loading || (mode === 'file' ? !file : !url)}
            style={{ opacity: (loading || (mode === 'file' ? !file : !url)) ? 0.5 : 1 }}
          >
            {loading ? (
              <>
                <Loader2 size={16} className="pulse" />
                Parsing...
              </>
            ) : (
              <>Parse & Map Endpoints</>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
