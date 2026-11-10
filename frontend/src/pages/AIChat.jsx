import React, { useState, useRef, useEffect } from 'react'
import {
  MessageSquare,
  Send,
  Bot,
  User,
  Loader2,
  ShieldAlert,
  Sparkles,
  Trash2,
  Info,
} from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { sendChatMessage } from '../services/aiApi'

export default function AIChat() {
  const { latestFindings, scans } = useAppContext()
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [includeScanContext, setIncludeScanContext] = useState(true)
  const messagesEndRef = useRef(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const scanContext = includeScanContext && latestFindings.length > 0
    ? {
        target_url: scans?.[0]?.target_url || 'Unknown',
        findings: latestFindings.map((f) => ({
          title: f.title,
          category: f.category,
          severity: f.severity,
          cvss_score: f.cvss_score,
          endpoint: f.endpoint,
          method: f.method,
          description: f.description,
        })),
      }
    : null

  const handleSend = async () => {
    const trimmed = input.trim()
    if (!trimmed || isLoading) return

    const userMsg = { role: 'user', content: trimmed }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setIsLoading(true)

    try {
      const history = messages.map((m) => ({ role: m.role, content: m.content }))
      const data = await sendChatMessage(trimmed, scanContext, history)
      setMessages((prev) => [...prev, { role: 'assistant', content: data.response }])
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ **Error:** ${err.response?.data?.detail || err.message}\n\nMake sure your backend is running and \`GEMINI_API_KEY\` is set in \`.env\`.`,
        },
      ])
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const quickPrompts = [
    'Which endpoint is the most critical risk?',
    'Explain the BOLA finding in simple terms',
    'Write a bug bounty report for the highest severity finding',
    'Summarize all findings for a non-technical manager',
    'What should we fix first and why?',
  ]

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <h1>AI Security Chat</h1>
          <span
            className="badge badge-info"
            style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <Sparkles size={12} /> GEMINI POWERED
          </span>
        </div>
        <p>Ask questions about your scan results, get security advice, or generate reports</p>
      </div>

      {/* Scan Context Indicator */}
      <div
        className="card"
        style={{
          marginBottom: '1rem',
          padding: '0.75rem 1.25rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
          <Info size={16} style={{ color: 'var(--accent-cyan)' }} />
          {latestFindings.length > 0 ? (
            <span style={{ color: 'var(--text-secondary)' }}>
              <strong style={{ color: 'var(--accent-cyan)' }}>{latestFindings.length} findings</strong> loaded
              as context from your latest scan
            </span>
          ) : (
            <span style={{ color: 'var(--text-muted)' }}>
              No scan results loaded — run a scan first for contextual answers, or ask general security questions
            </span>
          )}
        </div>
        {latestFindings.length > 0 && (
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              fontSize: '0.8rem',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
            }}
          >
            <input
              type="checkbox"
              checked={includeScanContext}
              onChange={(e) => setIncludeScanContext(e.target.checked)}
            />
            Include scan context
          </label>
        )}
      </div>

      {/* Chat Window */}
      <div
        className="card"
        style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 340px)', minHeight: '450px' }}
      >
        {/* Messages Area */}
        <div
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '1.25rem',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
          }}
        >
          {messages.length === 0 ? (
            <div
              style={{
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '1.5rem',
                color: 'var(--text-muted)',
              }}
            >
              <ShieldAlert size={48} style={{ opacity: 0.3 }} />
              <div style={{ textAlign: 'center' }}>
                <h3 style={{ color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                  Talk to Your Scan Results
                </h3>
                <p style={{ fontSize: '0.85rem', maxWidth: '500px' }}>
                  Ask anything about your vulnerabilities, request explanations, generate reports,
                  or get remediation advice.
                </p>
              </div>

              {/* Quick Prompt Suggestions */}
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: '0.5rem',
                  justifyContent: 'center',
                  maxWidth: '700px',
                }}
              >
                {quickPrompts.map((prompt) => (
                  <button
                    key={prompt}
                    className="btn btn-secondary"
                    style={{
                      fontSize: '0.78rem',
                      padding: '0.4rem 0.75rem',
                      borderRadius: '999px',
                    }}
                    onClick={() => {
                      setInput(prompt)
                    }}
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((msg, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  gap: '0.75rem',
                  alignItems: 'flex-start',
                  flexDirection: msg.role === 'user' ? 'row-reverse' : 'row',
                }}
              >
                {/* Avatar */}
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    background:
                      msg.role === 'user'
                        ? 'var(--gradient-primary)'
                        : 'linear-gradient(135deg, #10b981, #06b6d4)',
                  }}
                >
                  {msg.role === 'user' ? (
                    <User size={16} color="#fff" />
                  ) : (
                    <Bot size={16} color="#fff" />
                  )}
                </div>

                {/* Message Bubble */}
                <div
                  style={{
                    maxWidth: '75%',
                    padding: '0.85rem 1.1rem',
                    borderRadius: 'var(--radius-lg)',
                    fontSize: '0.88rem',
                    lineHeight: '1.6',
                    whiteSpace: 'pre-wrap',
                    background:
                      msg.role === 'user' ? 'rgba(99, 102, 241, 0.12)' : 'var(--bg-card)',
                    border: `1px solid ${
                      msg.role === 'user' ? 'rgba(99, 102, 241, 0.25)' : 'var(--border-subtle)'
                    }`,
                    color: 'var(--text-primary)',
                  }}
                >
                  {msg.content}
                </div>
              </div>
            ))
          )}

          {isLoading && (
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  background: 'linear-gradient(135deg, #10b981, #06b6d4)',
                }}
              >
                <Bot size={16} color="#fff" />
              </div>
              <div
                style={{
                  padding: '0.85rem 1.1rem',
                  borderRadius: 'var(--radius-lg)',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  color: 'var(--text-muted)',
                  fontSize: '0.85rem',
                }}
              >
                <Loader2 size={16} className="pulse" />
                Analyzing...
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div
          style={{
            borderTop: '1px solid var(--border-subtle)',
            padding: '1rem 1.25rem',
            display: 'flex',
            gap: '0.75rem',
            alignItems: 'flex-end',
          }}
        >
          {messages.length > 0 && (
            <button
              className="btn btn-secondary"
              style={{ padding: '0.6rem', flexShrink: 0 }}
              onClick={() => setMessages([])}
              title="Clear chat"
            >
              <Trash2 size={18} />
            </button>
          )}

          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about your scan results..."
            rows={1}
            style={{
              flex: 1,
              background: 'var(--bg-primary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              padding: '0.7rem 1rem',
              color: 'var(--text-primary)',
              fontSize: '0.9rem',
              fontFamily: 'inherit',
              resize: 'none',
              outline: 'none',
              minHeight: '42px',
              maxHeight: '120px',
            }}
          />

          <button
            className="btn btn-primary"
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            style={{ padding: '0.6rem 1rem', flexShrink: 0 }}
          >
            {isLoading ? <Loader2 size={18} className="pulse" /> : <Send size={18} />}
          </button>
        </div>
      </div>
    </div>
  )
}

