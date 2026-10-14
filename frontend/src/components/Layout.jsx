import { NavLink, Outlet } from 'react-router-dom'
import {
  LayoutDashboard,
  Upload,
  Map,
  Play,
  FileText,
  Shield,
  Zap,
} from 'lucide-react'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/upload', icon: Upload, label: 'Upload Spec' },
  { to: '/endpoints', icon: Map, label: 'Endpoint Map' },
  { to: '/scan', icon: Play, label: 'Scan Console' },
  { to: '/reports', icon: FileText, label: 'Reports' },
]

export default function Layout() {
  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <div style={{
              width: '32px',
              height: '32px',
              background: 'var(--primary-accent)',
              borderRadius: 'var(--radius-sm)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Shield size={18} style={{ color: '#0a0a0a' }} />
            </div>
            <h1>VAPT Engine</h1>
          </div>
          <p className="subtitle">API Security Testing</p>
        </div>

        <nav className="sidebar-nav">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'active' : ''}`
              }
            >
              <Icon size={18} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div style={{
          padding: '1rem 1.25rem',
          borderTop: '1px solid var(--border-subtle)',
        }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginBottom: '0.5rem',
          }}>
            <Zap size={12} style={{ color: 'var(--primary-accent)' }} />
            <span style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '0.65rem',
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.1em',
            }}>
              v0.1.0 — Phase 1
            </span>
          </div>
          <div style={{
            fontSize: '0.72rem',
            color: 'var(--text-muted)',
            lineHeight: 1.4,
          }}>
            OWASP API Top 10 Pentest Framework
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  )
}
