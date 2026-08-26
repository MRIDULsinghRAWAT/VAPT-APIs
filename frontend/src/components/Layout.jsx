import { NavLink, Outlet } from 'react-router-dom'
import {
  LayoutDashboard,
  Upload,
  Map,
  Play,
  FileText,
  Shield,
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={22} style={{ color: 'var(--accent-cyan)' }} />
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
              <Icon size={20} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div style={{
          padding: '1rem 1.5rem',
          borderTop: '1px solid var(--border-subtle)',
          fontSize: '0.7rem',
          color: 'var(--text-muted)',
        }}>
          <p>v0.1.0 — Phase 1</p>
          <p style={{ marginTop: '0.25rem' }}>By Mridul Singh Rawat</p>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  )
}
