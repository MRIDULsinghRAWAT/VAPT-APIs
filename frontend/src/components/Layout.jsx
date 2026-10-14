import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Upload,
  Map,
  Play,
  FileText,
  Search,
} from 'lucide-react'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/upload', icon: Upload, label: 'Upload Spec' },
  { to: '/endpoints', icon: Map, label: 'Endpoints' },
  { to: '/scan', icon: Play, label: 'Scan Console' },
  { to: '/reports', icon: FileText, label: 'Reports' },
]

export default function Layout() {
  const location = useLocation()

  // Get current active route name for the breadcrumb
  const currentNav = navItems.find((item) =>
    item.to === '/' ? location.pathname === '/' : location.pathname.startsWith(item.to)
  )
  const currentTitle = currentNav ? currentNav.label : 'Overview'

  return (
    <div className="app-layout-topbar">
      {/* ── Top Navigation Bar (Exact Digitalists.at Header) ── */}
      <header className="top-navbar">
        {/* Left: Brand + 0xF1E500 Color Bars */}
        <div className="top-brand-group">
          <NavLink to="/" className="top-brand-title">
            vapt<span>engine</span>
          </NavLink>

          <div className="color-strip-container">
            <span className="strip-hex">0xF1E500</span>
            <div className="color-strips">
              <span style={{ background: '#ff7700' }} />
              <span style={{ background: '#ffcc00', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#000', fontSize: '8px', fontWeight: 900 }}>✕</span>
              <span style={{ background: '#00ff66' }} />
              <span style={{ background: '#00e5ff' }} />
              <span style={{ background: '#0033ff' }} />
              <span style={{ background: '#aa00ff' }} />
              <span style={{ background: '#ff0055' }} />
            </div>
          </div>
        </div>

        {/* Center: Monospace Breadcrumb Subtitle */}
        <div className="top-breadcrumb-group">
          <div className="breadcrumb-path">
            <span className="home-icon">⌂</span>
            <span className="slash">/</span>
            <span className="crumb-target">{currentTitle}</span>
          </div>
          <div className="breadcrumb-sub">
            HELLO WORLD. WELCOME SECURITY ENGINE.
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="top-nav-links">
          {navItems.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `top-nav-item ${isActive ? 'active' : ''}`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Right: Black CTA Button + Search + TL;TR */}
        <div className="top-right-group">
          <NavLink to="/scan" className="btn-cta-black">
            START SCAN <span className="cta-dot">■</span>
          </NavLink>

          <button className="icon-search-btn" title="Search" aria-label="Search">
            <Search size={18} strokeWidth={2} />
          </button>

          <span className="tltr-tag">TL;TR</span>
        </div>
      </header>

      {/* Main Page Content */}
      <main className="main-content-fluid">
        <Outlet />
      </main>
    </div>
  )
}
