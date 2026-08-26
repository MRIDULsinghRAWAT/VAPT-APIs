import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import SpecUpload from './pages/SpecUpload'
import EndpointMap from './pages/EndpointMap'
import ScanConsole from './pages/ScanConsole'
import Reports from './pages/Reports'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="upload" element={<SpecUpload />} />
        <Route path="endpoints" element={<EndpointMap />} />
        <Route path="scan" element={<ScanConsole />} />
        <Route path="reports" element={<Reports />} />
      </Route>
    </Routes>
  )
}

export default App
