/**
 * API service layer — all backend communication goes through here.
 */

import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// ── Scans ──

export async function createScan(data) {
  const res = await api.post('/scans/', data)
  return res.data
}

export async function listScans() {
  const res = await api.get('/scans/')
  return res.data
}

export async function getScan(scanId) {
  const res = await api.get(`/scans/${scanId}`)
  return res.data
}

export async function runScan(scanId, payload) {
  const res = await api.post(`/scans/${scanId}/run`, payload)
  return res.data
}

// ── Spec Parser ──

export async function parseSpecFile(file) {
  const formData = new FormData()
  formData.append('file', file)
  const res = await api.post('/specs/parse', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return res.data
}

export async function parseSpecFromUrl(url) {
  const res = await api.post(`/specs/parse-url?url=${encodeURIComponent(url)}`)
  return res.data
}

// ── Reports ──

export async function exportReport(scanId, format = 'html') {
  const res = await api.get(`/reports/${scanId}/export?format=${format}`)
  return res.data
}

export default api
