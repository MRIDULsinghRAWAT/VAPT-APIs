/**
 * AI service layer — Gemini-powered remediation and security chat.
 */

import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

const aiApi = axios.create({
  baseURL: API_BASE,
  timeout: 60000, // AI calls can take longer
  headers: { 'Content-Type': 'application/json' },
})

/**
 * Generate AI-powered remediation for a vulnerability finding.
 * @param {Object} finding - { title, category, severity, cvss_score, endpoint, method, description, evidence }
 * @returns {Object} - { explanation, fix_code, owasp_reference, cwe_id, risk_analysis }
 */
export async function getAIRemediation(finding) {
  const res = await aiApi.post('/ai/remediate', { finding })
  return res.data
}

/**
 * Send a message to the AI security chat.
 * @param {string} message - User's question
 * @param {Object|null} scanContext - Optional scan results context { target_url, findings: [...] }
 * @param {Array|null} chatHistory - Optional array of { role, content } messages
 * @returns {Object} - { response }
 */
export async function sendChatMessage(message, scanContext = null, chatHistory = null) {
  const res = await aiApi.post('/ai/chat', {
    message,
    scan_context: scanContext,
    chat_history: chatHistory,
  })
  return res.data
}

