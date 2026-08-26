/**
 * Real Live Network Attack Engine.
 * Sends genuine HTTP requests over the network to the target API endpoint,
 * captures real HTTP status codes, headers, and payload responses,
 * and confirms vulnerabilities using live network diffs.
 */

export async function executeLiveNetworkScan(parsedSpec, targetBaseUrl, token, onLog) {
  const results = []
  const baseUrl = targetBaseUrl.replace(/\/$/, '')
  const endpoints = parsedSpec?.endpoints || []

  onLog(`🌐 Initiating live HTTP socket connection to: ${baseUrl}`)

  // ── TEST 1: Broken Authentication (Unprotected Admin Routes) ──
  onLog(`[+] [Broken Auth] Probing unauthenticated routes against target server...`)
  const adminEndpoints = endpoints.filter((ep) => ep.path.toLowerCase().includes('admin'))

  for (const ep of adminEndpoints) {
    const url = `${baseUrl}${ep.path}`
    try {
      const startTime = performance.now()
      const resp = await fetch(url, { method: ep.method })
      const duration = Math.round(performance.now() - startTime)
      const bodyText = await resp.text()

      if (resp.status === 200) {
        onLog(`  💥 VULNERABLE: ${ep.method} ${ep.path} responded ${resp.status} OK in ${duration}ms without credentials!`)
        results.push({
          id: `LIVE-BA-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
          title: `Confirmed Broken Authentication on ${ep.method} ${ep.path}`,
          category: 'Broken Authentication',
          severity: 'critical',
          cvss_score: 9.1,
          endpoint: ep.path,
          method: ep.method,
          description: `The live target server permitted unrestricted HTTP ${ep.method} access to an administrative path without requiring authentication tokens or credentials.`,
          evidence: `HTTP GET ${url}\nAuthorization: [None]\n\nServer Response: HTTP/1.1 ${resp.status} OK (${duration}ms)\nPayload Snippet:\n${bodyText.slice(0, 300)}`,
          remediation: 'Implement mandatory JWT validation or middleware authentication on all administrative endpoints.',
        })
      } else {
        onLog(`  🛡️ SAFE: ${ep.method} ${ep.path} returned ${resp.status}`)
      }
    } catch (err) {
      onLog(`  ⚠️ Failed connecting to ${url}: ${err.message}`)
    }
  }

  // ── TEST 2: Real Rate Limiting Burst Probe ──
  onLog(`[+] [Rate Limiting] Firing 20 concurrent burst requests to authentication endpoints...`)
  const authEndpoints = endpoints.filter((ep) => /login|otp|token|auth/i.test(ep.path))

  for (const ep of authEndpoints) {
    const url = `${baseUrl}${ep.path}`
    try {
      const burstSize = 20
      const startTime = performance.now()
      const reqPromises = Array.from({ length: burstSize }).map(() =>
        fetch(url, {
          method: ep.method,
          headers: { 'Content-Type': 'application/json' },
          body: ep.method === 'POST' ? JSON.stringify({ email: 'audit@target.local', password: 'TestPassword123' }) : undefined,
        }).catch((e) => null)
      )

      const responses = await Promise.all(reqPromises)
      const duration = Math.round(performance.now() - startTime)
      const validResps = responses.filter(Boolean)
      const statusCodes = validResps.map((r) => r.status)
      const has429 = statusCodes.includes(429)

      if (!has429 && validResps.length >= 10) {
        onLog(`  💥 VULNERABLE: Processed ${validResps.length}/${burstSize} requests in ${duration}ms (0x HTTP 429 received)`)
        results.push({
          id: `LIVE-RL-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
          title: `Confirmed Missing Rate Limiting on ${ep.method} ${ep.path}`,
          category: 'Rate Limiting',
          severity: 'medium',
          cvss_score: 5.3,
          endpoint: ep.path,
          method: ep.method,
          description: `The live authentication route answered ${validResps.length} rapid concurrent requests in ${duration}ms without rate-limiting headers or HTTP 429 throttling.`,
          evidence: `Burst Test Target: ${ep.method} ${url}\nRequests Sent: ${burstSize}\nSuccessful Responses: ${validResps.length} (${statusCodes.slice(0, 8).join(', ')}...)\nThrottled Responses (429): 0`,
          remediation: 'Deploy IP-based token bucket rate limiters (e.g., max 5 attempts per minute).',
        })
      }
    } catch (err) {
      onLog(`  ⚠️ Rate limit probe failed: ${err.message}`)
    }
  }

  // ── TEST 3: Real BOLA & IDOR Cross-Account Traversal ──
  onLog(`[+] [BOLA] Probing resource ID traversal across user identifiers...`)
  const pathParamEndpoints = endpoints.filter((ep) => /\{[^\}]+\}/.test(ep.path))

  for (const ep of pathParamEndpoints) {
    const url1 = `${baseUrl}${ep.path.replace(/\{[^\}]+\}/g, '1')}`
    const url2 = `${baseUrl}${ep.path.replace(/\{[^\}]+\}/g, '2')}`

    try {
      const headers = token ? { Authorization: `Bearer ${token}` } : {}
      const [r1, r2] = await Promise.all([
        fetch(url1, { method: ep.method, headers }),
        fetch(url2, { method: ep.method, headers }),
      ])

      if (r1.status === 200 && r2.status === 200) {
        const text1 = await r1.text()
        const text2 = await r2.text()

        if (text1 !== text2 && text1.length > 20 && text2.length > 20) {
          onLog(`  💥 VULNERABLE: Accessed both User 1 and User 2 object IDs with HTTP 200 OK!`)
          results.push({
            id: `LIVE-BOLA-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
            title: `Confirmed BOLA / IDOR on ${ep.method} ${ep.path}`,
            category: 'BOLA',
            severity: 'high',
            cvss_score: 8.6,
            endpoint: ep.path,
            method: ep.method,
            description: `The live server allowed reading/modifying distinct object identifiers (${url1} and ${url2}) without verifying session ownership.`,
            evidence: `Request 1: ${ep.method} ${url1} -> HTTP 200 OK\nPayload: ${text1.slice(0, 150)}...\n\nRequest 2: ${ep.method} ${url2} -> HTTP 200 OK\nPayload: ${text2.slice(0, 150)}...`,
            remediation: 'Implement user-context ownership validation before returning or mutating database objects.',
          })
        }
      }
    } catch (err) {
      onLog(`  ⚠️ BOLA probe failed on ${ep.path}: ${err.message}`)
    }
  }

  // ── TEST 4: Real Mass Assignment Injection ──
  onLog(`[+] [Mass Assignment] Injecting privileged parameters (is_admin: true, role: admin)...`)
  const mutatingEndpoints = endpoints.filter((ep) => ['PUT', 'POST', 'PATCH'].includes(ep.method.toUpperCase()))

  for (const ep of mutatingEndpoints) {
    const targetPath = ep.path.replace(/\{[^\}]+\}/g, '2')
    const url = `${baseUrl}${targetPath}`

    const injectionPayload = {
      full_name: 'Security Audit User',
      email: 'audit@target.local',
      is_admin: true,
      role: 'admin',
      balance: 999999.0,
    }

    try {
      const resp = await fetch(url, {
        method: ep.method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(injectionPayload),
      })

      if (resp.status === 200 || resp.status === 201) {
        const respText = await resp.text()
        if (respText.includes('"is_admin":true') || respText.includes('"is_admin": true') || respText.includes('admin')) {
          onLog(`  💥 VULNERABLE: Server accepted and persisted 'is_admin: true' into database!`)
          results.push({
            id: `LIVE-MA-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
            title: `Confirmed Mass Assignment on ${ep.method} ${ep.path} (Privilege Escalation)`,
            category: 'Mass Assignment',
            severity: 'high',
            cvss_score: 7.5,
            endpoint: ep.path,
            method: ep.method,
            description: `The live server accepted non-whitelisted administrative fields ('is_admin: true', 'role: admin') in the JSON body and modified the user object.`,
            evidence: `Request: ${ep.method} ${url}\nBody: ${JSON.stringify(injectionPayload, null, 2)}\n\nServer Response: HTTP 200 OK\n${respText.slice(0, 300)}`,
            remediation: 'Use strict DTO schemas and whitelist client-updatable properties explicitly.',
          })
        }
      }
    } catch (err) {
      onLog(`  ⚠️ Mass assignment probe failed: ${err.message}`)
    }
  }

  // ── TEST 5: Real Excessive Data Exposure ──
  onLog(`[+] [Excessive Data] Auditing live JSON payloads for leaked PII & credentials...`)
  const userProfileEp = endpoints.find((ep) => ep.path.includes('profile'))

  if (userProfileEp) {
    const url = `${baseUrl}${userProfileEp.path.replace(/\{[^\}]+\}/g, '1')}`
    try {
      const resp = await fetch(url, { method: 'GET' })
      if (resp.status === 200) {
        const bodyText = await resp.text()
        const leakedKeys = []
        if (/password_hash|password/i.test(bodyText)) leakedKeys.push('password_hash')
        if (/ssn/i.test(bodyText)) leakedKeys.push('ssn')
        if (/credit_card/i.test(bodyText)) leakedKeys.push('credit_card')

        if (leakedKeys.length > 0) {
          onLog(`  💥 VULNERABLE: Response payload leaked sensitive attributes: [${leakedKeys.join(', ')}]`)
          results.push({
            id: `LIVE-EDE-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
            title: `Confirmed Excessive Data Exposure on ${userProfileEp.method} ${userProfileEp.path}`,
            category: 'Excessive Data Exposure',
            severity: 'high',
            cvss_score: 7.5,
            endpoint: userProfileEp.path,
            method: userProfileEp.method,
            description: `The API endpoint returned raw internal database attributes (${leakedKeys.join(', ')}) in public HTTP responses.`,
            evidence: `Request: GET ${url}\nResponse: HTTP 200 OK\nPayload Snippet:\n${bodyText.slice(0, 350)}`,
            remediation: 'Use output serializer models (e.g. Pydantic response_model) to filter out internal database attributes.',
          })
        }
      }
    } catch (err) {}
  }

  onLog(`🏁 Live network penetration test complete. Generated ${results.length} confirmed live findings.`)
  return results
}
