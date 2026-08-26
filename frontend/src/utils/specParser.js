/**
 * Client-side OpenAPI/Swagger spec parser.
 * Mirrors the backend parser logic so the frontend works standalone
 * without needing the backend running.
 */

export function parseSpec(rawContent, filename = '') {
  const spec = loadSpec(rawContent, filename)

  if (spec.openapi) {
    return parseOpenAPI3(spec)
  } else if (spec.swagger) {
    return parseSwagger2(spec)
  } else {
    throw new Error('Unrecognized spec format. Expected "openapi" (3.x) or "swagger" (2.0).')
  }
}

function loadSpec(raw, filename) {
  // Try JSON first
  try {
    return JSON.parse(raw)
  } catch (jsonErr) {
    // If not JSON, try basic YAML-like parse or throw informative error
    throw new Error('Please provide a valid JSON OpenAPI/Swagger file (.json).')
  }
}

function parseOpenAPI3(spec) {
  const info = spec.info || {}
  const servers = spec.servers || []
  const baseUrl = servers[0]?.url || null

  const securitySchemes = spec.components?.securitySchemes || {}
  const authSchemes = extractAuthSchemes(securitySchemes)
  const globalSecurity = spec.security || []

  const endpoints = []
  const paths = spec.paths || {}

  for (const [path, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue

    for (const method of ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']) {
      const operation = pathItem[method]
      if (!operation) continue

      const params = []
      const allParams = [...(pathItem.parameters || []), ...(operation.parameters || [])]

      for (const p of allParams) {
        if (!p || typeof p !== 'object') continue
        const schema = p.schema || {}
        params.push({
          name: p.name || '',
          location: p.in || 'query',
          required: p.required || false,
          param_type: schema.type || 'string',
          description: p.description || null,
        })
      }

      // Request body
      let requestBodySchema = null
      const reqBody = operation.requestBody || {}
      if (reqBody.content) {
        const jsonContent = reqBody.content['application/json'] || {}
        requestBodySchema = jsonContent.schema || null
      }

      // Response schema
      let responseSchema = null
      const responses = operation.responses || {}
      const successResp = responses['200'] || responses['201'] || responses['2XX']
      if (successResp?.content) {
        const respJson = successResp.content['application/json'] || {}
        responseSchema = respJson.schema || null
      }

      // Auth
      const opSecurity = operation.security !== undefined ? operation.security : globalSecurity
      const authRequired = Array.isArray(opSecurity) && opSecurity.length > 0
      const authSchemeNames = []
      for (const sec of (opSecurity || [])) {
        if (sec && typeof sec === 'object') {
          authSchemeNames.push(...Object.keys(sec))
        }
      }

      endpoints.push({
        path,
        method: method.toUpperCase(),
        summary: operation.summary || null,
        description: operation.description || null,
        parameters: params,
        request_body_schema: requestBodySchema,
        response_schema: responseSchema,
        auth_required: authRequired,
        auth_schemes: authSchemeNames,
        tags: operation.tags || [],
      })
    }
  }

  // Stats
  const methodsBreakdown = {}
  let protectedCount = 0
  let unprotectedCount = 0

  for (const ep of endpoints) {
    methodsBreakdown[ep.method] = (methodsBreakdown[ep.method] || 0) + 1
    if (ep.auth_required) protectedCount++
    else unprotectedCount++
  }

  const totalParams = endpoints.reduce((sum, ep) => sum + ep.parameters.length, 0)

  return {
    title: info.title || 'Untitled API',
    version: info.version || '0.0.0',
    spec_version: `openapi-${spec.openapi}`,
    base_url: baseUrl,
    description: info.description || null,
    endpoints,
    auth_schemes: authSchemes,
    total_endpoints: endpoints.length,
    total_params: totalParams,
    methods_breakdown: methodsBreakdown,
    auth_coverage: { protected: protectedCount, unprotected: unprotectedCount },
  }
}

function parseSwagger2(spec) {
  const info = spec.info || {}
  const host = spec.host || ''
  const basePath = spec.basePath || ''
  const schemes = spec.schemes || ['https']
  const baseUrl = host ? `${schemes[0]}://${host}${basePath}` : null

  const securityDefs = spec.securityDefinitions || {}
  const authSchemes = extractAuthSchemesV2(securityDefs)
  const globalSecurity = spec.security || []

  const endpoints = []
  const paths = spec.paths || {}

  for (const [path, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue

    for (const method of ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']) {
      const operation = pathItem[method]
      if (!operation) continue

      const params = []
      let requestBodySchema = null
      const allParams = [...(pathItem.parameters || []), ...(operation.parameters || [])]

      for (const p of allParams) {
        if (!p || typeof p !== 'object') continue
        if (p.in === 'body') {
          requestBodySchema = p.schema || null
          continue
        }
        params.push({
          name: p.name || '',
          location: p.in || 'query',
          required: p.required || false,
          param_type: p.type || 'string',
          description: p.description || null,
        })
      }

      let responseSchema = null
      const responses = operation.responses || {}
      const successResp = responses['200'] || responses['201']
      if (successResp) {
        responseSchema = successResp.schema || null
      }

      const opSecurity = operation.security !== undefined ? operation.security : globalSecurity
      const authRequired = Array.isArray(opSecurity) && opSecurity.length > 0
      const authSchemeNames = []
      for (const sec of (opSecurity || [])) {
        if (sec && typeof sec === 'object') authSchemeNames.push(...Object.keys(sec))
      }

      endpoints.push({
        path,
        method: method.toUpperCase(),
        summary: operation.summary || null,
        description: operation.description || null,
        parameters: params,
        request_body_schema: requestBodySchema,
        response_schema: responseSchema,
        auth_required: authRequired,
        auth_schemes: authSchemeNames,
        tags: operation.tags || [],
      })
    }
  }

  const methodsBreakdown = {}
  let protectedCount = 0
  let unprotectedCount = 0

  for (const ep of endpoints) {
    methodsBreakdown[ep.method] = (methodsBreakdown[ep.method] || 0) + 1
    if (ep.auth_required) protectedCount++
    else unprotectedCount++
  }

  const totalParams = endpoints.reduce((sum, ep) => sum + ep.parameters.length, 0)

  return {
    title: info.title || 'Untitled API',
    version: info.version || '0.0.0',
    spec_version: `swagger-${spec.swagger}`,
    base_url: baseUrl,
    description: info.description || null,
    endpoints,
    auth_schemes: authSchemes,
    total_endpoints: endpoints.length,
    total_params: totalParams,
    methods_breakdown: methodsBreakdown,
    auth_coverage: { protected: protectedCount, unprotected: unprotectedCount },
  }
}

function extractAuthSchemes(securitySchemes) {
  return Object.entries(securitySchemes).map(([name, details]) => ({
    name,
    scheme_type: details?.type || 'unknown',
    location: details?.in || null,
    header_name: details?.name || null,
    scheme: details?.scheme || null,
  }))
}

function extractAuthSchemesV2(securityDefs) {
  return Object.entries(securityDefs).map(([name, details]) => ({
    name,
    scheme_type: details?.type || 'unknown',
    location: details?.in || null,
    header_name: details?.name || null,
    scheme: null,
  }))
}
