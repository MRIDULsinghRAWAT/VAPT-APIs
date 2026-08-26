"""
OpenAPI / Swagger Spec Parser — Phase 1 Core Module

Parses both OpenAPI 3.x and Swagger 2.0 specs (JSON or YAML) into a
structured attack surface map (ParsedSpec).

This is the literal first module — everything else depends on it.
"""

import json
from typing import Any, Dict, List, Optional

import yaml

from app.schemas.spec import (
    AuthSchemeInfo,
    EndpointInfo,
    ParameterInfo,
    ParsedSpec,
)


def parse_openapi_spec(raw_content: str, filename: str = "") -> ParsedSpec:
    """
    Parse raw OpenAPI/Swagger spec content into a structured ParsedSpec.

    Supports:
      - OpenAPI 3.0.x / 3.1.x (JSON or YAML)
      - Swagger 2.0 (JSON or YAML)

    Args:
        raw_content: The raw string content of the spec file.
        filename: Original filename (used to hint JSON vs YAML parsing).

    Returns:
        ParsedSpec with all endpoints, parameters, auth schemes, and stats.
    """
    # ── Step 1: Parse raw content ──
    spec_dict = _load_spec(raw_content, filename)

    # ── Step 2: Detect spec version ──
    if "openapi" in spec_dict:
        return _parse_openapi_3(spec_dict)
    elif "swagger" in spec_dict:
        return _parse_swagger_2(spec_dict)
    else:
        raise ValueError(
            "Unrecognized spec format. Expected 'openapi' (3.x) or 'swagger' (2.0) key."
        )


def _load_spec(raw: str, filename: str) -> Dict[str, Any]:
    """Try JSON first, fall back to YAML."""
    # If filename hints YAML, try YAML first
    if filename.endswith((".yaml", ".yml")):
        try:
            return yaml.safe_load(raw)
        except yaml.YAMLError:
            pass

    # Try JSON
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try YAML as fallback
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError:
        raise ValueError("Could not parse spec as JSON or YAML.")


# ──────────────────────────────────────────────────────────────
# OpenAPI 3.x Parser
# ──────────────────────────────────────────────────────────────

def _parse_openapi_3(spec: Dict[str, Any]) -> ParsedSpec:
    """Parse an OpenAPI 3.0/3.1 spec."""
    info = spec.get("info", {})
    servers = spec.get("servers", [])
    base_url = servers[0]["url"] if servers else None

    # Auth schemes
    security_schemes = (
        spec.get("components", {}).get("securitySchemes", {})
    )
    auth_schemes = _extract_auth_schemes(security_schemes)

    # Global security (applies to all endpoints unless overridden)
    global_security = spec.get("security", [])

    # Endpoints
    endpoints: List[EndpointInfo] = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ("get", "post", "put", "delete", "patch", "head", "options"):
            operation = path_item.get(method)
            if not operation:
                continue

            endpoint = _parse_openapi3_operation(
                path, method, operation, path_item, global_security
            )
            endpoints.append(endpoint)

    # Compute stats
    methods_breakdown: Dict[str, int] = {}
    protected = 0
    unprotected = 0

    for ep in endpoints:
        key = ep.method.upper()
        methods_breakdown[key] = methods_breakdown.get(key, 0) + 1
        if ep.auth_required:
            protected += 1
        else:
            unprotected += 1

    total_params = sum(len(ep.parameters) for ep in endpoints)

    return ParsedSpec(
        title=info.get("title", "Untitled API"),
        version=info.get("version", "0.0.0"),
        spec_version=f"openapi-{spec.get('openapi', '3.0')}",
        base_url=base_url,
        description=info.get("description"),
        endpoints=endpoints,
        auth_schemes=auth_schemes,
        total_endpoints=len(endpoints),
        total_params=total_params,
        methods_breakdown=methods_breakdown,
        auth_coverage={"protected": protected, "unprotected": unprotected},
    )


def _parse_openapi3_operation(
    path: str,
    method: str,
    operation: Dict[str, Any],
    path_item: Dict[str, Any],
    global_security: List,
) -> EndpointInfo:
    """Parse a single OpenAPI 3.x operation into EndpointInfo."""

    # Parameters (merge path-level + operation-level)
    params: List[ParameterInfo] = []
    all_raw_params = path_item.get("parameters", []) + operation.get("parameters", [])

    for p in all_raw_params:
        if not isinstance(p, dict):
            continue
        schema = p.get("schema", {})
        params.append(ParameterInfo(
            name=p.get("name", ""),
            location=p.get("in", "query"),
            required=p.get("required", False),
            param_type=schema.get("type", "string"),
            description=p.get("description"),
            example=p.get("example") or schema.get("example"),
        ))

    # Request body
    request_body_schema = None
    req_body = operation.get("requestBody", {})
    if req_body:
        content = req_body.get("content", {})
        json_content = content.get("application/json", {})
        request_body_schema = json_content.get("schema")

    # Response schema (grab the success response)
    response_schema = None
    responses = operation.get("responses", {})
    success_resp = responses.get("200") or responses.get("201") or responses.get("2XX")
    if success_resp:
        resp_content = success_resp.get("content", {})
        resp_json = resp_content.get("application/json", {})
        response_schema = resp_json.get("schema")

    # Security / Auth
    op_security = operation.get("security", global_security)
    auth_required = bool(op_security)
    auth_scheme_names = []
    for sec in (op_security or []):
        if isinstance(sec, dict):
            auth_scheme_names.extend(sec.keys())

    return EndpointInfo(
        path=path,
        method=method.upper(),
        summary=operation.get("summary"),
        description=operation.get("description"),
        parameters=params,
        request_body_schema=request_body_schema,
        response_schema=response_schema,
        auth_required=auth_required,
        auth_schemes=auth_scheme_names,
        tags=operation.get("tags", []),
    )


# ──────────────────────────────────────────────────────────────
# Swagger 2.0 Parser
# ──────────────────────────────────────────────────────────────

def _parse_swagger_2(spec: Dict[str, Any]) -> ParsedSpec:
    """Parse a Swagger 2.0 spec."""
    info = spec.get("info", {})
    host = spec.get("host", "")
    base_path = spec.get("basePath", "")
    schemes = spec.get("schemes", ["https"])
    base_url = f"{schemes[0]}://{host}{base_path}" if host else None

    # Auth schemes
    security_defs = spec.get("securityDefinitions", {})
    auth_schemes = _extract_auth_schemes_v2(security_defs)

    # Global security
    global_security = spec.get("security", [])

    # Endpoints
    endpoints: List[EndpointInfo] = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ("get", "post", "put", "delete", "patch", "head", "options"):
            operation = path_item.get(method)
            if not operation:
                continue

            endpoint = _parse_swagger2_operation(
                path, method, operation, path_item, global_security
            )
            endpoints.append(endpoint)

    # Stats
    methods_breakdown: Dict[str, int] = {}
    protected = 0
    unprotected = 0

    for ep in endpoints:
        key = ep.method.upper()
        methods_breakdown[key] = methods_breakdown.get(key, 0) + 1
        if ep.auth_required:
            protected += 1
        else:
            unprotected += 1

    total_params = sum(len(ep.parameters) for ep in endpoints)

    return ParsedSpec(
        title=info.get("title", "Untitled API"),
        version=info.get("version", "0.0.0"),
        spec_version=f"swagger-{spec.get('swagger', '2.0')}",
        base_url=base_url,
        description=info.get("description"),
        endpoints=endpoints,
        auth_schemes=auth_schemes,
        total_endpoints=len(endpoints),
        total_params=total_params,
        methods_breakdown=methods_breakdown,
        auth_coverage={"protected": protected, "unprotected": unprotected},
    )


def _parse_swagger2_operation(
    path: str,
    method: str,
    operation: Dict[str, Any],
    path_item: Dict[str, Any],
    global_security: List,
) -> EndpointInfo:
    """Parse a single Swagger 2.0 operation."""

    params: List[ParameterInfo] = []
    all_raw_params = path_item.get("parameters", []) + operation.get("parameters", [])

    request_body_schema = None

    for p in all_raw_params:
        if not isinstance(p, dict):
            continue

        loc = p.get("in", "query")

        # Swagger 2.0 puts body params in "in": "body"
        if loc == "body":
            request_body_schema = p.get("schema")
            continue

        params.append(ParameterInfo(
            name=p.get("name", ""),
            location=loc,
            required=p.get("required", False),
            param_type=p.get("type", "string"),
            description=p.get("description"),
            example=p.get("x-example"),
        ))

    # Response schema
    response_schema = None
    responses = operation.get("responses", {})
    success_resp = responses.get("200") or responses.get("201")
    if success_resp:
        response_schema = success_resp.get("schema")

    # Security
    op_security = operation.get("security", global_security)
    auth_required = bool(op_security)
    auth_scheme_names = []
    for sec in (op_security or []):
        if isinstance(sec, dict):
            auth_scheme_names.extend(sec.keys())

    return EndpointInfo(
        path=path,
        method=method.upper(),
        summary=operation.get("summary"),
        description=operation.get("description"),
        parameters=params,
        request_body_schema=request_body_schema,
        response_schema=response_schema,
        auth_required=auth_required,
        auth_schemes=auth_scheme_names,
        tags=operation.get("tags", []),
    )


# ──────────────────────────────────────────────────────────────
# Auth scheme extraction helpers
# ──────────────────────────────────────────────────────────────

def _extract_auth_schemes(security_schemes: Dict[str, Any]) -> List[AuthSchemeInfo]:
    """Extract auth schemes from OpenAPI 3.x securitySchemes."""
    schemes = []
    for name, details in security_schemes.items():
        if not isinstance(details, dict):
            continue
        schemes.append(AuthSchemeInfo(
            name=name,
            scheme_type=details.get("type", "unknown"),
            location=details.get("in"),
            header_name=details.get("name"),
            scheme=details.get("scheme"),
        ))
    return schemes


def _extract_auth_schemes_v2(security_defs: Dict[str, Any]) -> List[AuthSchemeInfo]:
    """Extract auth schemes from Swagger 2.0 securityDefinitions."""
    schemes = []
    for name, details in security_defs.items():
        if not isinstance(details, dict):
            continue
        schemes.append(AuthSchemeInfo(
            name=name,
            scheme_type=details.get("type", "unknown"),
            location=details.get("in"),
            header_name=details.get("name"),
            scheme=None,
        ))
    return schemes
