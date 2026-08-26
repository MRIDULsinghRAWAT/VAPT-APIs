"""
Pydantic schemas for parsed API spec output.
These represent the structured attack surface map that the spec parser produces.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ParameterInfo(BaseModel):
    """A single API parameter (path, query, header, or body field)."""
    name: str
    location: str            # "path", "query", "header", "cookie", "body"
    required: bool = False
    param_type: str = "string"
    description: Optional[str] = None
    example: Optional[Any] = None


class EndpointInfo(BaseModel):
    """A single API endpoint extracted from the spec."""
    path: str                                    # e.g. /users/{id}
    method: str                                  # GET, POST, PUT, DELETE, PATCH
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: List[ParameterInfo] = []
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None
    auth_required: bool = False
    auth_schemes: List[str] = []                 # e.g. ["bearerAuth"]
    tags: List[str] = []


class AuthSchemeInfo(BaseModel):
    """An authentication scheme defined in the spec."""
    name: str
    scheme_type: str                             # "http", "apiKey", "oauth2", "openIdConnect"
    location: Optional[str] = None               # "header", "query", "cookie"
    header_name: Optional[str] = None            # e.g. "Authorization"
    scheme: Optional[str] = None                 # e.g. "bearer"


class ParsedSpec(BaseModel):
    """
    The complete parsed attack surface map from an OpenAPI/Swagger spec.
    This is the output of Phase 1's spec parser.
    """
    title: str
    version: str
    spec_version: str                            # "openapi-3.0" or "swagger-2.0"
    base_url: Optional[str] = None
    description: Optional[str] = None
    endpoints: List[EndpointInfo] = []
    auth_schemes: List[AuthSchemeInfo] = []
    total_endpoints: int = 0
    total_params: int = 0

    # Summary stats for the UI
    methods_breakdown: Dict[str, int] = {}       # {"GET": 5, "POST": 3, ...}
    auth_coverage: Dict[str, int] = {}           # {"protected": 8, "unprotected": 2}
