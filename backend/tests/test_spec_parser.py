"""
Tests for the OpenAPI/Swagger spec parser.
"""

import pytest
from app.services.spec_parser import parse_openapi_spec


# ── Sample OpenAPI 3.0 Spec ──
SAMPLE_OPENAPI3 = """
{
  "openapi": "3.0.0",
  "info": {
    "title": "Test API",
    "version": "1.0.0",
    "description": "A test API for parser validation"
  },
  "servers": [
    {"url": "http://localhost:8080/api/v1"}
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      }
    }
  },
  "security": [
    {"bearerAuth": []}
  ],
  "paths": {
    "/users": {
      "get": {
        "summary": "List all users",
        "tags": ["Users"],
        "responses": {
          "200": {
            "description": "User list",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {"$ref": "#/components/schemas/User"}
                }
              }
            }
          }
        }
      },
      "post": {
        "summary": "Create a user",
        "tags": ["Users"],
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": {"type": "string"},
                  "email": {"type": "string"}
                }
              }
            }
          }
        },
        "responses": {
          "201": {"description": "Created"}
        }
      }
    },
    "/users/{id}": {
      "get": {
        "summary": "Get user by ID",
        "tags": ["Users"],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {"type": "integer"}
          }
        ],
        "responses": {
          "200": {"description": "User object"}
        }
      }
    },
    "/public/info": {
      "get": {
        "summary": "Public info endpoint",
        "security": [],
        "responses": {
          "200": {"description": "Public info"}
        }
      }
    }
  }
}
"""


# ── Sample Swagger 2.0 Spec ──
SAMPLE_SWAGGER2 = """
{
  "swagger": "2.0",
  "info": {
    "title": "Legacy API",
    "version": "2.0.0"
  },
  "host": "localhost:9090",
  "basePath": "/api",
  "schemes": ["http"],
  "securityDefinitions": {
    "apiKey": {
      "type": "apiKey",
      "name": "X-API-Key",
      "in": "header"
    }
  },
  "paths": {
    "/items": {
      "get": {
        "summary": "List items",
        "security": [{"apiKey": []}],
        "responses": {
          "200": {"description": "Item list"}
        }
      }
    },
    "/items/{itemId}": {
      "put": {
        "summary": "Update item",
        "security": [{"apiKey": []}],
        "parameters": [
          {
            "name": "itemId",
            "in": "path",
            "required": true,
            "type": "integer"
          },
          {
            "name": "body",
            "in": "body",
            "schema": {
              "type": "object",
              "properties": {
                "name": {"type": "string"}
              }
            }
          }
        ],
        "responses": {
          "200": {"description": "Updated"}
        }
      }
    }
  }
}
"""


class TestOpenAPI3Parser:
    """Tests for OpenAPI 3.x parsing."""

    def test_basic_parsing(self):
        result = parse_openapi_spec(SAMPLE_OPENAPI3, "test.json")
        assert result.title == "Test API"
        assert result.version == "1.0.0"
        assert "openapi" in result.spec_version

    def test_endpoint_count(self):
        result = parse_openapi_spec(SAMPLE_OPENAPI3, "test.json")
        assert result.total_endpoints == 4  # GET /users, POST /users, GET /users/{id}, GET /public/info

    def test_base_url(self):
        result = parse_openapi_spec(SAMPLE_OPENAPI3, "test.json")
        assert result.base_url == "http://localhost:8080/api/v1"

    def test_auth_schemes(self):
        result = parse_openapi_spec(SAMPLE_OPENAPI3, "test.json")
        assert len(result.auth_schemes) == 1
        assert result.auth_schemes[0].name == "bearerAuth"
        assert result.auth_schemes[0].scheme == "bearer"

    def test_auth_coverage(self):
        result = parse_openapi_spec(SAMPLE_OPENAPI3, "test.json")
        # 3 protected (global security) + 1 unprotected (security: [])
        assert result.auth_coverage["protected"] == 3
        assert result.auth_coverage["unprotected"] == 1

    def test_methods_breakdown(self):
        result = parse_openapi_spec(SAMPLE_OPENAPI3, "test.json")
        assert result.methods_breakdown["GET"] == 3
        assert result.methods_breakdown["POST"] == 1

    def test_path_parameters(self):
        result = parse_openapi_spec(SAMPLE_OPENAPI3, "test.json")
        user_by_id = [ep for ep in result.endpoints if ep.path == "/users/{id}"][0]
        assert len(user_by_id.parameters) == 1
        assert user_by_id.parameters[0].name == "id"
        assert user_by_id.parameters[0].location == "path"

    def test_request_body(self):
        result = parse_openapi_spec(SAMPLE_OPENAPI3, "test.json")
        create_user = [ep for ep in result.endpoints if ep.method == "POST"][0]
        assert create_user.request_body_schema is not None


class TestSwagger2Parser:
    """Tests for Swagger 2.0 parsing."""

    def test_basic_parsing(self):
        result = parse_openapi_spec(SAMPLE_SWAGGER2, "test.json")
        assert result.title == "Legacy API"
        assert "swagger" in result.spec_version

    def test_base_url_construction(self):
        result = parse_openapi_spec(SAMPLE_SWAGGER2, "test.json")
        assert result.base_url == "http://localhost:9090/api"

    def test_endpoint_count(self):
        result = parse_openapi_spec(SAMPLE_SWAGGER2, "test.json")
        assert result.total_endpoints == 2

    def test_body_param_extraction(self):
        result = parse_openapi_spec(SAMPLE_SWAGGER2, "test.json")
        update_item = [ep for ep in result.endpoints if ep.method == "PUT"][0]
        assert update_item.request_body_schema is not None
        # Body param should NOT appear in parameters list
        param_names = [p.name for p in update_item.parameters]
        assert "body" not in param_names


class TestEdgeCases:
    """Edge cases and error handling."""

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Could not parse"):
            parse_openapi_spec("this is not valid json or yaml", "bad.txt")

    def test_unknown_spec_format_raises(self):
        with pytest.raises(ValueError, match="Unrecognized spec format"):
            parse_openapi_spec('{"not_a_spec": true}', "unknown.json")

    def test_yaml_parsing(self):
        yaml_spec = """
openapi: "3.0.0"
info:
  title: YAML API
  version: "1.0"
paths:
  /test:
    get:
      summary: Test endpoint
      responses:
        "200":
          description: OK
"""
        result = parse_openapi_spec(yaml_spec, "test.yaml")
        assert result.title == "YAML API"
        assert result.total_endpoints == 1
