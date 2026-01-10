//! OpenAPI Documentation Generation (ISSUE-026)
//!
//! Provides OpenAPI 3.0 specification generation for P2 API endpoints.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OpenAPI specification root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiSpec {
    /// OpenAPI version
    pub openapi: String,
    /// API information
    pub info: ApiInfo,
    /// Server list
    pub servers: Vec<Server>,
    /// API paths
    pub paths: HashMap<String, PathItem>,
    /// Reusable components
    pub components: Components,
    /// Security requirements
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security: Vec<HashMap<String, Vec<String>>>,
    /// Tags for grouping
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
}

impl OpenApiSpec {
    /// Generate the P2 API specification
    pub fn generate_p2_spec() -> Self {
        Self {
            openapi: "3.0.3".to_string(),
            info: ApiInfo {
                title: "P2/DSN Storage API".to_string(),
                description: Some("Encrypted permanence storage layer for Rainbow Protocol".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                contact: Some(Contact {
                    name: Some("Rainbow Protocol Team".to_string()),
                    email: Some("dev@rainbow.protocol".to_string()),
                    url: None,
                }),
                license: Some(License {
                    name: "Apache-2.0".to_string(),
                    url: Some("https://www.apache.org/licenses/LICENSE-2.0".to_string()),
                }),
            },
            servers: vec![
                Server {
                    url: "https://api.p2.rainbow.protocol".to_string(),
                    description: Some("Production".to_string()),
                    variables: None,
                },
                Server {
                    url: "https://api.staging.p2.rainbow.protocol".to_string(),
                    description: Some("Staging".to_string()),
                    variables: None,
                },
                Server {
                    url: "http://localhost:8080".to_string(),
                    description: Some("Local Development".to_string()),
                    variables: None,
                },
            ],
            paths: Self::generate_paths(),
            components: Self::generate_components(),
            security: vec![{
                let mut map = HashMap::new();
                map.insert("bearerAuth".to_string(), vec![]);
                map
            }],
            tags: vec![
                Tag { name: "Payloads".to_string(), description: Some("Encrypted payload operations".to_string()) },
                Tag { name: "Tickets".to_string(), description: Some("Access ticket management".to_string()) },
                Tag { name: "Evidence".to_string(), description: Some("Evidence bundle operations".to_string()) },
                Tag { name: "Health".to_string(), description: Some("Health and monitoring".to_string()) },
            ],
        }
    }

    fn generate_paths() -> HashMap<String, PathItem> {
        let mut paths = HashMap::new();

        // Payload endpoints
        paths.insert("/payloads".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["Payloads".to_string()],
                summary: Some("List payloads".to_string()),
                description: Some("List encrypted payloads with pagination".to_string()),
                operation_id: Some("listPayloads".to_string()),
                parameters: vec![
                    Parameter::query("limit", "integer", "Number of items per page"),
                    Parameter::query("offset", "integer", "Offset for pagination"),
                ],
                responses: Self::standard_responses("PayloadList"),
                security: None,
            }),
            post: Some(Operation {
                tags: vec!["Payloads".to_string()],
                summary: Some("Upload payload".to_string()),
                description: Some("Upload an encrypted payload to P2 storage".to_string()),
                operation_id: Some("uploadPayload".to_string()),
                parameters: vec![],
                responses: Self::standard_responses("PayloadRef"),
                security: None,
            }),
            put: None,
            delete: None,
            patch: None,
        });

        paths.insert("/payloads/{payloadRef}".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["Payloads".to_string()],
                summary: Some("Get payload".to_string()),
                description: Some("Retrieve an encrypted payload by reference".to_string()),
                operation_id: Some("getPayload".to_string()),
                parameters: vec![
                    Parameter::path("payloadRef", "Payload reference ID"),
                ],
                responses: Self::standard_responses("Payload"),
                security: None,
            }),
            post: None,
            put: None,
            delete: Some(Operation {
                tags: vec!["Payloads".to_string()],
                summary: Some("Delete payload (tombstone)".to_string()),
                description: Some("Mark a payload as deleted (tombstone only, append-only invariant)".to_string()),
                operation_id: Some("deletePayload".to_string()),
                parameters: vec![
                    Parameter::path("payloadRef", "Payload reference ID"),
                ],
                responses: Self::standard_responses("TombstoneResult"),
                security: None,
            }),
            patch: None,
        });

        // Ticket endpoints
        paths.insert("/tickets".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["Tickets".to_string()],
                summary: Some("List tickets".to_string()),
                description: Some("List access tickets".to_string()),
                operation_id: Some("listTickets".to_string()),
                parameters: vec![],
                responses: Self::standard_responses("TicketList"),
                security: None,
            }),
            post: Some(Operation {
                tags: vec!["Tickets".to_string()],
                summary: Some("Create ticket".to_string()),
                description: Some("Create a new access ticket".to_string()),
                operation_id: Some("createTicket".to_string()),
                parameters: vec![],
                responses: Self::standard_responses("AccessTicket"),
                security: None,
            }),
            put: None,
            delete: None,
            patch: None,
        });

        // Evidence endpoints
        paths.insert("/evidence".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["Evidence".to_string()],
                summary: Some("List evidence bundles".to_string()),
                description: Some("List evidence bundles for a case".to_string()),
                operation_id: Some("listEvidence".to_string()),
                parameters: vec![
                    Parameter::query("caseRef", "string", "Case reference ID"),
                ],
                responses: Self::standard_responses("EvidenceBundleList"),
                security: None,
            }),
            post: Some(Operation {
                tags: vec!["Evidence".to_string()],
                summary: Some("Submit evidence".to_string()),
                description: Some("Submit a new evidence bundle".to_string()),
                operation_id: Some("submitEvidence".to_string()),
                parameters: vec![],
                responses: Self::standard_responses("EvidenceBundle"),
                security: None,
            }),
            put: None,
            delete: None,
            patch: None,
        });

        // Health endpoints
        paths.insert("/health".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["Health".to_string()],
                summary: Some("Health check".to_string()),
                description: Some("Check service health".to_string()),
                operation_id: Some("healthCheck".to_string()),
                parameters: vec![],
                responses: Self::health_responses(),
                security: None,
            }),
            post: None,
            put: None,
            delete: None,
            patch: None,
        });

        paths.insert("/health/ready".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["Health".to_string()],
                summary: Some("Readiness check".to_string()),
                description: Some("Check if service is ready to accept traffic".to_string()),
                operation_id: Some("readinessCheck".to_string()),
                parameters: vec![],
                responses: Self::health_responses(),
                security: None,
            }),
            post: None,
            put: None,
            delete: None,
            patch: None,
        });

        paths
    }

    fn generate_components() -> Components {
        let mut schemas = HashMap::new();

        // PayloadRef schema
        schemas.insert("PayloadRef".to_string(), Schema {
            schema_type: Some("object".to_string()),
            properties: Some({
                let mut props = HashMap::new();
                props.insert("ref_id".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("Unique payload reference".to_string()),
                    format: None,
                    example: Some(serde_json::json!("payload:abc123:def456")),
                });
                props.insert("checksum".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("BLAKE3 checksum of encrypted data".to_string()),
                    format: None,
                    example: None,
                });
                props.insert("size_bytes".to_string(), SchemaProperty {
                    schema_type: "integer".to_string(),
                    description: Some("Size in bytes".to_string()),
                    format: Some("int64".to_string()),
                    example: None,
                });
                props
            }),
            required: Some(vec!["ref_id".to_string(), "checksum".to_string()]),
            description: Some("Reference to an encrypted payload".to_string()),
        });

        // AccessTicket schema
        schemas.insert("AccessTicket".to_string(), Schema {
            schema_type: Some("object".to_string()),
            properties: Some({
                let mut props = HashMap::new();
                props.insert("ticket_id".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("Unique ticket ID".to_string()),
                    format: None,
                    example: None,
                });
                props.insert("purpose".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("Access purpose".to_string()),
                    format: None,
                    example: Some(serde_json::json!("audit")),
                });
                props.insert("valid_until".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("Expiration timestamp".to_string()),
                    format: Some("date-time".to_string()),
                    example: None,
                });
                props
            }),
            required: Some(vec!["ticket_id".to_string(), "purpose".to_string()]),
            description: Some("Access ticket for payload retrieval".to_string()),
        });

        // EvidenceBundle schema
        schemas.insert("EvidenceBundle".to_string(), Schema {
            schema_type: Some("object".to_string()),
            properties: Some({
                let mut props = HashMap::new();
                props.insert("bundle_id".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("Bundle ID".to_string()),
                    format: None,
                    example: None,
                });
                props.insert("case_ref".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("Case reference".to_string()),
                    format: None,
                    example: None,
                });
                props.insert("evidence_level".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("Evidence level (A or B)".to_string()),
                    format: None,
                    example: Some(serde_json::json!("A")),
                });
                props
            }),
            required: Some(vec!["bundle_id".to_string(), "case_ref".to_string()]),
            description: Some("Evidence bundle for judicial discovery".to_string()),
        });

        // Error schema
        schemas.insert("Error".to_string(), Schema {
            schema_type: Some("object".to_string()),
            properties: Some({
                let mut props = HashMap::new();
                props.insert("code".to_string(), SchemaProperty {
                    schema_type: "integer".to_string(),
                    description: Some("Error code".to_string()),
                    format: None,
                    example: Some(serde_json::json!(4001)),
                });
                props.insert("message".to_string(), SchemaProperty {
                    schema_type: "string".to_string(),
                    description: Some("Error message".to_string()),
                    format: None,
                    example: Some(serde_json::json!("Payload not found")),
                });
                props
            }),
            required: Some(vec!["code".to_string(), "message".to_string()]),
            description: Some("API error response".to_string()),
        });

        Components {
            schemas,
            security_schemes: {
                let mut sec = HashMap::new();
                sec.insert("bearerAuth".to_string(), SecurityScheme {
                    scheme_type: "http".to_string(),
                    scheme: Some("bearer".to_string()),
                    bearer_format: Some("JWT".to_string()),
                    description: Some("JWT Bearer token authentication".to_string()),
                });
                sec
            },
        }
    }

    fn standard_responses(success_schema: &str) -> HashMap<String, Response> {
        let mut responses = HashMap::new();
        responses.insert("200".to_string(), Response {
            description: "Successful operation".to_string(),
            content: Some({
                let mut content = HashMap::new();
                content.insert("application/json".to_string(), MediaType {
                    schema: Some(SchemaRef::Ref(format!("#/components/schemas/{}", success_schema))),
                });
                content
            }),
        });
        responses.insert("400".to_string(), Response {
            description: "Bad request".to_string(),
            content: Some({
                let mut content = HashMap::new();
                content.insert("application/json".to_string(), MediaType {
                    schema: Some(SchemaRef::Ref("#/components/schemas/Error".to_string())),
                });
                content
            }),
        });
        responses.insert("401".to_string(), Response {
            description: "Unauthorized".to_string(),
            content: None,
        });
        responses.insert("404".to_string(), Response {
            description: "Not found".to_string(),
            content: Some({
                let mut content = HashMap::new();
                content.insert("application/json".to_string(), MediaType {
                    schema: Some(SchemaRef::Ref("#/components/schemas/Error".to_string())),
                });
                content
            }),
        });
        responses.insert("500".to_string(), Response {
            description: "Internal server error".to_string(),
            content: Some({
                let mut content = HashMap::new();
                content.insert("application/json".to_string(), MediaType {
                    schema: Some(SchemaRef::Ref("#/components/schemas/Error".to_string())),
                });
                content
            }),
        });
        responses
    }

    fn health_responses() -> HashMap<String, Response> {
        let mut responses = HashMap::new();
        responses.insert("200".to_string(), Response {
            description: "Service is healthy".to_string(),
            content: Some({
                let mut content = HashMap::new();
                content.insert("application/json".to_string(), MediaType {
                    schema: Some(SchemaRef::Inline(Schema {
                        schema_type: Some("object".to_string()),
                        properties: Some({
                            let mut props = HashMap::new();
                            props.insert("status".to_string(), SchemaProperty {
                                schema_type: "string".to_string(),
                                description: None,
                                format: None,
                                example: Some(serde_json::json!("healthy")),
                            });
                            props
                        }),
                        required: None,
                        description: None,
                    })),
                });
                content
            }),
        });
        responses.insert("503".to_string(), Response {
            description: "Service is unhealthy".to_string(),
            content: None,
        });
        responses
    }

    /// Export specification as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export specification as YAML (if serde_yaml is available)
    #[cfg(feature = "yaml")]
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

// Supporting types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiInfo {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Contact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<License>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<HashMap<String, ServerVariable>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerVariable {
    pub default: String,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub put: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "operationId", skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<Parameter>,
    pub responses: HashMap<String, Response>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<Vec<HashMap<String, Vec<String>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
    pub schema: ParameterSchema,
}

impl Parameter {
    pub fn query(name: &str, schema_type: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            location: "query".to_string(),
            description: Some(description.to_string()),
            required: false,
            schema: ParameterSchema { schema_type: schema_type.to_string() },
        }
    }

    pub fn path(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            location: "path".to_string(),
            description: Some(description.to_string()),
            required: true,
            schema: ParameterSchema { schema_type: "string".to_string() },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<HashMap<String, MediaType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaType {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaRef>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum SchemaRef {
    Ref(String),
    Inline(Schema),
}

impl Serialize for SchemaRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SchemaRef::Ref(r) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("$ref", r)?;
                map.end()
            }
            SchemaRef::Inline(s) => s.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Components {
    pub schemas: HashMap<String, Schema>,
    #[serde(rename = "securitySchemes")]
    pub security_schemes: HashMap<String, SecurityScheme>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, SchemaProperty>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaProperty {
    #[serde(rename = "type")]
    pub schema_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScheme {
    #[serde(rename = "type")]
    pub scheme_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(rename = "bearerFormat", skip_serializing_if = "Option::is_none")]
    pub bearer_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_spec() {
        let spec = OpenApiSpec::generate_p2_spec();
        assert_eq!(spec.openapi, "3.0.3");
        assert!(!spec.paths.is_empty());
        assert!(!spec.components.schemas.is_empty());
    }

    #[test]
    fn test_to_json() {
        let spec = OpenApiSpec::generate_p2_spec();
        let json = spec.to_json().unwrap();
        assert!(json.contains("openapi"));
        assert!(json.contains("3.0.3"));
    }
}
