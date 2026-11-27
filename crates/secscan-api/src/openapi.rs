use serde_json::{json, Value};

pub fn openapi_spec() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Secure Headers Scanner API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "High-performance Rust HTTP security headers scanner with SSRF protection, weighted scoring, SSE streaming, and YAML snapshot diffing."
        },
        "paths": {
            "/api/healthz": {
                "get": {
                    "summary": "Health check",
                    "responses": {
                        "200": { "description": "Service is healthy" }
                    }
                }
            },
            "/api/scan": {
                "post": {
                    "summary": "Batch scan domains and return JSON results with score, grade, remediations, and diff against previous YAML snapshot",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["domains"],
                                    "properties": {
                                        "domains": {
                                            "type": "array",
                                            "items": { "type": "string" }
                                        },
                                        "saveSnapshot": {
                                            "type": "boolean",
                                            "default": true
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Scan results, snapshot, and optional diff" },
                        "400": { "description": "Validation error" },
                        "429": { "description": "Rate limit exceeded" }
                    }
                }
            },
            "/api/scan/stream": {
                "post": {
                    "summary": "Stream scan results in real time using Server-Sent Events (SSE)",
                    "responses": {
                        "200": { "description": "text/event-stream with start, result, and done events" }
                    }
                }
            },
            "/api/last-scan": {
                "get": {
                    "summary": "Retrieve the previous scan snapshot saved in YAML as JSON",
                    "responses": {
                        "200": { "description": "Latest scan snapshot or null" }
                    }
                }
            },
            "/api/last-scan/yaml": {
                "get": {
                    "summary": "Download the previous scan snapshot as raw YAML",
                    "responses": {
                        "200": { "description": "Raw YAML document" },
                        "404": { "description": "No previous scan exists" }
                    }
                }
            },
            "/api/diff": {
                "post": {
                    "summary": "Compute diff between an uploaded YAML baseline and a current scan snapshot",
                    "responses": {
                        "200": { "description": "Computed diff object" }
                    }
                }
            }
        }
    })
}
