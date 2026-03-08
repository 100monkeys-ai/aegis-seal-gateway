use std::collections::HashMap;

use serde_json::Value;

use crate::domain::OperationSpec;
use crate::infrastructure::errors::GatewayError;

pub fn parse_operations(raw_spec: &Value) -> Result<HashMap<String, OperationSpec>, GatewayError> {
    let mut operations = HashMap::new();
    let paths = raw_spec
        .get("paths")
        .and_then(|v| v.as_object())
        .ok_or_else(|| GatewayError::Validation("OpenAPI spec missing paths".to_string()))?;

    for (path, methods) in paths {
        let Some(method_map) = methods.as_object() else {
            continue;
        };
        for (method, op_body) in method_map {
            let Some(op_id) = op_body.get("operationId").and_then(|v| v.as_str()) else {
                continue;
            };
            let op = OperationSpec {
                operation_id: op_id.to_string(),
                method: method.to_uppercase(),
                path: path.to_string(),
            };
            operations.insert(op_id.to_string(), op);
        }
    }

    if operations.is_empty() {
        return Err(GatewayError::Validation(
            "OpenAPI spec has no operationId definitions".to_string(),
        ));
    }

    Ok(operations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_operation_ids_from_paths() {
        let spec = serde_json::json!({
            "paths": {
                "/repos": {
                    "post": { "operationId": "createRepo" }
                }
            }
        });
        let operations = parse_operations(&spec).expect("should parse");
        let operation = operations.get("createRepo").expect("operation present");
        assert_eq!(operation.method, "POST");
        assert_eq!(operation.path, "/repos");
    }
}
