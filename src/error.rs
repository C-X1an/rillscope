//! Closed, value-free errors for all public paths.
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ErrorCode {
    #[serde(rename = "E_INPUT")]
    Input,
    #[serde(rename = "E_UNSUPPORTED")]
    Unsupported,
    #[serde(rename = "E_BIND")]
    Bind,
    #[serde(rename = "E_TYPE")]
    Type,
    #[serde(rename = "E_FORBIDDEN")]
    Forbidden,
    #[serde(rename = "E_CATALOG")]
    Catalog,
    #[serde(rename = "E_CONTEXT")]
    Context,
    #[serde(rename = "E_PLAN")]
    Plan,
    #[serde(rename = "E_LIMIT")]
    Limit,
    #[serde(rename = "E_BUDGET")]
    Budget,
    #[serde(rename = "E_OUTPUT_LIMIT")]
    OutputLimit,
    #[serde(rename = "E_CANCELLED")]
    Cancelled,
    #[serde(rename = "E_OVERFLOW")]
    Overflow,
    #[serde(rename = "E_INTERNAL")]
    Internal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct QueryError {
    pub code: ErrorCode,
    pub phase: &'static str,
    pub message: &'static str,
}

impl QueryError {
    pub fn new(code: ErrorCode) -> Self {
        use ErrorCode::*;
        let (phase, message) = match code {
            Input => ("decode", "invalid or unsupported input fields"),
            Unsupported => ("decode", "unsupported query construct"),
            Bind => ("bind", "unknown or ambiguous column"),
            Type => ("bind", "incompatible data types"),
            Forbidden => ("bind", "column or table is not available in this scope"),
            Catalog => ("catalog", "invalid catalog"),
            Context => ("context", "invalid trusted context"),
            Plan => ("verify", "invalid plan authority or provenance"),
            Limit => ("decode", "input or configuration limit exceeded"),
            Budget => ("execute", "work or logical memory budget exceeded"),
            OutputLimit => ("collect", "output limit exceeded"),
            Cancelled => ("execute", "query cancelled"),
            Overflow => ("execute", "integer overflow"),
            Internal => ("execute", "internal execution failure"),
        };
        Self {
            code,
            phase,
            message,
        }
    }

    pub fn exit_code(self) -> u8 {
        use ErrorCode::*;
        match self.code {
            Input | Unsupported | Bind | Type | Forbidden => 2,
            Limit | Budget | OutputLimit => 3,
            Cancelled => 4,
            Catalog | Context => 5,
            Plan | Overflow | Internal => 6,
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for QueryError {}
impl From<ErrorCode> for QueryError {
    fn from(value: ErrorCode) -> Self {
        Self::new(value)
    }
}
pub type Result<T> = std::result::Result<T, QueryError>;
