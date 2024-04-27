use bitcoincore_rpc::Error as BitcoinCoreRpcError;
use reqwest::Error as ReqwestError;
use thiserror::Error;
use url::ParseError;

use crate::jsonrpc::JsonRpcError;

/// Errors for relay requests.
#[derive(Error, Debug)]
pub enum Error {
    /// The request failed.
    #[error(transparent)]
    RequestError(#[from] ReqwestError),
    /// The request could not be parsed.
    #[error(transparent)]
    JsonRpcError(#[from] JsonRpcError),
    /// The request parameters were invalid.
    #[error("Client error: {text}")]
    ClientError { text: String },
    /// The server's error.
    #[error("Server error: {text}")]
    ServerError { text: String },
    /// The request could not be serialized.
    #[error(transparent)]
    RequestSerdeJson(#[from] serde_json::Error),
    /// The response could not be deserialized.
    #[error("Deserialization error: {err}. Response: {text}")]
    ResponseSerdeJson {
        err: serde_json::Error,
        text: String,
    },
    /// The bitcoin failed.
    #[error(transparent)]
    BitcoinCoreRpcError(#[from] BitcoinCoreRpcError),
    /// The url failed.
    #[error(transparent)]
    UrlParseError(#[from] ParseError),
}
