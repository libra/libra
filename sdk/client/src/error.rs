// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Allow dead_code so that we don't have to individually enable/disable parts when the 'async' or
// 'blocking' feature are enabled
#![allow(dead_code)]

use diem_json_rpc_types::{errors::JsonRpcError, stream::response::StreamJsonRpcResponse};

cfg_websocket! {
    use tokio_tungstenite::tungstenite;
}

pub type Result<T, E = Error> = ::std::result::Result<T, E>;

#[derive(Debug)]
pub struct Error {
    inner: Box<Inner>,
}

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug)]
struct Inner {
    kind: Kind,
    source: Option<BoxError>,
    json_rpc_error: Option<JsonRpcError>,
}

#[derive(Debug)]
enum Kind {
    HttpStatus(u16),
    Timeout,
    Request,
    JsonRpcError,
    RpcResponse,
    ChainId,
    StaleResponse,
    Batch,
    Decode,
    InvalidProof,
    NeedSync,
    Unknown,
}

impl Error {
    pub fn json_rpc_error(&self) -> Option<&JsonRpcError> {
        self.inner.json_rpc_error.as_ref()
    }

    pub fn is_retriable(&self) -> bool {
        match self.inner.kind {
            // internal server errors are retriable
            Kind::HttpStatus(status) => (500..=599).contains(&status),
            Kind::Timeout | Kind::StaleResponse | Kind::NeedSync => true,
            Kind::RpcResponse
            | Kind::Request
            | Kind::JsonRpcError
            | Kind::ChainId
            | Kind::Batch
            | Kind::Decode
            | Kind::InvalidProof
            | Kind::Unknown => false,
        }
    }

    pub fn is_need_sync(&self) -> bool {
        matches!(self.inner.kind, Kind::NeedSync)
    }

    //
    // Private Constructors
    //

    fn new<E: Into<BoxError>>(kind: Kind, source: Option<E>) -> Self {
        Self {
            inner: Box::new(Inner {
                kind,
                source: source.map(Into::into),
                json_rpc_error: None,
            }),
        }
    }

    fn with_json_rpc_error(mut self, json_rpc_error: JsonRpcError) -> Self {
        self.inner.json_rpc_error = Some(json_rpc_error);
        self
    }

    pub(crate) fn status(status: u16) -> Self {
        Self::new(Kind::HttpStatus(status), None::<Error>)
    }

    pub(crate) fn timeout<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Timeout, Some(e))
    }

    pub(crate) fn json_rpc(json_rpc_error: JsonRpcError) -> Self {
        Self::new(Kind::JsonRpcError, None::<Error>).with_json_rpc_error(json_rpc_error)
    }

    pub(crate) fn rpc_response<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::RpcResponse, Some(e))
    }

    pub(crate) fn batch<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Batch, Some(e))
    }

    pub(crate) fn decode<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Decode, Some(e))
    }

    pub(crate) fn encode<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Decode, Some(e))
    }

    pub(crate) fn invalid_proof<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::InvalidProof, Some(e))
    }

    pub(crate) fn need_sync<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::NeedSync, Some(e))
    }

    pub(crate) fn unknown<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Unknown, Some(e))
    }

    pub(crate) fn request<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::Request, Some(e))
    }

    pub(crate) fn chain_id(expected: u8, recieved: u8) -> Self {
        Self::new(
            Kind::ChainId,
            Some(format!("expected: {} recieved: {}", expected, recieved)),
        )
    }

    pub(crate) fn stale<E: Into<BoxError>>(e: E) -> Self {
        Self::new(Kind::StaleResponse, Some(e))
    }

    cfg_async! {
        pub(crate) fn from_reqwest_error(e: reqwest::Error) -> Self {
            if e.is_timeout() {
                Self::timeout(e)
            } else if e.is_request() {
                Self::request(e)
            } else if e.is_decode() {
                Self::decode(e)
            } else {
                Self::unknown(e)
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source.as_ref().map(|e| &**e as _)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::decode(e)
    }
}

cfg_websocket! {

    pub type StreamResult<T, E = StreamError> = ::std::result::Result<T, E>;

    #[derive(Debug)]
    pub enum StreamKind {
        HttpStatus(u16),
        Request,
        Decode,
        Encode,
        ConnectionClosed,
        MessageTooLarge,
        HttpError,
        TlsError,
        IdAlreadyUsed,
        IdNotFound(Option<StreamJsonRpcResponse>),
        QueueFullError,
        JsonRpcError,
        SubscriptionOkTimeout
    }

    #[derive(Debug)]
    pub struct StreamError {
        inner: Box<StreamInner>,
    }

    #[derive(Debug)]
    struct StreamInner {
        kind: StreamKind,
        source: Option<BoxError>,
        json_rpc_error: Option<JsonRpcError>,
    }

    impl StreamError {
        pub fn json_rpc_error(&self) -> Option<&JsonRpcError> {
            self.inner.json_rpc_error.as_ref()
        }

        pub(crate) fn from_tungstenite_error(e: tungstenite::Error) -> Self {
            match e {
                tungstenite::Error::ConnectionClosed => Self::connection_closed(None::<Self>),
                tungstenite::Error::AlreadyClosed => Self::connection_closed(None::<Self>),
                tungstenite::Error::Io(e) => Self::connection_closed(Some(e)),
                tungstenite::Error::Tls(e) => Self::new(StreamKind::TlsError, Some(e)),
                tungstenite::Error::Capacity(e) => Self::new(StreamKind::MessageTooLarge, Some(e)),
                tungstenite::Error::Protocol(e) => Self::connection_closed(Some(e)),
                tungstenite::Error::SendQueueFull(_) => {
                    Self::new(StreamKind::QueueFullError, None::<Self>)
                }
                tungstenite::Error::Utf8 => Self::encode(e),
                tungstenite::Error::Url(e) => Self::new(StreamKind::Request, Some(e)),
                tungstenite::Error::Http(e) => {
                    Self::new(StreamKind::HttpStatus(e.status().as_u16()), None::<Self>)
                }
                tungstenite::Error::HttpFormat(e) => Self::new(StreamKind::HttpError, Some(e)),
            }
        }

        pub(crate) fn decode<E: Into<BoxError>>(e: E) -> Self {
            Self::new(StreamKind::Decode, Some(e))
        }

        pub(crate) fn encode<E: Into<BoxError>>(e: E) -> Self {
            Self::new(StreamKind::Encode, Some(e))
        }

        pub(crate) fn from_http_error(e: tungstenite::http::Error) -> Self {
            Self::new(StreamKind::HttpError, Some(e))
        }

        pub(crate) fn connection_closed<E: Into<BoxError>>(e: Option<E>) -> Self {
            Self::new(StreamKind::ConnectionClosed, e)
        }

        pub(crate) fn subscription_id_already_used<E: Into<BoxError>>(e: Option<E>) -> Self {
            Self::new(StreamKind::IdAlreadyUsed, e)
        }

        pub(crate) fn subscription_ok_timeout() -> Self {
            Self::new(StreamKind::SubscriptionOkTimeout, None::<Self>)
        }

        pub(crate) fn subscription_json_rpc_error(error: JsonRpcError) -> Self{
            Self {
                inner: Box::new(StreamInner {
                    kind: StreamKind::JsonRpcError,
                    source: None,
                    json_rpc_error: Some(error),
                }),
            }
        }

        fn new<E: Into<BoxError>>(kind: StreamKind, source: Option<E>) -> Self {
            Self {
                inner: Box::new(StreamInner {
                    kind,
                    source: source.map(Into::into),
                    json_rpc_error: None,
                }),
            }
        }
    }

    impl From<serde_json::Error> for StreamError {
        fn from(e: serde_json::Error) -> Self {
            Self::decode(e)
        }
    }

    impl std::fmt::Display for StreamError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    impl std::error::Error for StreamError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.inner.source.as_ref().map(|e| &**e as _)
        }
    }

}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum WaitForTransactionError {
    // Get account transaction error
    GetTransactionError(Error),
    // Transaction hash does not match transaction hash argument
    TransactionHashMismatchError(diem_json_rpc_types::views::TransactionView),
    // Got transaction and it's vm_status#type is not "executed" (execution success)
    TransactionExecutionFailed(diem_json_rpc_types::views::TransactionView),
    // Wait timeout
    Timeout,
    // Transaction not found, latest known block (ledger info) timestamp is more recent
    // than expiration_time_secs argument.
    TransactionExpired,
}

impl std::fmt::Display for WaitForTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

impl std::error::Error for WaitForTransactionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WaitForTransactionError::GetTransactionError(e) => Some(e),
            _ => None,
        }
    }
}
