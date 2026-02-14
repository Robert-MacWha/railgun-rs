use std::pin::Pin;

use futures::Stream;
use thiserror::Error;

use super::types::WakuMessage;

#[derive(Debug, Error)]
pub enum WakuTransportError {
    #[error("Subscription failed: {0}")]
    SubscriptionFailed(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
}

#[cfg(not(feature = "wasm"))]
pub type MessageStream = Pin<Box<dyn Stream<Item = WakuMessage> + Send>>;

#[cfg(feature = "wasm")]
pub type MessageStream = Pin<Box<dyn Stream<Item = WakuMessage>>>;

/// Transport layer for Waku network communication.
#[cfg(not(feature = "wasm"))]
#[async_trait::async_trait]
pub trait WakuTransport: Send + Sync {
    /// Subscribe to messages on the given content topics.
    ///
    /// Returns a stream of messages received on any of the subscribed topics.
    /// The subscription remains active until the stream is dropped.
    async fn subscribe(
        &self,
        content_topics: Vec<String>,
    ) -> Result<MessageStream, WakuTransportError>;

    /// Send a message to the given content topic.
    async fn send(&self, content_topic: &str, payload: Vec<u8>) -> Result<(), WakuTransportError>;
}

/// Transport layer for Waku network communication (WASM version).
///
/// This trait abstracts the Waku network operations, allowing for
/// dependency injection of different implementations.
#[cfg(feature = "wasm")]
#[async_trait::async_trait(?Send)]
pub trait WakuTransport {
    /// Subscribe to messages on the given content topics.
    ///
    /// Returns a stream of messages received on any of the subscribed topics.
    /// The subscription remains active until the stream is dropped.
    async fn subscribe(
        &self,
        content_topics: Vec<String>,
    ) -> Result<MessageStream, WakuTransportError>;

    /// Send a message to the given content topic.
    async fn send(&self, content_topic: &str, payload: Vec<u8>) -> Result<(), WakuTransportError>;
}
