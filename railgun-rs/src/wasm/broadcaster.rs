use std::pin::Pin;

use futures::Stream;
use futures::channel::mpsc::{self, UnboundedReceiver};
use js_sys::{Array, Function, Uint8Array};
use thiserror::Error;
use tracing::warn;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::railgun::broadcaster::broadcaster::{Broadcaster, Fee};
use crate::railgun::broadcaster::broadcaster_manager::BroadcasterManager;
use crate::railgun::broadcaster::transport::{MessageStream, WakuTransport, WakuTransportError};
use crate::railgun::broadcaster::types::WakuMessage;

/// Error type for JS Waku transport operations.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum JsWakuTransportError {
    #[error("Serde error: {0}")]
    Serde(#[from] serde_wasm_bindgen::Error),
    #[error("JS Error: {0:?}")]
    Js(JsValue),
}

/// JavaScript-backed Waku transport that delegates to JS functions.
///
/// The subscribe function must have the signature:
/// ```typescript
/// type SubscribeFn = (
///   topics: string[],
///   onMessage: (msg: WakuMessage) => void
/// ) => Promise<void>;
/// ```
///
/// The send function must have the signature:
/// ```typescript
/// type SendFn = (
///   topic: string,
///   payload: Uint8Array
/// ) => Promise<void>;
/// ```
#[wasm_bindgen]
pub struct JsBroadcasterManager {
    inner: BroadcasterManager,
}

#[wasm_bindgen]
pub struct JsBroadcaster {
    inner: Broadcaster,
}

#[wasm_bindgen]
pub struct JsFee {
    inner: Fee,
}

struct JsWakuTransport {
    subscribe_fn: Function,
    send_fn: Function,
}

struct ReceiverStream(UnboundedReceiver<WakuMessage>);

#[wasm_bindgen]
impl JsBroadcasterManager {
    #[wasm_bindgen(constructor)]
    pub fn new(chain_id: u64, subscribe_fn: Function, send_fn: Function) -> Self {
        let transport = JsWakuTransport::new(subscribe_fn, send_fn);
        let inner = BroadcasterManager::new(chain_id, transport);
        Self { inner }
    }

    #[wasm_bindgen]
    pub fn start(&mut self) {
        let inner = self.inner.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = inner.start().await {
                warn!("BroadcasterManager error: {}", e);
            }
        });
    }

    #[wasm_bindgen]
    pub async fn best_broadcaster_for_token(
        &self,
        token_address: String,
        current_time: u64,
    ) -> Option<JsBroadcaster> {
        let token = token_address.parse().ok()?;
        self.inner
            .best_broadcaster_for_token(token, current_time)
            .await
            .map(|b| JsBroadcaster { inner: b })
    }
}

impl JsBroadcasterManager {
    pub fn inner(&self) -> &BroadcasterManager {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut BroadcasterManager {
        &mut self.inner
    }
}

#[wasm_bindgen]
impl JsBroadcaster {
    #[wasm_bindgen]
    pub fn fee(&self) -> JsFee {
        JsFee {
            inner: self.inner.fee.clone(),
        }
    }
}

impl JsBroadcaster {
    pub fn inner(&self) -> &Broadcaster {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut Broadcaster {
        &mut self.inner
    }
}

impl JsFee {
    pub fn inner(&self) -> &Fee {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut Fee {
        &mut self.inner
    }
}

impl JsWakuTransport {
    pub fn new(subscribe_fn: Function, send_fn: Function) -> Self {
        Self {
            subscribe_fn,
            send_fn,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl WakuTransport for JsWakuTransport {
    async fn subscribe(
        &self,
        content_topics: Vec<String>,
    ) -> Result<MessageStream, WakuTransportError> {
        let (tx, rx) = mpsc::unbounded::<WakuMessage>();

        // Convert topics to JS array
        let topics_array = Array::new();
        for topic in content_topics {
            topics_array.push(&JsValue::from_str(&topic));
        }

        // Create closure that sends messages to the channel
        let on_message: Closure<dyn Fn(JsValue)> =
            Closure::wrap(Box::new(
                move |msg: JsValue| match serde_wasm_bindgen::from_value::<WakuMessage>(msg) {
                    Ok(waku_msg) => {
                        if tx.unbounded_send(waku_msg).is_err() {
                            warn!("Failed to send message to channel (receiver dropped)");
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse WakuMessage from JS: {}", e);
                    }
                },
            ));

        let on_message_fn = on_message.as_ref().unchecked_ref::<Function>().clone();

        // Keep the closure alive for the lifetime of the subscription.
        // This leaks memory, but the subscription is expected to live for the
        // lifetime of the application.
        on_message.forget();

        // Call subscribe_fn(topics, onMessage)
        let this = JsValue::NULL;
        let promise = self
            .subscribe_fn
            .call2(&this, &topics_array.into(), &on_message_fn)
            .map_err(|e| WakuTransportError::SubscriptionFailed(format!("{:?}", e)))?;

        let promise = js_sys::Promise::from(promise);
        JsFuture::from(promise)
            .await
            .map_err(|e| WakuTransportError::SubscriptionFailed(format!("{:?}", e)))?;

        Ok(Box::pin(ReceiverStream(rx)))
    }

    async fn send(&self, content_topic: &str, payload: Vec<u8>) -> Result<(), WakuTransportError> {
        let this = JsValue::NULL;
        let topic_js = JsValue::from_str(content_topic);
        let payload_js = Uint8Array::from(payload.as_slice());

        let promise = self
            .send_fn
            .call2(&this, &topic_js, &payload_js.into())
            .map_err(|e| WakuTransportError::SendFailed(format!("{:?}", e)))?;

        let promise = js_sys::Promise::from(promise);
        JsFuture::from(promise)
            .await
            .map_err(|e| WakuTransportError::SendFailed(format!("{:?}", e)))?;

        Ok(())
    }
}

impl Stream for ReceiverStream {
    type Item = WakuMessage;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}
