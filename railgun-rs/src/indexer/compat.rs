use std::pin::Pin;

use futures::Stream;

use super::syncer::SyncEvent;

/// Boxed error type that is `Send + Sync` on native but not on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(target_arch = "wasm32")]
pub type BoxedError = Box<dyn std::error::Error>;

/// Boxed stream type that is `Send` on native but not on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSyncStream<'a> = Pin<Box<dyn Stream<Item = SyncEvent> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxedSyncStream<'a> = Pin<Box<dyn Stream<Item = SyncEvent> + 'a>>;

/// Trait alias for Send bound that only applies on native.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}
