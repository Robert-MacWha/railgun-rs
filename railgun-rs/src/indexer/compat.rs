use std::pin::Pin;

use futures::Stream;

use super::syncer::SyncEvent;

/// Boxed error type that is `Send + Sync` on native but not on WASM.
#[cfg(not(feature = "wasm"))]
pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(feature = "wasm")]
pub type BoxedError = Box<dyn std::error::Error>;

/// Boxed stream type that is `Send` on native but not on WASM.
#[cfg(not(feature = "wasm"))]
pub type BoxedSyncStream<'a> = Pin<Box<dyn Stream<Item = SyncEvent> + Send + 'a>>;

#[cfg(feature = "wasm")]
pub type BoxedSyncStream<'a> = Pin<Box<dyn Stream<Item = SyncEvent> + 'a>>;

/// Trait alias for Send bound that only applies on native.
#[cfg(not(feature = "wasm"))]
pub trait MaybeSend: Send {}

#[cfg(not(feature = "wasm"))]
impl<T: Send> MaybeSend for T {}

#[cfg(feature = "wasm")]
pub trait MaybeSend {}

#[cfg(feature = "wasm")]
impl<T> MaybeSend for T {}
