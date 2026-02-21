# Secret Management

Secret data includes:
- Mnemonic phrases
- EVM private keys
- Railgun private keys (spending + viewing)
- Decrypted notes
- Private circuit inputs
- Note out data (npks_out / values_out)

In general, secret data should never be directly stored by the SDK. The SDK should aim to only store encrypted data from on-chain events.
- We almost certainly need to store note out data somewhere, at least temporarily. In order to submit a transaction to the POI node we need to (a) wait for it to be indexed, and (b) re-generate the POI proof data. This requires the note out data, which is not accessible on-chain for operations sending to different addresses. Because we rely on subsquid for txid indexing, we can't generate the POI proof instantly on the event of the transaction being mined, but instead wait for subsquid.  If the SDK were restarted during this time, the note out data would be lost and the transaction wouldn't be able to be submitted to the POI node.

## Privacy Concerns
- Consider whether the SDK pruning event data could lead to privacy leaks if compromised. For example, a compromised SDK might reveal which notes are owned by the user and corelate volumes and decrypted note data.
- Consider if there's a way to avoid storing the note out data. If we could index the txid tree on-chain instead of via subsquid, we could generate the POI proof data immediately and discard the note out data.
  - I'm told by HB that there will be an update that adds on-chain events for the TXID tree, which would make this doable. Coming sometime in the next month or so.
