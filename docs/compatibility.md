# Compatibility

Great pains have been taken to ensure that the Rust SDK is 100% compatible with the TypeScript SDK. This means that the Rust SDK should be able to act as a drop-in replacement, and should work with existing railgun architectures.

## Casing

The rust SDK uses snake_case for all field names, and serializes to camelCase for external use. This maintains compatibility with the typescript SDK, which uses camelCase.

## Hex Strings

The typescript SDK is incredibly inconsistent with hex strings.  Some fields are serialized as decimal strings, some to hex strings with a 0x prefix, and some to hex strings without a 0x prefix.  The same type is often serialized in multiple different ways.

For example, in the `poi-validation.test.ts` test file, the `Txid` type is serialized as a hex string with a 0x prefix going into the test, but is returned as a hex string without a 0x prefix in the test output.

```typescript
// https://github.com/Railgun-Community/engine/blob/349debb349de286c991619c471dc8da150119a86/src/validation/__tests__/poi-validation.test.ts#L118
const pois: PreTransactionPOIsPerTxidLeafPerList = {
    test_list: {
        "136f24c883d58d7130d8e001a043bad3b2b09a36104bec5b6a0f8181b7d0fa70": {
            // ... other fields
            railgunTxidIfHasUnshield: "0x0fefd169291c1deec2affa8dcbfbee4a4bbeddfc3b5723c031665ba631725c62",
        }
    },
}

// https://github.com/Railgun-Community/engine/blob/349debb349de286c991619c471dc8da150119a86/src/validation/__tests__/poi-validation.test.ts#L139
expect(validSpendable).to.deep.equal({
    isValid: true,
    extractedRailgunTransactionData: [{
        // Same TxID, but without the 0x prefix
        railgunTxid: "0fefd169291c1deec2affa8dcbfbee4a4bbeddfc3b5723c031665ba631725c62",
        // ... other fields
    }],
});
```

In general:
- On-chain objects (eg `Address`, transaction calldata, nullifiers) use hex WITH 0x prefix
- Blinded commitments use hex WITH 0x prefix
- Merkle roots and merkle leaves (ie `Txid`, `TxidLeafHash`, `UtxoLeafHash`) use hex WITHOUT 0x prefix
- SnarkJS proofs (`snarkjs_proof`) use decimal strings

In general, the Rust SDK will always serialize hex strings without a 0x prefix, and will always deserialize hex strings with or without a 0x prefix. In specific cases, the Rust SDK may serialize hex strings with a 0x prefix if essential for compatibility.
