So basically broadcasters:

1. Submit whatever transaction you call for them to.
   1. The tx you submit is encrypted and sent over the waku network.
      1. https://github.com/Railgun-Community/waku-broadcaster-client/blob/1cd94e556ed02ac9d830dff10b8d5896a05753d4/packages/common/src/transact/broadcaster-transaction.ts#L203
      2. `BroadcastMessageData`,
      3. Calling the `transact` method
   2. The `to` address must either be the railgun relay adapter contract or the smart wallet contract.
   3. The `data` is the contract call data to the `to` address.
2. You pay them a fee, equal to `estimate_gas * feePerUnitGas`.
   1. The fee must be paid in one of their advertised fee tokens.
   2. The fee must be paid in the first output note.
      1. Because the fee is paid in a note, it adds a note, changes the input data, which changes the gas estimate. So you need to iteratively converge on the fee.
   3. Consequentially - the fee must be paid in a single token.


Info from broadcasters:
```js
{
  fees: {
    // [tokenAddress]: feePerUnitGas
    '0xfff9976782d46cc05630d1f6ebab18b2324d6b14': '0xcc47f20295c0000',
    '0x97a36608da67af0a79e50cb6343f86f340b3b49e': '0xcc47f20295c0000',
    '0x3e622317f8c93f7328350cf0b56d9ed4c620c5d6': '0xcc47f20295c0000'
  },
  feeExpiration: 1770510282367,
  feesID: 'akfpv0ht1k6tf6bq',
  railgunAddress: '0zk1qyqhtwaa9zj3ug9dmxhfedappvm509w7dr5lgadaehxz38w9u457mrv7j6fe3z53layes62mktxj5kd6reh2kxd39ds2gnpf6wphtw39y5g36lsvukeywfqa8y0',
  availableWallets: 2,
  version: '8.2.3',
  relayAdapt: '0x7e3d929EbD5bDC84d02Bd3205c777578f33A214D',
  requiredPOIListKeys: [
    'efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88'
  ],
  reliability: 0.45
}
```

Unencrypted data:
https://github.com/Railgun-Community/shared-models/blob/dc3af7873305938f9f0771a24ad91f807f1b88e0/src/models/broadcaster.ts#L75
```js
type BroadcasterRawParamsShared = {
  chainID: number;
  chainType: ChainType;
  useRelayAdapt: boolean; // Depends on to address
  to: string;
  data: string;
  minGasPrice: string; // just `gasPrice` or `maxFeePerGas` from the transaction gas estimate
  txidVersion: TXIDVersion;
  feesID: string; // from broadcaster info
  broadcasterViewingKey: string; // from broadcaster railgun address
  devLog: boolean; // From config (https://github.com/Railgun-Community/waku-broadcaster-client/blob/main/packages/common/src/models/broadcaster-config.ts#L5)
  minVersion: string;  // From config
  maxVersion: string; // From config
  preTransactionPOIsPerTxidLeafPerList: PreTransactionPOIsPerTxidLeafPerList; // Collection of all list keys, new operation hashes, and proofs for that operation.
  transactType: BroadcasterTransactRequestType.COMMON;
};

export type PreTransactionPOIsPerTxidLeafPerList = Record<
  string, // listKey
  Record<
    string, // txidLeafHash
    PreTransactionPOI
  >
>;

export type PreTransactionPOI = {
  snarkProof: Proof;
  txidMerkleroot: string;
  poiMerkleroots: string[];
  blindedCommitmentsOut: string[];
  railgunTxidIfHasUnshield: string;
};
```

Encrypt with the broadcaster's viewing key:
```js
const { viewingPublicKey: broadcasterViewingKey } = getRailgunWalletAddressData(broadcasterRailgunAddress);

const encryptedDataResponse = await encryptDataWithSharedKey(
   transactData,
   broadcasterViewingKey,
);
```

txIdLeafHash:
```js
export const getRailgunTxidLeafHash = (
  railgunTxidBigInt: bigint, // hash of [nullifiers, commitments, boundParamsHash]
  utxoTreeIn: bigint, // the tree the in_notes are coming from
  globalTreePosition: bigint, // For transactions pre-submission, equal to the below constant (I think).
): string => {
  return ByteUtils.nToHex(
    poseidon([railgunTxidBigInt, utxoTreeIn, globalTreePosition]),
    ByteLength.UINT_256,
  );
};
```

globalTreePosition:
```js
export const GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE = 99999;
export const GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE = 99999;
export const GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE = 199999;
export const GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE = 199999;

export const getGlobalTreePosition = (tree: number, index: number): bigint => {
  return BigInt(tree * TREE_MAX_ITEMS + index);
};

export const getGlobalTreePositionPreTransactionPOIProof = (): bigint => {
  return getGlobalTreePosition(
    GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
    GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
  );
};

```

txId:
```js
export const getRailgunTransactionID = (railgunTransaction: {
  nullifiers: string[];
  commitments: string[];
  boundParamsHash: string;
}): bigint => {
  const nullifierBigInts = railgunTransaction.nullifiers.map((el) => ByteUtils.hexToBigInt(el));
  const commitmentBigInts = railgunTransaction.commitments.map((el) => ByteUtils.hexToBigInt(el));
  const boundParamsHashBigInt = ByteUtils.hexToBigInt(railgunTransaction.boundParamsHash);
  return getRailgunTransactionIDFromBigInts(
    nullifierBigInts,
    commitmentBigInts,
    boundParamsHashBigInt,
  );
};
```

