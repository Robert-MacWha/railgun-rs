/**
 * @module Broadcaster
 * @description Railgun broadcasters are used to relay transactions to the railgun network
 * without needing to send a transaction yourself. This lets users avoid de-anonymization
 * when seeding new private accounts.
 * 
 * Broadcasters will only relay transactions if they are paid a fee and if they receive
 * a valid proof of inocence (POI) for the transaction. Broadcasters will broadcast
 * these restrictions via Waku messages.
 * 
 * @see https://docs.railgun.org/developer-guide/wallet/broadcasters
 * @see https://docs.waku.org/
 * @see https://github.com/Railgun-Community/waku-broadcaster-client
 */

import { bytesToUtf8, createDecoder, createLightNode, IDecodedMessage, LightNode } from "@waku/sdk";
import { Address, fromHex, Hex } from "viem";

type RailgunAddress = String;

interface BroadcasterFeeMessage {
    data: string;
    signature: string;
};

interface BroadcasterFeeMessageData {
    fees: Record<Address, Hex>;
    feeExpiration: number;
    feesID: string;
    railgunAddress: RailgunAddress;
    identifier?: string;
    availableWallets: number;
    version: string;
    relayAdapt: Address;
    requiredPOIListKeys: string[];
    reliability: number;
};

interface TokenFee {
    feePerUnitGas: bigint;
    expiration: number;
    feesID: string;
    availableWallets: number;
    relayAdapt: Address;
    reliability: number;
};

const WAKU_RAILGUN_PUB_SUB_TOPIC = '/waku/2/rs/1/1';
const WAKU_RAILGUN_DEFAULT_SHARD = {
    clusterId: 1,
    shard: 1,
    shardId: 1,
    pubsubTopic: WAKU_RAILGUN_PUB_SUB_TOPIC,
};
const BROADCASTER_VERSION = '8';

/**
 * Broadcasters maintains a list of known railgun broadcasters for a given Chain.
 * 
 * Creates a client that connects to the waku network in the background.\
 * 
 * 
 * @todo: Add the ability to set a list of known trusted broadcasters, where all
 * others are ignored.
 * 
 * @todo: The official railgun SDK filters out broadcasters to only include broadcasters (a)
 * broadcasting fees for tokens that are also broadcasted by trusted broadcasters and (b)
 * broadcasters whos fees are competitive. I don't see much point implementing this since
 * we'll just use the most competitive working broadcaster?
 */
export class Broadcasters {
    private readonly broadcasters: Map<RailgunAddress, BroadcasterFeeMessageData>
    private readonly tokenFees: Map<Address, Map<RailgunAddress, TokenFee>>;

    constructor(private readonly chain_id: number, private readonly node: LightNode) {
        this.broadcasters = new Map();
        this.tokenFees = new Map();
    }

    /**
     * Creates and starts a Broadcaster client for the given chain.
     * 
     * The broadcaster automatically connects to the waku network and collects
     * fee information from broadcasters.
     * 
     * @param chainId CAIP-2 chain ID
     * @returns Started Broadcasters client
     * 
     * @todo Consider making the `node` a singleton to avoid multiple connections.
     * If do want to support multiple chains or multiple railgun accounts this would be a good
     * idea.
     */
    static async create(chain_id: number): Promise<Broadcasters> {
        const node = await createLightNode({
            defaultBootstrap: true,
        });
        await node.start();

        const broadcaster = new Broadcasters(chain_id, node);

        const feeDecoder = createDecoder(feeContentTopic(chain_id), WAKU_RAILGUN_DEFAULT_SHARD)
        const decoders = [feeDecoder];
        console.log("Subscribing to broadcaster fee topic:", decoders);
        node.filter.subscribe(decoders, (msg) => {
            console.log("Received message on topic:", msg.contentTopic);
            try {
                if (msg.contentTopic === feeContentTopic(chain_id)) {
                    broadcaster.handleFeesMessage(msg);
                    return;
                }
                console.log("Received message on unknown topic:", msg.contentTopic);

            } catch (err) {
                console.error("Error handling broadcaster message:", err);
            }
        });

        return broadcaster;
    }

    async stop(): Promise<void> {
        await this.node.stop();
    }

    async handleFeesMessage(msg: IDecodedMessage) {
        const { feeMessageData, signature } = await decodeBroadcasterFeeMessage(msg.payload);
        if (!feeMessageData.fees) {
            return;
        }

        console.log(feeMessageData);
        this.broadcasters.set(feeMessageData.railgunAddress, feeMessageData);

        for (const [_tokenAddress, _feePerUnitGas] of Object.entries(feeMessageData.fees)) {
            const tokenAddress = _tokenAddress as Address;
            const feePerUnitGas = BigInt(_feePerUnitGas as Hex);
            let tokenFeeMap = this.tokenFees.get(tokenAddress);
            if (!tokenFeeMap) {
                tokenFeeMap = new Map();
                this.tokenFees.set(tokenAddress, tokenFeeMap);
            }

            tokenFeeMap.set(feeMessageData.railgunAddress, {
                feePerUnitGas,
                expiration: feeMessageData.feeExpiration,
                feesID: feeMessageData.feesID,
                availableWallets: feeMessageData.availableWallets,
                relayAdapt: feeMessageData.relayAdapt,
                reliability: feeMessageData.reliability,
            });
        };
    }
}

async function decodeBroadcasterFeeMessage(payload: Uint8Array): Promise<{ feeMessageData: BroadcasterFeeMessageData, signature: string }> {
    const { data, signature } = JSON.parse(bytesToUtf8(payload)) as BroadcasterFeeMessage;
    const utf8String = fromHex(data as Hex, { to: 'string' });
    const feeMessageData = JSON.parse(utf8String) as BroadcasterFeeMessageData;

    const broadcasterMajorVersion = feeMessageData.version.split('.')[0];
    if (broadcasterMajorVersion !== BROADCASTER_VERSION) {
        throw new Error(`Incompatible broadcaster version: got: ${feeMessageData.version} expected: ${BROADCASTER_VERSION}`);
    }

    return { feeMessageData, signature };
}

function feeContentTopic(chain_id: number): string {
    const cid = `0-${chain_id}`;
    return `/railgun/v2/${cid}-fees/json`;
}
