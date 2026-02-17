/**
 * @module WakuTransport
 * @description Helper to create a WakuTransport from a Waku LightNode.
 */

import {
  createDecoder,
  createEncoder,
  createLightNode,
  CreateNodeOptions,
  type IDecodedMessage,
  type LightNode,
} from "@waku/sdk";
import { getWasm } from "./wasm.ts";
import { JsBroadcasterManager, WakuMessage } from "../pkg/railgun_rs";

const WAKU_RAILGUN_PUB_SUB_TOPIC = '/waku/2/rs/1/1';
const WAKU_RAILGUN_SHARD_CONFIG = {
  clusterId: 1,
  shard: 1,
  shardId: 1,
  pubsubTopic: WAKU_RAILGUN_PUB_SUB_TOPIC,
};

/**
 * Subscribe function signature expected by JsBroadcaster.
 *
 * @param topics - Content topics to subscribe to
 * @param onMessage - Callback invoked when a message is received
  * @returns Promise that resolves when the subscription is setup
 */
type SubscribeFn = (
  topics: string[],
  onMessage: (msg: WakuMessage) => void
) => Promise<void>;

/**
 * Send function signature expected by JsBroadcaster.
 *
 * @param topic - Content topic to send to
 * @param payload - Message payload
 * @returns Promise that resolves when the message is sent
 */
type SendFn = (topic: string, payload: Uint8Array) => Promise<void>;

/**
 * Creates a JsBroadcaster instance by initializing a Waku LightNode with the 
 * provided options.
 */
export async function createBroadcaster(chain_id: bigint, options: CreateNodeOptions = { defaultBootstrap: true }): Promise<JsBroadcasterManager> {
  const node = await createLightNode(options);
  await node.start();

  return createBroadcasterFromNode(chain_id, node);
}

/**
 * Create a JsBroadcaster instance from an existing Waku LightNode.
 */
export function createBroadcasterFromNode(chain_id: bigint, node: LightNode): JsBroadcasterManager {
  const { JsBroadcaster } = getWasm();

  const subscribeFn: SubscribeFn = async (topics, onMessage) => {
    console.log("Subscribing to topics:", topics);
    const decoders = topics.map((topic) =>
      createDecoder(topic, WAKU_RAILGUN_SHARD_CONFIG)
    );

    await node.filter.subscribe(
      decoders,
      (wakuMsg: IDecodedMessage) => {
        const msg: WakuMessage = {
          payload: Array.from(wakuMsg.payload),
          contentTopic: wakuMsg.contentTopic,
          timestamp: wakuMsg.timestamp
            ? wakuMsg.timestamp.getTime()
            : undefined,
        };
        console.log("Received message on topic:", wakuMsg.contentTopic);
        onMessage(msg);
      }
    );
  };

  const sendFn: SendFn = async (topic, payload) => {
    const encoder = createEncoder({
      contentTopic: topic,
      routingInfo: WAKU_RAILGUN_SHARD_CONFIG,
    });

    await node.lightPush.send(encoder, { payload });
  };

  return new JsBroadcasterManager(chain_id, subscribeFn, sendFn);
}