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
  type QueryRequestParams,
} from "@waku/sdk";
import { getWasm } from "./wasm.ts";
import { JsBroadcasterManager, WakuMessage } from "../pkg/railgun_rs";

const WAKU_RAILGUN_PUB_SUB_TOPIC = "/waku/2/rs/1/1";
const WAKU_RAILGUN_SHARD_CONFIG = {
  clusterId: 1,
  shard: 1,
  shardId: 1,
  pubsubTopic: WAKU_RAILGUN_PUB_SUB_TOPIC,
};

/** Historical look-back window in milliseconds (60 seconds). */
const HISTORICAL_LOOK_BACK_MS = 60_000;

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
 * Retrieve historical messages for a content topic.
 *
 * Returns all matching messages within the look-back window in
 * chronological order. Tracks cursors internally so subsequent calls
 * only return new messages.
 *
 * @param topic - Content topic to query
 * @returns Promise resolving to an array of WakuMessages
 */
type RetrieveHistoricalFn = (topic: string) => Promise<WakuMessage[]>;

/**
 * Creates a JsBroadcaster instance by initializing a Waku LightNode with the
 * provided options.
 */
export async function createBroadcaster(
  chain_id: bigint,
  options: CreateNodeOptions = { defaultBootstrap: true }
): Promise<JsBroadcasterManager> {
  const node = await createLightNode(options);
  await node.start();

  return createBroadcasterFromNode(chain_id, node);
}

/**
 * Create a JsBroadcaster instance from an existing Waku LightNode.
 */
export function createBroadcasterFromNode(
  chain_id: bigint,
  node: LightNode
): JsBroadcasterManager {
  const { JsBroadcasterManager: JsBroadcasterManagerClass } = getWasm();

  const subscribeFn: SubscribeFn = async (topics, onMessage) => {
    console.log("Subscribing to topics:", topics);
    const decoders = topics.map((topic) =>
      createDecoder(topic, WAKU_RAILGUN_SHARD_CONFIG)
    );

    await node.filter.subscribe(decoders, (wakuMsg: IDecodedMessage) => {
      const msg: WakuMessage = {
        payload: Array.from(wakuMsg.payload),
        contentTopic: wakuMsg.contentTopic,
        timestamp: wakuMsg.timestamp
          ? wakuMsg.timestamp.getTime()
          : undefined,
      };
      console.log("Received message on topic:", wakuMsg.contentTopic);
      onMessage(msg);
    });
  };

  const sendFn: SendFn = async (topic, payload) => {
    const encoder = createEncoder({
      contentTopic: topic,
      routingInfo: WAKU_RAILGUN_SHARD_CONFIG,
    });

    await node.lightPush.send(encoder, { payload });
  };

  // Track the last message per topic for cursor-based pagination.
  const lastMessageByTopic = new Map<string, IDecodedMessage>();

  const retrieveHistoricalFn: RetrieveHistoricalFn = async (topic) => {
    const decoder = createDecoder(topic, WAKU_RAILGUN_SHARD_CONFIG);
    const messages: WakuMessage[] = [];

    const options: QueryRequestParams = {
      includeData: true,
      pubsubTopic: WAKU_RAILGUN_PUB_SUB_TOPIC,
      contentTopics: [topic],
      paginationForward: true,
    };

    const lastMessage = lastMessageByTopic.get(topic);
    if (lastMessage) {
      // Resume from where we left off.
      options.paginationCursor = node.store.createCursor(lastMessage);
    } else {
      // First call — use the look-back window.
      const startTime = new Date(Date.now() - HISTORICAL_LOOK_BACK_MS);
      const endTime = new Date();
      options.timeStart = startTime;
      options.timeEnd = endTime;
    }

    let latestDecodedMessage: IDecodedMessage | undefined;

    const generator = node.store.queryGenerator([decoder], options);
    for await (const pagePromises of generator) {
      for (const messagePromise of pagePromises) {
        if (messagePromise == null) continue;
        const decoded = await messagePromise;
        if (decoded == null) continue;

        latestDecodedMessage = decoded;

        messages.push({
          payload: Array.from(decoded.payload),
          contentTopic: decoded.contentTopic,
          timestamp: decoded.timestamp
            ? decoded.timestamp.getTime()
            : undefined,
        });
      }
    }

    // Update cursor for the next call.
    if (latestDecodedMessage) {
      lastMessageByTopic.set(topic, latestDecodedMessage);
    }

    return messages;
  };

  return new JsBroadcasterManagerClass(
    chain_id,
    subscribeFn,
    sendFn,
    retrieveHistoricalFn
  );
}