import * as protobuf from 'protobufjs';
import * as path from 'path';

// shape of a decoded cotmessage wrapper
export interface CotMessagePayload {
  messageType: number;
  otRoundInit?: { roundIndex: number; pointA: Uint8Array };
  otRoundResponse?: { roundIndex: number; pointB: Uint8Array };
  otEncryptedMsgs?: { roundIndex: number; e0: Uint8Array; e1: Uint8Array };
  shareResult?: { share: Uint8Array };
  error?: { description: string };
}

// msg type enum vals that match proto schema
export const MessageType = {
  UNKNOWN: 0,
  OT_ROUND_INIT: 1,
  OT_ROUND_RESPONSE: 2,
  OT_ENCRYPTED_MSGS: 3,
  SHARE_RESULT: 4,
  ERROR: 5,
} as const;

export class ProtoUtils {
  private static root: protobuf.Root;
  private static cotMessageType: protobuf.Type;

  // load .proto file. call once before encode/decode.
  static async load(protoPath?: string): Promise<void> {
    const resolvedPath =
      protoPath || path.resolve(__dirname, '..', '..', 'proto', 'cot.proto');
    ProtoUtils.root = await protobuf.load(resolvedPath);
    ProtoUtils.cotMessageType = ProtoUtils.root.lookupType('cot.CotMessage');
  }

  // drop a cotmessage and get raw protobuf bytes
  static encode(payload: CotMessagePayload): Buffer {
    const errMsg = ProtoUtils.cotMessageType.verify(payload);
    if (errMsg) {
      throw new Error(`Proto verification failed: ${errMsg}`);
    }
    const message = ProtoUtils.cotMessageType.create(payload);
    const buffer = ProtoUtils.cotMessageType.encode(message).finish();
    return Buffer.from(buffer);
  }

  // decode raw protobuf bytes into a cotmessage.
  static decode(data: Buffer): CotMessagePayload {
    const message = ProtoUtils.cotMessageType.decode(data);
    return ProtoUtils.cotMessageType.toObject(message, {
      bytes: Buffer,
      defaults: true,
    }) as unknown as CotMessagePayload;
  }

  // encode cotmessage - 4-byte big-endian prefix for tcp so it works.
  static encodeFramed(payload: CotMessagePayload): Buffer {
    const encoded = ProtoUtils.encode(payload);
    const framed = Buffer.alloc(4 + encoded.length);
    framed.writeUInt32BE(encoded.length, 0);
    encoded.copy(framed, 4);
    return framed;
  }
}
