import { CryptoUtils } from './crypto_utils';

// state per round bc we need to track this mess
enum OTState {
  WAITING_FOR_A = 'WAITING_FOR_A',
  SENT_B = 'SENT_B',
  RECEIVED_ENCRYPTED = 'RECEIVED_ENCRYPTED',
  COMPLETE = 'COMPLETE',
}

// simple types for now will fix it in future for more perfect types
interface OTRoundState {
  readonly index: number;
  b: Buffer;             
  B: Buffer;             
  ci: number;            
  A: Buffer;             
  mc: Buffer | null;     
  state: OTState;
}

export class OTSession {
  private readonly y: Buffer;
  private readonly rounds: Map<number, OTRoundState> = new Map();

  constructor(y: Buffer) {
    this.y = y;
  }

  prepareResponse(i: number, A: Buffer): Buffer {
    const ci = CryptoUtils.getBit(this.y, i);
    const b = CryptoUtils.generateScalar();
    const bG = CryptoUtils.scalarBaseMultiply(b);

    let B: Buffer;
    if (ci === 0) {
      B = bG;
    } else {
      B = CryptoUtils.pointAdd(bG, A);
    }

    this.rounds.set(i, {
      index: i,
      b,
      B,
      ci,
      A,
      mc: null,
      state: OTState.SENT_B,
    });

    return B;
  }

  processEncryptedMessages(i: number, e0: Buffer, e1: Buffer): void {
    const round = this.rounds.get(i);
    if (!round) {
      throw new Error(`No state for round ${i}`);
    }
    if (round.state !== OTState.SENT_B) {
      throw new Error(`Invalid state for round ${i}: ${round.state}`);
    }

    const sharedPoint = CryptoUtils.scalarPointMultiply(round.b, round.A);
    const xCoord = CryptoUtils.getXCoordinate(sharedPoint);
    const kc = CryptoUtils.deriveAesKey(xCoord);

    const ec = round.ci === 0 ? e0 : e1;
    round.mc = CryptoUtils.aesDecrypt(kc, ec);
    round.state = OTState.COMPLETE;

    round.b.fill(0);
  }

  computeAdditiveShare(): Buffer {
    let V: Buffer = Buffer.alloc(32, 0) as Buffer;

    for (let i = 1; i <= 256; i++) {
      const round = this.rounds.get(i);
      if (!round || !round.mc) {
        throw new Error(`Round ${i} not complete`);
      }

      const term = CryptoUtils.scalarShiftLeft(round.mc, i - 1);
      V = CryptoUtils.scalarAdd(V, term);
    }

    return V;
  }
}
