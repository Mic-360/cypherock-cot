import * as crypto from 'crypto';

// secp256k1 curve consts got it from stack overflow

/** field prime p */
const CURVE_P = BigInt(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
);

/** curve order n */
const CURVE_N = BigInt(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
);

/** gen pt g x-coord */
const G_X = BigInt(
  '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
);

/** gen pt g y-coord */
const G_Y = BigInt(
  '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
);

/** secp256k1 b = 7 */
const CURVE_B = 7n;

/** pt at infinity */
interface ECPoint {
  x: bigint;
  y: bigint;
}

const POINT_AT_INFINITY: ECPoint | null = null;

// modular math helpers

/** (x mod m), strictly non-negative */
function modP(x: bigint): bigint {
  return ((x % CURVE_P) + CURVE_P) % CURVE_P;
}

function modN(x: bigint): bigint {
  return ((x % CURVE_N) + CURVE_N) % CURVE_N;
}

/** mod pow: base^exp mod m */
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % m;
    }
    exp >>= 1n;
    base = (base * base) % m;
  }
  return result;
}

/** mod inverse via fermat's lil theorem */
function modInverse(a: bigint, m: bigint): bigint {
  return modPow(((a % m) + m) % m, m - 2n, m);
}

// bigint ↔ buffer conversion

/** cast bigint to 32-byte big-endian buffer */
function bigintToBuffer32(n: bigint): Buffer {
  const hex = n.toString(16).padStart(64, '0');
  return Buffer.from(hex, 'hex');
}

/** buffer to bigint */
function bufferToBigint(buf: Buffer): bigint {
  return BigInt('0x' + buf.toString('hex'));
}

// ec pt ops

/** inflate 33-byte compressed pt to affine (x, y) */
function decompressPoint(compressed: Buffer): ECPoint {
  if (compressed.length !== 33) {
    throw new Error(`Invalid compressed point length: ${compressed.length}`);
  }
  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error(`Invalid point prefix: 0x${prefix.toString(16)}`);
  }
  const x = bufferToBigint(compressed.subarray(1, 33));

  // y² = x³ + 7 (mod p)
  const ySquared = modP(modP(x * x % CURVE_P * x) + CURVE_B);

  // Square root: y = ySqrd^((p + 1) / 4) mod p  (works because p = 3 mod 4)
  let y = modPow(ySquared, (CURVE_P + 1n) / 4n, CURVE_P);

  // guess y parity using prefix byte
  const isOdd = (y & 1n) === 1n;
  const wantOdd = prefix === 0x03;
  if (isOdd !== wantOdd) {
    y = modP(-y);
  }

  return { x, y };
}

/** squash affine pt down to 33 bytes */
function compressPoint(point: ECPoint): Buffer {
  const prefix = (point.y & 1n) === 1n ? 0x03 : 0x02;
  const buf = Buffer.alloc(33);
  buf[0] = prefix;
  const xBuf = bigintToBuffer32(point.x);
  xBuf.copy(buf, 1);
  return buf;
}

/** ec pt double on secp256k1: 2p */
function ecDouble(p: ECPoint | null): ECPoint | null {
  if (p === null) return null;
  if (p.y === 0n) return null;

  const num = modP(3n * p.x % CURVE_P * p.x);
  const den = modInverse(modP(2n * p.y), CURVE_P);
  const lam = modP(num * den);

  const xr = modP(lam * lam % CURVE_P - 2n * p.x);
  const yr = modP(lam * modP(p.x - xr) % CURVE_P - p.y);

  return { x: xr, y: yr };
}

/** ec pt add on secp256k1: p + q */
function ecAdd(p: ECPoint | null, q: ECPoint | null): ECPoint | null {
  if (p === null) return q;
  if (q === null) return p;
  if (p.x === q.x) {
    if (p.y === q.y) return ecDouble(p);
    return null; // p + (-p) = O
  }

  const num = modP(q.y - p.y);
  const den = modInverse(modP(q.x - p.x), CURVE_P);
  const lam = modP(num * den);

  const xr = modP(lam * lam % CURVE_P - p.x - q.x);
  const yr = modP(lam * modP(p.x - xr) % CURVE_P - p.y);

  return { x: xr, y: yr };
}

/** ec scalar mult: k * p via double-n-add */
function ecScalarMul(k: bigint, p: ECPoint | null): ECPoint | null {
  if (p === null || k === 0n) return null;

  k = ((k % CURVE_N) + CURVE_N) % CURVE_N;
  let result: ECPoint | null = null;
  let addend: ECPoint | null = p;

  while (k > 0n) {
    if (k & 1n) {
      result = ecAdd(result, addend);
    }
    addend = ecDouble(addend);
    k >>= 1n;
  }
  return result;
}

// the genratr point 

const G: ECPoint = { x: G_X, y: G_Y };

// pub cryptoutils cls

export class CryptoUtils {
  static generateScalar(): Buffer {
    while (true) {
      const buf = crypto.randomBytes(32);
      const val = bufferToBigint(buf);
      if (val >= 1n && val < CURVE_N) {
        return buf;
      }
    }
  }

  /**
   * scalar x pt g > 33-byte compressed pt.
   * uses node crypto ecdh for perf.
   */
  static scalarBaseMultiply(scalar: Buffer): Buffer {
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(scalar);
    return Buffer.from(ecdh.getPublicKey(null, 'compressed'));
  }

  /**
   * scalar x random ec pt > 33-byte compressed.
   * forced to math it w/ bigint double-n-add bc node crypto is lacking.
   */
  static scalarPointMultiply(scalar: Buffer, point: Buffer): Buffer {
    const k = bufferToBigint(scalar);
    const p = decompressPoint(point);
    const result = ecScalarMul(k, p);
    if (result === null) {
      throw new Error('Scalar multiplication resulted in point at infinity');
    }
    return compressPoint(result);
  }

  static pointAdd(a: Buffer, b: Buffer): Buffer {
    const pa = decompressPoint(a);
    const pb = decompressPoint(b);
    const result = ecAdd(pa, pb);
    if (result === null) {
      throw new Error('Point addition resulted in point at infinity');
    }
    return compressPoint(result);
  }

  static pointSubtract(a: Buffer, b: Buffer): Buffer {
    const pa = decompressPoint(a);
    const pb = decompressPoint(b);
    const negB: ECPoint = { x: pb.x, y: modP(-pb.y) };
    const result = ecAdd(pa, negB);
    if (result === null) {
      throw new Error('Point subtraction resulted in point at infinity');
    }
    return compressPoint(result);
  }

  static getXCoordinate(point: Buffer): Buffer {
    if (point.length !== 33) {
      throw new Error(`Invalid compressed point length: ${point.length}`);
    }
    return Buffer.from(point.subarray(1, 33));
  }

  static aesEncrypt(key: Buffer, plaintext: Buffer): Buffer {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(true);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
  }

  static aesDecrypt(key: Buffer, data: Buffer): Buffer {
    const iv = data.subarray(0, 16);
    const ciphertext = data.subarray(16);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    decipher.setAutoPadding(true);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  static deriveAesKey(xCoordinate: Buffer): Buffer {
    return crypto.createHash('sha256').update(xCoordinate).digest();
  }

  /**
   * (a + b) mod n
   */
  static scalarAdd(a: Buffer, b: Buffer): Buffer {
    const result = modN(bufferToBigint(a) + bufferToBigint(b));
    return bigintToBuffer32(result);
  }

  static scalarNegate(a: Buffer): Buffer {
    const result = modN(-bufferToBigint(a));
    return bigintToBuffer32(result);
  }

  static scalarMul(a: Buffer, b: Buffer): Buffer {
    const result = modN(bufferToBigint(a) * bufferToBigint(b));
    return bigintToBuffer32(result);
  }

  static getBit(scalar: Buffer, i: number): number {
    if (i < 1 || i > 256) {
      throw new Error(`Bit index out of range: ${i}`);
    }
    const byteIndex = 31 - Math.floor((i - 1) / 8);
    const bitIndex = (i - 1) % 8;
    return (scalar[byteIndex] >> bitIndex) & 1;
  }

  static scalarShiftLeft(scalar: Buffer, bits: number): Buffer {
    const s = bufferToBigint(scalar);
    const pow2 = modN(1n << BigInt(bits));
    const result = modN(s * pow2);
    return bigintToBuffer32(result);
  }
}
