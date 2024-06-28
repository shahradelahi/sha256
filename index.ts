type BinaryLike = string | Uint8Array | Buffer;

/**
 * Class representing a SHA-256 hash helper.
 * This class provides methods to hash data using the SHA-256 algorithm.
 */
class Helper {
  #h0 = 0x6a09e667;
  #h1 = 0xbb67ae85;
  #h2 = 0x3c6ef372;
  #h3 = 0xa54ff53a;
  #h4 = 0x510e527f;
  #h5 = 0x9b05688c;
  #h6 = 0x1f83d9ab;
  #h7 = 0x5be0cd19;
  #tsz = 0;
  #bp = 0;
  #k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  #rrot = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  #w = new Uint32Array(64);
  #buf = new Uint8Array(64);

  #process(): void {
    for (let j = 0, r = 0; j < 16; j++, r += 4) {
      this.#w[j] =
        (this.#buf[r] << 24) |
        (this.#buf[r + 1] << 16) |
        (this.#buf[r + 2] << 8) |
        this.#buf[r + 3];
    }
    for (let j = 16; j < 64; j++) {
      const s0 =
        this.#rrot(this.#w[j - 15], 7) ^ this.#rrot(this.#w[j - 15], 18) ^ (this.#w[j - 15] >>> 3);
      const s1 =
        this.#rrot(this.#w[j - 2], 17) ^ this.#rrot(this.#w[j - 2], 19) ^ (this.#w[j - 2] >>> 10);
      this.#w[j] = (this.#w[j - 16] + s0 + this.#w[j - 7] + s1) | 0;
    }
    let a = this.#h0,
      b = this.#h1,
      c = this.#h2,
      d = this.#h3,
      e = this.#h4,
      f = this.#h5,
      g = this.#h6,
      h = this.#h7;
    for (let j = 0; j < 64; j++) {
      const S1 = this.#rrot(e, 6) ^ this.#rrot(e, 11) ^ this.#rrot(e, 25),
        ch = (e & f) ^ (~e & g),
        t1 = (h + S1 + ch + this.#k[j] + this.#w[j]) | 0,
        S0 = this.#rrot(a, 2) ^ this.#rrot(a, 13) ^ this.#rrot(a, 22),
        maj = (a & b) ^ (a & c) ^ (b & c),
        t2 = (S0 + maj) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    this.#h0 = (this.#h0 + a) | 0;
    this.#h1 = (this.#h1 + b) | 0;
    this.#h2 = (this.#h2 + c) | 0;
    this.#h3 = (this.#h3 + d) | 0;
    this.#h4 = (this.#h4 + e) | 0;
    this.#h5 = (this.#h5 + f) | 0;
    this.#h6 = (this.#h6 + g) | 0;
    this.#h7 = (this.#h7 + h) | 0;
    this.#bp = 0;
  }

  /**
   * Creates a Helper instance.
   * @param {BinaryLike} [key] - If provided, it's added to the hash.
   */
  static from(key: BinaryLike): Helper {
    const h = new Helper();
    h.add(key);
    return h;
  }

  /**
   * Adds data to the hash.
   *
   * @param {BinaryLike} data - The data to add to the hash.
   */
  add(data: BinaryLike): void {
    if (typeof data === 'string') {
      data =
        typeof TextEncoder === 'undefined' ? Buffer.from(data) : new TextEncoder().encode(data);
    }
    for (let i = 0; i < data.length; i++) {
      this.#buf[this.#bp++] = data[i];
      if (this.#bp === 64) this.#process();
    }
    this.#tsz += data.length;
  }

  /**
   * Computes and returns the hash digest as a Uint8Array.
   *
   * @returns {Uint8Array} The hash digest.
   */
  digest(): Uint8Array {
    this.#buf[this.#bp++] = 0x80;
    if (this.#bp == 64) this.#process();
    if (this.#bp + 8 > 64) {
      while (this.#bp < 64) this.#buf[this.#bp++] = 0x00;
      this.#process();
    }
    while (this.#bp < 58) this.#buf[this.#bp++] = 0x00;
    // Max number of bytes is 35,184,372,088,831
    const L = this.#tsz * 8;
    this.#buf[this.#bp++] = (L / 1099511627776) & 255;
    this.#buf[this.#bp++] = (L / 4294967296) & 255;
    this.#buf[this.#bp++] = L >>> 24;
    this.#buf[this.#bp++] = (L >>> 16) & 255;
    this.#buf[this.#bp++] = (L >>> 8) & 255;
    this.#buf[this.#bp++] = L & 255;
    this.#process();
    const reply = new Uint8Array(32);
    reply[0] = this.#h0 >>> 24;
    reply[1] = (this.#h0 >>> 16) & 255;
    reply[2] = (this.#h0 >>> 8) & 255;
    reply[3] = this.#h0 & 255;
    reply[4] = this.#h1 >>> 24;
    reply[5] = (this.#h1 >>> 16) & 255;
    reply[6] = (this.#h1 >>> 8) & 255;
    reply[7] = this.#h1 & 255;
    reply[8] = this.#h2 >>> 24;
    reply[9] = (this.#h2 >>> 16) & 255;
    reply[10] = (this.#h2 >>> 8) & 255;
    reply[11] = this.#h2 & 255;
    reply[12] = this.#h3 >>> 24;
    reply[13] = (this.#h3 >>> 16) & 255;
    reply[14] = (this.#h3 >>> 8) & 255;
    reply[15] = this.#h3 & 255;
    reply[16] = this.#h4 >>> 24;
    reply[17] = (this.#h4 >>> 16) & 255;
    reply[18] = (this.#h4 >>> 8) & 255;
    reply[19] = this.#h4 & 255;
    reply[20] = this.#h5 >>> 24;
    reply[21] = (this.#h5 >>> 16) & 255;
    reply[22] = (this.#h5 >>> 8) & 255;
    reply[23] = this.#h5 & 255;
    reply[24] = this.#h6 >>> 24;
    reply[25] = (this.#h6 >>> 16) & 255;
    reply[26] = (this.#h6 >>> 8) & 255;
    reply[27] = this.#h6 & 255;
    reply[28] = this.#h7 >>> 24;
    reply[29] = (this.#h7 >>> 16) & 255;
    reply[30] = (this.#h7 >>> 8) & 255;
    reply[31] = this.#h7 & 255;
    return reply;
  }
}

/**
 * Computes the SHA-256 hash of the given data.
 *
 * @param {BinaryLike} data - The data to hash.
 * @returns {Uint8Array} The SHA-256 hash of the data.
 *
 * @example
 * // Hashing a string
 * const hash = sha256('Hello, world!');
 * console.log(hash);
 *
 * // Hashing a Uint8Array
 * const data = new Uint8Array([1, 2, 3, 4, 5]);
 * const hash2 = sha256(data);
 * console.log(hash2);
 */
export function sha256(data: BinaryLike): Uint8Array {
  return Helper.from(data).digest();
}

/**
 * Computes the HMAC-SHA-256 of a message with a given key.
 *
 * @param {BinaryLike} key - The key for the HMAC.
 * @param {string} message - The message to hash.
 * @returns {Uint8Array} The HMAC-SHA-256 of the message.
 *
 * @example
 * // HMAC with a string key and message
 * const key = 'my-secret-key';
 * const message = 'Hello, HMAC!';
 * const hmac = hmacSha256(key, message);
 * console.log(hmac);
 *
 * // HMAC with a Uint8Array key and message
 * const keyArray = new Uint8Array([1, 2, 3, 4, 5]);
 * const hmac2 = hmacSha256(keyArray, 'Hello, HMAC!');
 * console.log(hmac2);
 */
export function hmacSha256(key: BinaryLike, message: BinaryLike): Uint8Array {
  let k =
    typeof key === 'string'
      ? typeof TextEncoder === 'undefined'
        ? Buffer.from(key)
        : new TextEncoder().encode(key)
      : key;

  if (key.length > 64) k = Helper.from(k).digest();
  const inner = new Uint8Array(64).fill(0x36);
  const outer = new Uint8Array(64).fill(0x5c);
  for (let i = 0; i < k.length; i++) {
    inner[i] ^= k[i];
    outer[i] ^= k[i];
  }
  const p1 = new Helper(),
    p2 = new Helper();
  p1.add(inner);
  p1.add(message);
  p2.add(outer);
  p2.add(p1.digest());
  return p2.digest();
}

/**
 * Compares two buffers
 *
 * @param {Uint8Array} a - The first buffer to compare.
 * @param {Uint8Array} b - The second buffer to compare.
 * @returns {boolean} True if the buffers are equal, false otherwise.
 *
 * @private
 */
function bufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }

  return true;
}

/**
 * Compares two strings for equality in a timing-safe manner.
 *
 * @param {string} a - The first string to compare.
 * @param {string} b - The second string to compare.
 * @returns {boolean} True if the strings are equal, false otherwise.
 *
 * @example
 * const result = timeSafeCompare('hello', 'hello');
 * console.log(result); // true
 *
 * const result2 = timeSafeCompare('hello', 'world');
 * console.log(result2); // false
 */
export function timeSafeCompare(a: string, b: string): boolean {
  const key = Math.random().toString(16).slice(2);

  const ah = hmacSha256(key, a);
  const bh = hmacSha256(key, b);

  return bufferEqual(ah, bh) && a === b;
}
