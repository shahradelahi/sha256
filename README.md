# sha256

A lightweight and pure JavaScript library providing utilities for SHA-256 and HMAC-SHA-256 hashing. This library is designed to work seamlessly in any environments, offering efficient and straightforward functions for cryptographic hashing.

## Installation

```bash
npm i @se-oss/sha256
```

## API

```typescript
type BinaryLike = string | Uint8Array | Buffer;

declare function sha256(data: BinaryLike): Uint8Array;
declare function hmacSha256(key: BinaryLike, message: BinaryLike): Uint8Array;
declare function timeSafeCompare(a: string, b: string): boolean;
```

## Examples

```typescript
import { sha256, hmacSha256, timeSafeCompare } from '@se-oss/sha256';

// Hashing a string
const hash = sha256('Hello, world!');
console.log(hash);

// Hashing a Uint8Array
const data = new Uint8Array([1, 2, 3, 4, 5]);
const hash2 = sha256(data);
console.log(hash2);

// HMAC with a string key and message
const key = 'my-secret-key';
const message = 'Hello, HMAC!';
const hmac = hmacSha256(key, message);
console.log(hmac);

// HMAC with a Uint8Array key and message
const keyArray = new Uint8Array([1, 2, 3, 4, 5]);
const hmac2 = hmacSha256(keyArray, 'Hello, HMAC!');
console.log(hmac2);

const result = timeSafeCompare('hello', 'hello');
console.log(result); // true

const result2 = timeSafeCompare('hello', 'world');
console.log(result2); // false
```

## Contributing

Want to contribute? Awesome! To show your support is to star the project, or to raise issues on [GitHub](https://github.com/shahradelahi/sha256).

Thanks again for your support, it is much appreciated! 🙏

## Credits

- [Andrea Griffini](https://github.com/6502)

## License

[MIT](/LICENSE) © [Shahrad Elahi](https://github.com/shahradelahi)
