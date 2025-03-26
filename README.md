# @se-oss/sha256

[![CI](https://github.com/shahradelahi/sha256/actions/workflows/ci.yml/badge.svg)](https://github.com/shahradelahi/sha256/actions/workflows/ci.yml)
[![NPM Version](https://img.shields.io/npm/v/@se-oss/sha256.svg)](https://www.npmjs.com/package/@se-oss/sha256)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)](/LICENSE)
[![Install Size](https://packagephobia.com/badge?p=@se-oss/sha256)](https://packagephobia.com/result?p=@se-oss/sha256)
![Edge Runtime Compatible](https://img.shields.io/badge/edge--runtime-%E2%9C%94%20compatible-black)

A lightweight JavaScript library that provides utilities for `SHA-256` and `HMAC-SHA-256` hashing. This library is designed to work seamlessly in any JavaScript runtime, offering efficient and straightforward functions for cryptographic hashing.

> [!WARNING]
>
> This library is noticeably slower than native modules such as [`node:crypto`](https://nodejs.org/api/crypto.html) and [WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Use this library only when you cannot use WebCrypto because its operations are asynchronous and `node:crypto` is not available.

---

- [Installation](#-installation)
- [Usage](#-usage)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [Credits](#-credits)
- [License](#license)

## 📦 Installation

```bash
npm i @se-oss/sha256
```

## 📖 Usage

```typescript
import { hmacSha256, sha256, timeSafeCompare } from '@se-oss/sha256';

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

## 📚 Documentation

For all configuration options, please see [the API docs](https://www.jsdocs.io/package/@se-oss/sha256).

##### API

<!-- prettier-ignore -->
```typescript
type BinaryLike = string | Uint8Array | Buffer;

function sha256(data: BinaryLike): Uint8Array;
function hmacSha256(key: BinaryLike, message: BinaryLike): Uint8Array;
function timeSafeCompare(a: string, b: string): boolean;
```

## 🤝 Contributing

Want to contribute? Awesome! To show your support is to star the project, or to raise issues on [GitHub](https://github.com/shahradelahi/sha256).

Thanks again for your support, it is much appreciated! 🙏

## 🙌 Credits

- [Andrea Griffini](https://github.com/6502)

## License

[MIT](/LICENSE) © [Shahrad Elahi](https://github.com/shahradelahi) and [contributors](https://github.com/shahradelahi/sha256/graphs/contributors).
