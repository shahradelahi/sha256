# @se-oss/sha256

[![CI](https://github.com/shahradelahi/sha256/actions/workflows/ci.yml/badge.svg)](https://github.com/shahradelahi/sha256/actions/workflows/ci.yml)
[![NPM Version](https://img.shields.io/npm/v/@se-oss/sha256.svg)](https://www.npmjs.com/package/@se-oss/sha256)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)](/LICENSE)
![npm bundle size](https://img.shields.io/bundlephobia/minzip/@se-oss/sha256)
[![Install Size](https://packagephobia.com/badge?p=@se-oss/sha256)](https://packagephobia.com/result?p=@se-oss/sha256)
![Edge Runtime Compatible](https://img.shields.io/badge/edge--runtime-%E2%9C%94%20compatible-black)

_@se-oss/sha256_ is a JavaScript library that provides utilities for `SHA-256` and `HMAC-SHA-256` hashing. This library is designed to work seamlessly in any JavaScript runtime, offering efficient and straightforward functions for cryptographic hashing.

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

<details>
<summary>Install using your favorite package manager</summary>

**pnpm**

```bash
pnpm install @se-oss/sha256
```

**yarn**

```bash
yarn add @se-oss/sha256
```

</details>

## 📖 Usage

### Hashing

```typescript
import { sha256 } from '@se-oss/sha256';

// Hashing a string
const hash = sha256('Hello, world!');

// Hashing a Uint8Array
const data = new Uint8Array([1, 2, 3, 4, 5]);
const hash2 = sha256(data);
```

### HMAC

```typescript
import { hmacSha256 } from '@se-oss/sha256';

const key = 'my-secret-key';
const message = 'Hello, HMAC!';
const hmac = hmacSha256(key, message);
```

### Streaming

```typescript
import { createSha256 } from '@se-oss/sha256';

const hasher = createSha256();
hasher.update('Hello, ');
hasher.update('world!');

const hexHash = hasher.digest('hex');
```

### Timing Safe Comparison

```typescript
import { timeSafeCompare } from '@se-oss/sha256';

const result = timeSafeCompare('hello', 'hello'); // true
```

## 📚 Documentation

For detailed API documentation on all methods, please see [the API docs](https://www.jsdocs.io/package/@se-oss/sha256).

## 🤝 Contributing

Want to contribute? Awesome! To show your support is to star the project, or to raise issues on [GitHub](https://github.com/shahradelahi/sha256).

Thanks again for your support, it is much appreciated! 🙏

## 🙌 Credits

- [Andrea Griffini](https://github.com/6502)

## License

[MIT](/LICENSE) © [Shahrad Elahi](https://github.com/shahradelahi) and [contributors](https://github.com/shahradelahi/sha256/graphs/contributors).
