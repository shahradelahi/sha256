import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { sha256 } from '.';

const sample = 'This is a sample data!';

describe('SHA-256', () => {
  it('should match node:crypto hash', () => {
    const hash = Buffer.from(sha256(sample)).toString('hex');
    const nodeHash = createHash('sha256').update(sample).digest('hex');
    expect(hash).toBe(nodeHash);
  });
});
