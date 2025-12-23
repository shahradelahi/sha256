import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { createSha256, sha256 } from '.';

const sample = 'This is a sample data!';

describe('SHA-256', () => {
  it('should match node:crypto hash', () => {
    const hash = Buffer.from(sha256(sample)).toString('hex');
    const nodeHash = createHash('sha256').update(sample).digest('hex');
    expect(hash).toBe(nodeHash);
  });

  it('should support hex digest', () => {
    const hash = createSha256().update(sample).digest('hex');
    const nodeHash = createHash('sha256').update(sample).digest('hex');
    expect(hash).toBe(nodeHash);
  });

  it('should support incremental updates', () => {
    const hasher = createSha256();
    hasher.update('part1');
    hasher.update('part2');
    const hash = hasher.digest('hex');

    const nodeHash = createHash('sha256').update('part1').update('part2').digest('hex');
    expect(hash).toBe(nodeHash);
  });
});
