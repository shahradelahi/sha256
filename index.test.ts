import { createHash } from 'node:crypto';
import { expect } from 'chai';
import { Bench } from 'tinybench';

import { sha256 } from './index.js';

const sample = 'This is a sample data!';

describe('SHA-256', () => {
  it('should', () => {
    const hash = Buffer.from(sha256(sample)).toString('hex');
    const nodeHash = createHash('sha256').update(sample).digest('hex');
    expect(hash).to.equal(nodeHash);
  });
});

it('Performance', async () => {
  const bench = new Bench({ time: 100 });

  bench
    .add('@se-oss/sha256', () => {
      sha256(sample);
    })
    .add('node:crypto', async () => {
      createHash('sha256').update(sample).digest('hex');
    });

  await bench.warmup();
  await bench.run();

  // eslint-disable-next-line no-console
  console.table(bench.table());
});
