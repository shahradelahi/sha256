import { createHash } from 'node:crypto';
import { bench, describe } from 'vitest';

import { sha256 } from '.';

describe('SHA256 Benchmarks', () => {
  const sample = 'This is a sample data!';

  bench('@se-oss/sha256', () => {
    sha256(sample);
  });

  bench('node:crypto', () => {
    createHash('sha256').update(sample).digest('hex');
  });
});
