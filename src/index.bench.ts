import { createHash } from 'node:crypto';
import { sha256 as sha256Native } from './node';
import { bench, describe } from 'vitest';

import { sha256 } from '.';

describe('SHA256 Benchmarks', () => {
  const sample = 'This is a sample data!';

  bench('@se-oss/sha256', () => {
    sha256(sample);
  });

  bench('@se-oss/sha256 (native)', () => {
    sha256Native(sample);
  });

  bench('node:crypto', () => {
    createHash('sha256').update(sample).digest();
  });
});
