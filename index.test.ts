import { createHash } from 'node:crypto';
import { expect } from 'chai';

import { sha256 } from './index.js';

describe('SHA-256', () => {
  const data = 'This is a sample data!';

  it('should', () => {
    const hash = Buffer.from(sha256(data)).toString('hex');
    const nodeHash = createHash('sha256').update(data).digest('hex');
    expect(hash).to.equal(nodeHash);
  });
});
