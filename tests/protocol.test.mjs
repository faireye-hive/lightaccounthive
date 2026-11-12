import test from 'node:test';
import assert from 'node:assert/strict';
import { validLiteName, buildRegistration } from '../src/protocol.ts';

test('accepts valid Lite names and rejects invalid Hive grammar', () => {
  for (const name of ['alice', 'brave-otter', 'abc.def', 'hive123']) {
    assert.equal(validLiteName(name), true, name);
  }
  for (const name of ['ab', 'ABC', 'a..bbb', '-abc', 'abc-', 'a.bbbb',
    'bad_name', '0123', 'longlonglonglonglong', 'foo.bar.a', '']) {
    assert.equal(validLiteName(name), false, name);
  }
});

test('registration envelope matches the Syncad L2 test fixture', () => {
  const tx = buildRegistration('brave-otter', 'STMOWNER', 'STMPOSTING', Date.UTC(2026, 10, 12, 15, 0));
  assert.deepEqual(tx, {
    app: 'lite_account',
    version: 1,
    operations: [{
      method: 'register_account',
      args: {
        name: 'brave-otter',
        owner: {
          weight_threshold: 1,
          key_auths: [{ member: { type: 'secp256k1', value: 'STMOWNER' }, weight: 1 }],
          account_auths: []
        },
        posting: {
          weight_threshold: 1,
          key_auths: [{ member: { type: 'secp256k1', value: 'STMPOSTING' }, weight: 1 }],
          account_auths: []
        }
      }
    }],
    expiration: '2026-11-12T15:30:00',
    signatures: []
  });
});

test('registration rejects an invalid name before creating an L2 envelope', () => {
  assert.throws(() => buildRegistration('BadName', 'STMOWNER', 'STMPOSTING'), /Invalid Lite/);
});
