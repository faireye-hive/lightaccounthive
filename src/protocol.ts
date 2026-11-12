/** lite_account L2 envelope, as specified by hive/lite_account integration tests.
 * register_account deliberately has zero L2 signatures: the Hive L1 broadcaster
 * authorizes the initial public authorities using its posting key.
 */
export function validLiteName(name: string): boolean {
  if (name.length < 3 || name.length > 16) return false;
  return name.split('.').every((part) =>
    part.length >= 3 &&
    /^[a-z][a-z0-9-]*[a-z0-9]$/.test(part)
  );
}

export function buildRegistration(
  name: string,
  ownerPublic: string,
  postingPublic: string,
  now = Date.now()
) {
  if (!validLiteName(name)) throw new Error('Invalid Lite account name');
  const authority = (publicKey: string) => ({
    weight_threshold: 1,
    key_auths: [{ member: { type: 'secp256k1', value: publicKey }, weight: 1 }],
    account_auths: []
  });
  return {
    app: 'lite_account',
    version: 1,
    operations: [{
      method: 'register_account',
      args: {
        name,
        owner: authority(ownerPublic),
        posting: authority(postingPublic)
      }
    }],
    expiration: new Date(now + 30 * 60 * 1000).toISOString().slice(0, 19),
    signatures: [] as string[]
  };
}
