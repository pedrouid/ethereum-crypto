import {
  sign,
  encrypt,
  decrypt,
  keccak256,
  serialize,
  deserialize,
  hexToBuffer,
  bufferToHex,
  utf8ToBuffer,
  bufferToUtf8,
  concatBuffers,
  addHexPrefix,
  recover,
  isHexString,
  arrayToBuffer,
} from 'eccrypto-js';

export * from 'eccrypto-js';

export interface EthSignature {
  r: string;
  s: string;
  v: string;
}

export const ETH_SIGN_PREFIX = '\x19Ethereum Signed Message:\n';

export function anyToBuffer(
  input: any[] | Buffer | string | Uint8Array
): Buffer {
  return typeof input === 'string'
    ? isHexString(input)
      ? hexToBuffer(input)
      : utf8ToBuffer(input)
    : Buffer.isBuffer(input)
    ? input
    : arrayToBuffer(new Uint8Array(input));
}

export function ensureBuffer(value: Buffer | string): Buffer {
  return Buffer.isBuffer(value) ? value : utf8ToBuffer(value);
}

export function toChecksumAddress(address: string): string {
  const hash = bufferToHex(keccak256(utf8ToBuffer(address)));
  let checksum = '';
  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) > 7) {
      checksum += address[i].toUpperCase();
    } else {
      checksum += address[i];
    }
  }
  return addHexPrefix(checksum);
}

export function getEthereumAddress(publicKey: Buffer | string): string {
  const buf = anyToBuffer(publicKey);
  const hex = addHexPrefix(bufferToHex(buf).slice(2));
  const hash = keccak256(hexToBuffer(hex));
  const address = bufferToHex(hash, true).substring(26);
  return toChecksumAddress(address);
}

export function hashMessage(message: Buffer | string): string {
  const data = ensureBuffer(message);
  const length = anyToBuffer(`${data.length}`);
  const hash = keccak256(
    concatBuffers(anyToBuffer(ETH_SIGN_PREFIX), length, data)
  );
  return bufferToHex(hash, true);
}

export function splitSignature(sig: Buffer): EthSignature {
  return {
    r: sig.slice(0, 32).toString('hex'),
    s: sig.slice(32, 64).toString('hex'),
    v: sig.slice(64, 65).toString('hex'),
  };
}

export function joinSignature(sig: EthSignature): string {
  return bufferToHex(
    concatBuffers(hexToBuffer(sig.r), hexToBuffer(sig.s), hexToBuffer(sig.v)),
    true
  );
}

export async function signDigest(
  privateKey: Buffer | string,
  digest: Buffer | string
): Promise<string> {
  return bufferToHex(
    await sign(anyToBuffer(privateKey), ensureBuffer(digest), true),
    true
  );
}

export async function signMessage(
  privateKey: Buffer | string,
  message: Buffer | string
): Promise<string> {
  const hash = hashMessage(message);
  return signDigest(privateKey, anyToBuffer(hash));
}

export async function recoverPublicKey(
  digest: Buffer | string,
  sig: Buffer | string
): Promise<string> {
  return bufferToHex(
    await recover(anyToBuffer(digest), anyToBuffer(sig)),
    true
  );
}

export async function recoverAddress(
  digest: Buffer | string,
  sig: Buffer | string
): Promise<string> {
  return getEthereumAddress(await recoverPublicKey(digest, sig));
}

export async function verifyMessage(
  message: Buffer | string,
  sig: Buffer | string
): Promise<string> {
  return recoverAddress(hashMessage(message), sig);
}

export async function encryptWithPublicKey(
  publicKey: string,
  message: string
): Promise<string> {
  const encrypted = await encrypt(
    hexToBuffer(publicKey),
    utf8ToBuffer(message)
  );
  return bufferToHex(serialize(encrypted));
}

export async function decryptWithPrivateKey(
  privateKey: string,
  message: string
): Promise<string> {
  const encrypted = deserialize(hexToBuffer(message));
  const decrypted = await decrypt(hexToBuffer(privateKey), encrypted);
  return bufferToUtf8(decrypted);
}
