// import { CF_PATH, recoverAddressWithEthers, signDigestWithEthers } from "@connext/types";
import {
  decryptWithPrivateKey,
  encryptWithPublicKey,
  signEthereumMessage,
  verifyEthereumMessage,
  signDigest,
  recoverAddress,
  keccak256,
  utf8ToBuffer,
  removeHexPrefix,
  bufferToHex,
} from '../src';
import * as EthCrypto from 'eth-crypto';
import * as ethers from 'ethers';

async function recoverAddressWithEthers(digest: string, sig: string) {
  return ethers.utils.recoverAddress(ethers.utils.arrayify(digest), sig);
}

async function signDigestWithEthers(privateKey: string, digest: string) {
  const signingKey = new ethers.utils.SigningKey(privateKey);
  return ethers.utils.joinSignature(
    signingKey.signDigest(ethers.utils.arrayify(digest))
  );
}

const CF_PATH = "m/44'/60'/0'/25446";

const prvKey = ethers.Wallet.createRandom().privateKey;
const pubKey = removeHexPrefix(ethers.utils.computePublicKey(prvKey));

const shortMessage = '123456789012345';
const longMessage = '1234567890123456';

const testMessage = 'test message to sign';
const testMessageArr = ethers.utils.arrayify(Buffer.from(testMessage));
const digest = keccak256(utf8ToBuffer(testMessage));
const digestHex = bufferToHex(digest, true);

// Mnemonic was pulled from the testnet daicard that received a test async transfer
const wallet = ethers.Wallet.fromMnemonic(
  'rely effort talent genuine pumpkin wire caught coil type alien offer obtain',
  `${CF_PATH}/0`
);

const example = {
  address: wallet.address,
  encryptedMessage:
    'b304bbe1bc97a4f1101f3381b93a837f022b6ef864c41e7b8837779b59be67ef355cf2c918961251ec118da2c0abde3b0e803d817b2a3a318f60609023301748350008307ae20ccb1473eac05aced53180511e97cc4cec5809cb4f2ba43517d7951a71bd56b85ac161b8ccdc98dbeabfa99d555216cda31247c21d4a3caa7c46d37fa229f02f15ba254f8d6f5b15ed5310c35dd9ddd54cd23b99a7e332ed501605',
  message: '0xd10d622728d22635333ea792730a0feaede8b61902050a3f8604bb85d7013864',
  prvKey: wallet.privateKey,
  pubKey: removeHexPrefix(ethers.utils.computePublicKey(wallet.privateKey)),
};

describe('crypto', () => {
  it('should decrypt stuff we encrypt', async () => {
    const encrypted = await encryptWithPublicKey(pubKey, shortMessage);
    const decrypted = await decryptWithPrivateKey(prvKey, encrypted);
    expect(shortMessage).toEqual(decrypted);
  });

  it('should decrypt messages longer than 15 chars', async () => {
    const encrypted = await encryptWithPublicKey(pubKey, longMessage);
    const decrypted = await decryptWithPrivateKey(prvKey, encrypted);
    expect(longMessage).toEqual(decrypted);
  });

  it('should encrypt and decrypt with eth-crypto package', async () => {
    const myEncrypted = await encryptWithPublicKey(pubKey, shortMessage);
    const ethEncrypted = EthCrypto.cipher.stringify(
      await EthCrypto.encryptWithPublicKey(pubKey, shortMessage)
    );
    const myDecrypted = await decryptWithPrivateKey(prvKey, ethEncrypted);
    const ethDecrypted = await EthCrypto.decryptWithPrivateKey(
      prvKey,
      EthCrypto.cipher.parse(myEncrypted)
    );
    expect(myDecrypted).toEqual(ethDecrypted);
    expect(myDecrypted).toEqual(shortMessage);
  });

  it('should decrypt messages that were encrypted in a browser', async () => {
    const decrypted = await decryptWithPrivateKey(
      example.prvKey,
      example.encryptedMessage
    );
    expect(decrypted).toEqual(example.message);
  });

  it('should sign Ethereum messages', async () => {
    const sig1 = await wallet.signMessage(testMessageArr);
    const sig2 = await signEthereumMessage(wallet.privateKey, testMessage);
    expect(sig1).toEqual(sig2);
  });

  it('should recover Ethereum messages', async () => {
    const sig = await signEthereumMessage(wallet.privateKey, testMessage);
    const recovered1 = await ethers.utils.verifyMessage(testMessage, sig);
    const recovered2 = await verifyEthereumMessage(testMessage, sig);
    expect(recovered2).toEqual(recovered1);
    expect(recovered2).toEqual(wallet.address);
  });

  it('should sign ECDSA digests', async () => {
    const sig1 = await signDigestWithEthers(wallet.privateKey, digestHex);
    const sig2 = await signDigest(wallet.privateKey, digest);
    expect(sig1).toEqual(sig2);
  });

  it('should recover ECDSA digests', async () => {
    const sig = await signDigest(wallet.privateKey, digest);
    const recovered1 = await recoverAddressWithEthers(digestHex, sig);
    const recovered2 = await recoverAddress(digest, sig);
    expect(recovered2).toEqual(recovered1);
    expect(recovered2).toEqual(wallet.address);
  });
});
