import { EthereumWallet, verifyEthereumMessage, recoverAddress } from '../src';
import * as eccryptoJS from 'eccrypto-js';
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

function getPublicKeyWithEthers(privateKey: string) {
  return eccryptoJS.removeHexPrefix(ethers.utils.computePublicKey(privateKey));
}

const dynamicWallet = ethers.Wallet.createRandom();
const fixedWallet = ethers.Wallet.fromMnemonic(
  'rely effort talent genuine pumpkin wire caught coil type alien offer obtain'
);

const shortMessage = '123456789012345';
const longMessage = '1234567890123456';

const testMessage = 'test message to sign';
const testMessageArr = ethers.utils.arrayify(Buffer.from(testMessage));
const digest = eccryptoJS.keccak256(eccryptoJS.utf8ToBuffer(testMessage));
const digestHex = eccryptoJS.bufferToHex(digest, true);

const walletA = {
  ethers: dynamicWallet,
  address: dynamicWallet.address,
  privateKey: dynamicWallet.privateKey,
  publicKey: getPublicKeyWithEthers(dynamicWallet.privateKey),
};

const walletB = {
  ethers: fixedWallet,
  address: fixedWallet.address,
  privateKey: fixedWallet.privateKey,
  publicKey: getPublicKeyWithEthers(fixedWallet.privateKey),
};

const example = {
  encrypted:
    '65247a9a55669176b0b361549cfb1b440264ab22099029b3ee619840c38f4818f0b6a476de1c20af531fb8f80636ee96ea64dbf0a8ad7884d3d9fe1b4cc8242dcebeb9941c6b054d3b7dbc5748d552e23ddde2756cfcac38597ceef7e15fe539e58a96374aa3dec7ec4e44b3aba5353d8650c42a85b8906af3eae53de735f8377d474ee1443bfd81661ce97669320de4e36812d209a1c54788790588398136c617',
  message: '0xd10d622728d22635333ea792730a0feaede8b61902050a3f8604bb85d7013864',
};

describe('ethereum-crypto', () => {
  it('should decrypt stuff we encrypt', async () => {
    const wallet = new EthereumWallet(walletA.privateKey);
    const encrypted = await wallet.encrypt(shortMessage, walletA.publicKey);
    const decrypted = await wallet.decrypt(encrypted);
    expect(shortMessage).toEqual(decrypted);
  });

  it('should decrypt messages longer than 15 chars', async () => {
    const wallet = new EthereumWallet(walletA.privateKey);
    const encrypted = await wallet.encrypt(longMessage, walletA.publicKey);
    const decrypted = await wallet.decrypt(encrypted);
    expect(longMessage).toEqual(decrypted);
  });

  it('should encrypt and decrypt with eth-crypto package', async () => {
    const wallet = new EthereumWallet(walletA.privateKey);
    const myEncrypted = await wallet.encrypt(shortMessage, walletA.publicKey);
    const ethEncrypted = EthCrypto.cipher.stringify(
      await EthCrypto.encryptWithPublicKey(walletA.publicKey, shortMessage)
    );
    const myDecrypted = await wallet.decrypt(ethEncrypted);
    const ethDecrypted = await EthCrypto.decryptWithPrivateKey(
      walletA.privateKey,
      EthCrypto.cipher.parse(myEncrypted)
    );
    expect(myDecrypted).toEqual(ethDecrypted);
    expect(myDecrypted).toEqual(shortMessage);
  });

  it('should decrypt messages that were encrypted in a browser', async () => {
    const wallet = new EthereumWallet(walletB.privateKey);
    const decrypted = await wallet.decrypt(example.encrypted);
    expect(decrypted).toEqual(example.message);
  });

  it('should sign Ethereum messages', async () => {
    const wallet = new EthereumWallet(walletB.privateKey);
    const sig1 = await walletB.ethers.signMessage(testMessageArr);
    const sig2 = await wallet.signMessage(testMessage);
    expect(sig1).toEqual(sig2);
  });

  it('should recover Ethereum messages', async () => {
    const wallet = new EthereumWallet(walletB.privateKey);
    const sig = await wallet.signMessage(testMessage);
    const recovered1 = await ethers.utils.verifyMessage(testMessage, sig);
    const recovered2 = await verifyEthereumMessage(testMessage, sig);
    expect(recovered2).toEqual(recovered1);
    expect(recovered2).toEqual(walletB.address);
  });

  it('should sign ECDSA digests', async () => {
    const wallet = new EthereumWallet(walletB.privateKey);
    const sig1 = await signDigestWithEthers(walletB.privateKey, digestHex);
    const sig2 = await wallet.signDigest(digestHex);
    expect(sig1).toEqual(sig2);
  });

  it('should recover ECDSA digests', async () => {
    const wallet = new EthereumWallet(walletB.privateKey);
    const sig = await wallet.signDigest(digestHex);
    const recovered1 = await recoverAddressWithEthers(digestHex, sig);
    const recovered2 = await recoverAddress(digest, sig);
    expect(recovered2).toEqual(recovered1);
    expect(recovered2).toEqual(walletB.address);
  });
});
