'use strict'

const crypto = require('node:crypto')
const { subtle } = require('node:crypto').webcrypto

const govEncryptionDataStr = 'AES-GENERATION'

const decoder = new TextDecoder()

function byteArrayToString(arr) {
  // Converts from ArrayBuffer to string
  // Used to go from output of decryptWithGCM to string
  return decoder.decode(arr)
}

function genRandomSalt(len = 16) {
  // Used to generate IVs for AES encryption
  // Used in combination with encryptWithGCM and decryptWithGCM
  return byteArrayToString(crypto.getRandomValues(new Uint8Array(len)))
}

async function cryptoKeyToJSON(cryptoKey) {
  // Used to and return CryptoKey in JSON format
  const key = await subtle.exportKey('jwk', cryptoKey)
  return key
}

async function generateEG() {
  // returns a pair of ElGamal keys as an object
  // private key is keypairObject.sec
  // public key is keypairObject.pub
  const keypair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey'])
  const keypairObject = { pub: keypair.publicKey, sec: keypair.privateKey }
  return keypairObject
}

async function computeDH(myPrivateKey, theirPublicKey) {
  return await subtle.deriveKey({ name: 'ECDH', public: theirPublicKey }, myPrivateKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign', 'verify'])
}

async function verifyWithECDSA(publicKey, message, signature) {
  // returns true if signature is correct for message and publicKey
  return await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' } }, publicKey, signature, message)
}

async function HMACtoAESKey(key, data, exportToArrayBuffer = false) {
  // Performs HMAC to derive a new key with derivedKeyAlgorithm AES
  // if exportToArrayBuffer is true, return key as ArrayBuffer. Otherwise, output CryptoKey
  // key is a CryptoKey
  // data is a string

  // first compute HMAC output
  const hmacBuf = await subtle.sign({ name: 'HMAC' }, key, data)

  // Then, re-import with derivedKeyAlgorithm AES-GCM
  const out = await subtle.importKey('raw', hmacBuf, 'AES-GCM', true, ['encrypt', 'decrypt'])

  // If exportToArrayBuffer is true, exportKey as ArrayBuffer
  // (Think: what part of the assignment can this help with?)
  if (exportToArrayBuffer) {
    return await subtle.exportKey('raw', out)
  }

  // otherwise, export as cryptoKey
  return out
}

async function HMACtoHMACKey(key, data) {
  // Performs HMAC to derive a new key with derivedKeyAlgorithm HMAC
  // key is a CryptoKey
  // data is a string

  // first compute HMAC output
  const hmacBuf = await subtle.sign({ name: 'HMAC' }, key, data)
  // Then, re-import with derivedKeyAlgorithm HMAC
  return await subtle.importKey('raw', hmacBuf, { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign'])
}

async function HKDF(inputKey, salt, infoStr) {
  // Calculates HKDF outputs
  // inputKey is a cryptoKey with derivedKeyAlgorithm HMAC
  // salt is a second cryptoKey with derivedKeyAlgorithm HMAC
  // infoStr is a string (can be an arbitrary constant e.g. "ratchet-str")
  // returns an array of two HKDF outputs [hkdfOut1, hkdfOut2]

  // since inputKey's derivedKeyAlgorithm is HMAC, we need to sign an arbitrary constant and
  // then re-import as a a CryptoKey with derivedKeyAlgorithm HKDF
  const inputKeyBuf = await subtle.sign({ name: 'HMAC' }, inputKey, '0')
  const inputKeyHKDF = await subtle.importKey('raw', inputKeyBuf, 'HKDF', false, ['deriveKey'])

  // Generate salts that will be needed for deriveKey calls later on
  const salt1 = await subtle.sign({ name: 'HMAC' }, salt, 'salt1')
  const salt2 = await subtle.sign({ name: 'HMAC' }, salt, 'salt2')

  // calculate first HKDF output (with salt1)
  const hkdfOut1 = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: salt1, info: infoStr },
    inputKeyHKDF, { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign'])

  // calculate second HKDF output (with salt2)
  const hkdfOut2 = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: salt2, info: infoStr },
    inputKeyHKDF, { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign'])

  return [hkdfOut1, hkdfOut2]
}

async function encryptWithGCM(key, plaintext, iv, authenticatedData = '') {
  // Encrypts using the GCM mode.
  return await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: authenticatedData }, key, plaintext)
}

async function decryptWithGCM(key, ciphertext, iv, authenticatedData = '') {
  // Decrypts using the GCM mode.
  return await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: authenticatedData }, key, ciphertext)
}

async function generateECDSA() {
  // returns a pair of Digital Signature Algorithm keys as an object
  // private key is keypairObject.sec
  // public key is keypairObject.pub
  const keypair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'])
  const keypairObject = { pub: keypair.publicKey, sec: keypair.privateKey }
  return keypairObject
}

async function signWithECDSA(privateKey, message) {
  // returns signature of message with privateKey
  // privateKey should be pair.sec from generateECDSA
  // message is a string
  // signature returned as an ArrayBuffer
  return await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' } }, privateKey, message)
}

module.exports = {
  govEncryptionDataStr,
  byteArrayToString,
  genRandomSalt,
  cryptoKeyToJSON,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateECDSA,
  signWithECDSA
}
