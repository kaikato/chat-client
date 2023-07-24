'use strict'

const {
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {

    this.EGKeyPair = await generateEG();
    const certificate = { username: username, pub: this.EGKeyPair.pub };
    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate(certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.
    const certString = JSON.stringify(certificate);
    var verify = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (!verify) {
      throw ("invalid signature on certificate");
    }
    this.certs[certificate.username] = certificate;
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage(name, plaintext) {
    const header = {}
    let ciphertext = ''

    //Check if previously communicated, if not initialize
    if (!this.conns[name]) {
      var SK = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
      var DHs = await generateEG();
      var DH2 = await computeDH(DHs.sec, this.certs[name].pub);
      var KDF = await HKDF(SK, DH2, "ratchet-str");
      const state = { DHs: DHs, DHr: this.certs[name].pub, RK: KDF[0], CKs: KDF[1], CKr: '', Ns: 0, Nr: 0, PN: 0, MKSKIPPED: new Map(), prev: this.certs[name].pub };
      this.conns[name] = state;
    }

    //Symmetric-key ratchet
    var MK = await HMACtoAESKey(this.conns[name].CKs, "AESKeyGen");
    var MK2 = await HMACtoAESKey(this.conns[name].CKs, "AESKeyGen", true);
    var CK = await HMACtoHMACKey(this.conns[name].CKs, "HMACKeyGen");
    this.conns[name].CKs = CK;

    var IV = await genRandomSalt();
    header.receiverIV = IV;

    header.DH = this.conns[name].DHs.pub;
    header.PN = this.conns[name].PN;
    header.Ns = this.conns[name].Ns;
    this.conns[name].Ns += 1;

    //Government keys
    var govKeys = await generateEG();
    header.vGov = govKeys.pub;
    var govDH = await computeDH(govKeys.sec, this.govPublicKey); //might be something missing here
    var govAESKey = await HMACtoAESKey(govDH, govEncryptionDataStr);
    header.ivGov = await genRandomSalt();
    header.cGov = await encryptWithGCM(govAESKey, MK2, header.ivGov);

    ciphertext = await encryptWithGCM(MK, plaintext, IV, JSON.stringify(header));

    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage(name, [header, ciphertext]) {

    if (!this.conns[name]) {
      var SK = await computeDH(this.EGKeyPair.sec, this.certs[name].pub);
      const state = { DHs: this.EGKeyPair, DHr: '', RK: SK, CKs: '', CKr: '', Ns: 0, Nr: 0, PN: 0, MKSKIPPED: new Map() }; //not totally sure what DHs should be here
      this.conns[name] = state;
    }

    // Try skipped messages.
    let t = await cryptoKeyToJSON(header.DH);
    t = JSON.stringify(t) + header.Ns;
    if (this.conns[name].MKSKIPPED.has(t)) {
      let mk = this.conns[name].MKSKIPPED.get(t);
      this.conns[name].MKSKIPPED.delete(t);
      let plaintextt = await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header));
      if (plaintextt) {
        plaintextt = byteArrayToString(plaintextt);
        return plaintextt
      }
    }

    if (header.DH != this.conns[name].DHr) {
      // skip message keys
      if (this.conns[name].CKr) {
        while (this.conns[name].Nr < header.PN) {
          var MKt = await HMACtoAESKey(this.conns[name].CKr, "AESKeyGen");
          var CKt = await HMACtoHMACKey(this.conns[name].CKr, "HMACKeyGen");
          this.conns[name].CKr = CKt;
          let s = await cryptoKeyToJSON(this.conns[name].DHr);
          s = JSON.stringify(s) + this.conns[name].Nr;
          this.conns[name].MKSKIPPED.set(s, MKt);
          this.conns[name].Nr += 1;
        }
      }
      // ratchet
      this.conns[name].prev = this.conns[name].DHr;
      this.conns[name].DHr = header.DH;
      this.conns[name].PN = this.conns[name].Ns;
      this.conns[name].Ns = 0;
      this.conns[name].Nr = 0;

      var DH = await computeDH(this.conns[name].DHs.sec, this.conns[name].DHr);
      var KDF = await HKDF(this.conns[name].RK, DH, "ratchet-str");
      this.conns[name].RK = KDF[0];
      this.conns[name].CKr = KDF[1];
      var EGKeys = await generateEG();
      this.conns[name].DHs = EGKeys;
      var DH = await computeDH(this.conns[name].DHs.sec, this.conns[name].DHr);
      var KDF = await HKDF(this.conns[name].RK, DH, "ratchet-str");
      this.conns[name].RK = KDF[0];
      this.conns[name].CKs = KDF[1];
    }

    // skip message keys
    if (this.conns[name].CKr) {
      while (this.conns[name].Nr < header.Ns) {
        var MKt = await HMACtoAESKey(this.conns[name].CKr, "AESKeyGen");
        var CKt = await HMACtoHMACKey(this.conns[name].CKr, "HMACKeyGen");
        this.conns[name].CKr = CKt;
        let s = await cryptoKeyToJSON(this.conns[name].DHr);
        s = JSON.stringify(s);
        s = s + this.conns[name].Nr;
        this.conns[name].MKSKIPPED.set(s, MKt);
        this.conns[name].Nr += 1;
      }
    }
    //Symmetric-key ratchet
    var MK = await HMACtoAESKey(this.conns[name].CKr, "AESKeyGen");
    var CK = await HMACtoHMACKey(this.conns[name].CKr, "HMACKeyGen");
    this.conns[name].CKr = CK;
    this.conns[name].Nr += 1;

    //Decrypt
    let plaintext = await decryptWithGCM(MK, ciphertext, header.receiverIV, JSON.stringify(header));
    plaintext = byteArrayToString(plaintext);
    return plaintext
  }
};

module.exports = {
  MessengerClient
}
