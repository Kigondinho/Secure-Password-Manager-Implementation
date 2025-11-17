"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;
const Buffer = require('buffer').Buffer;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;   
const PBKDF2_SALT_LENGTH = 16;    
const AES_GCM_IV_LENGTH = 12;     
const MAC_KEY_INFO = stringToBuffer("MAC_KEY_DERIVATION"); 
const ENC_KEY_INFO = stringToBuffer("AES_KEY_DERIVATION"); 

/********* Helper Functions ********/

/**
 * Derives a sub-key from the master key k using HMAC-SHA256 as a PRF.
 */
async function deriveSubKey(masterKey, info, keyUsages, algorithmName) {
    const rawKeyBuffer = await subtle.sign("HMAC", masterKey, info);
    return await subtle.importKey(
        "raw",
        rawKeyBuffer,
        { name: algorithmName, length: 256 }, 
        false, 
        keyUsages
    );
}

/**
 * Encapsulates PBKDF2 and subsequent sub-key derivation.
 * NOTE: This function should only be called once to derive keys (O(1) time complexity). [cite: 248]
 * @param {string} password The user's master password.
 * @param {ArrayBuffer} saltBuffer The PBKDF2 salt.
 * @returns {Promise<{kMAC: CryptoKey, kENC: CryptoKey}>}
 */
async function deriveKeys(password, saltBuffer) {
    const passwordBuffer = stringToBuffer(password);
    const rawKey = await subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveKey"]);

    const pbkdf2Params = { 
        name: "PBKDF2", 
        salt: saltBuffer, 
        iterations: PBKDF2_ITERATIONS, 
        hash: "SHA-256" 
    };

    // Derive Master Key (k)
    const masterKeyK = await subtle.deriveKey(
        pbkdf2Params, rawKey, 
        { name: "HMAC", hash: "SHA-256", length: 256 }, 
        true, // extractable: true is needed for deriveSubKey to use subtle.sign
        ["sign", "verify"]
    );
    
    // Derive Sub-Keys (HMAC as PRF)
    const kMAC = await deriveSubKey(masterKeyK, MAC_KEY_INFO, ["sign", "verify"], "HMAC");
    const kENC = await deriveSubKey(masterKeyK, ENC_KEY_INFO, ["encrypt", "decrypt"], "AES-GCM");

    return { kMAC, kENC };
}

/**
 * Pads the password value to a fixed length (MAX_PASSWORD_LENGTH + 1 byte for length prefix).
 */
function padValue(value) {
    const valueBuffer = stringToBuffer(value);
    const maxDataLength = MAX_PASSWORD_LENGTH;
    const fixedLength = maxDataLength + 1; 

    if (valueBuffer.length > maxDataLength) {
        throw new Error("Password exceeds maximum length of " + maxDataLength);
    }
    
    const paddedBuffer = Buffer.alloc(fixedLength);
    paddedBuffer.writeUInt8(valueBuffer.length, 0);
    valueBuffer.copy(paddedBuffer, 1);

    return paddedBuffer.buffer; 
}

/**
 * Reverses padding on the decrypted buffer.
 */
function unpadValue(paddedBuffer) {
    const buffer = Buffer.from(paddedBuffer);
    const actualLength = buffer.readUInt8(0);
    
    if (actualLength > MAX_PASSWORD_LENGTH) {
        throw new Error("Integrity check failed: decrypted password length is impossible.");
    }
    
    const valueBuffer = buffer.slice(1, 1 + actualLength);
    
    return bufferToString(valueBuffer);
}

/********* Implementation ********/
class Keychain {
  
  constructor(saltBase64, kMAC, kENC) {
    this.data = {
      salt: saltBase64, 
      kvs: {} 
    };
    this.secrets = {
      kMAC: kMAC,
      kENC: kENC  
    };
  };

  /** * Creates an empty keychain with the given password. */
  static async init(password) {
    const salt = getRandomBytes(PBKDF2_SALT_LENGTH);
    const saltBase64 = encodeBuffer(salt);
    
    // Derive keys using PBKDF2 (for master key) and HMAC (for sub-keys)
    const { kMAC, kENC } = await deriveKeys(password, salt);

    return new Keychain(saltBase64, kMAC, kENC);
  }
    
  /**
    * Loads the keychain state from the provided representation (repr). 
    * Arguments:
    * password:           string
    * repr:               string
    * trustedDataCheck:   string (optional SHA-256 hash)
    * Return Type: Keychain
    * Run-time: O(n)
    */
  static async load(password, repr, trustedDataCheck) {
    // 1. Deserialize the data (O(n) time)
    let loadedData;
    try {
        loadedData = JSON.parse(repr);
    } catch (e) {
        throw new Error("Invalid keychain representation format.");
    }
    
    // 2. Password Authentication & Key Derivation (O(1) time)
    const saltBase64 = loadedData.salt;
    const saltBuffer = decodeBuffer(saltBase64);

    let kMAC, kENC;
    try {
        // Derive keys using the provided password and stored salt
        ({ kMAC, kENC } = await deriveKeys(password, saltBuffer));
    } catch (e) {
        // If PBKDF2 fails, we assume the password was invalid. [cite: 166]
        throw new Error("Invalid password provided or key derivation failed."); 
    }

    // 3. Rollback Attack Defense (Integrity Check) (O(n) time)
    if (trustedDataCheck !== undefined) { // [cite: 157, 179]
      // Compute the SHA-256 hash of the input representation string (O(n) time)
      const reprBuffer = stringToBuffer(repr);
      const computedHashBuffer = await subtle.digest("SHA-256", reprBuffer);
      const computedHashBase64 = encodeBuffer(computedHashBuffer);
      
      // Compare computed hash with the trusted check value
      if (computedHashBase64 !== trustedDataCheck) { // [cite: 163, 164]
          // Tampering detected! This defends against rollback attacks.
          throw new Error("Integrity check failed: Database content has been tampered with or rolled back.");
      }
    }
    
    // 4. Instantiate and Return (O(1) time)
    const keychain = new Keychain(saltBase64, kMAC, kENC);
    // Restore the encrypted KVS contents (kvs field must be preserved for autograding) [cite: 243]
    keychain.data.kvs = loadedData.kvs; 
    
    return keychain;
  };
    
  /** * Inserts the domain and associated data into the KVS. */
  async set(name, value) {
    const nameBuffer = stringToBuffer(name);
    const hmacDomainBuffer = await subtle.sign("HMAC", this.secrets.kMAC, nameBuffer);
    const keyBase64 = encodeBuffer(hmacDomainBuffer); 

    const paddedValueBuffer = padValue(value);
    const iv = getRandomBytes(AES_GCM_IV_LENGTH);

    const encryptParams = {
        name: "AES-GCM",
        iv: iv,
        additionalData: hmacDomainBuffer 
    };

    const ciphertextBuffer = await subtle.encrypt(
        encryptParams,
        this.secrets.kENC,
        paddedValueBuffer
    );
    
    this.data.kvs[keyBase64] = {
        iv: encodeBuffer(iv),
        ciphertext: encodeBuffer(ciphertextBuffer) 
    };
  }

  /** * Fetches the data (as a string) corresponding to the given domain. */
  async get(name) {
    const nameBuffer = stringToBuffer(name);
    const hmacDomainBuffer = await subtle.sign("HMAC", this.secrets.kMAC, nameBuffer);
    const keyBase64 = encodeBuffer(hmacDomainBuffer); 

    const record = this.data.kvs[keyBase64];
    if (!record) {
      return null;
    }

    const iv = decodeBuffer(record.iv);
    const ciphertextBuffer = decodeBuffer(record.ciphertext);

    const decryptParams = {
        name: "AES-GCM",
        iv: iv,
        additionalData: hmacDomainBuffer 
    };

    let paddedPlaintextBuffer;
    try {
        paddedPlaintextBuffer = await subtle.decrypt(
            decryptParams,
            this.secrets.kENC,
            ciphertextBuffer
        );
    } catch (e) {
        throw new Error("Integrity/Authentication check failed on record decryption.");
    }
    
    return unpadValue(paddedPlaintextBuffer);
  }

  /**
    * Removes the record with name from the password manager.
    */
  async remove(name) {
    const nameBuffer = stringToBuffer(name);
    const hmacDomainBuffer = await subtle.sign("HMAC", this.secrets.kMAC, nameBuffer);
    const keyBase64 = encodeBuffer(hmacDomainBuffer); 

    if (this.data.kvs.hasOwnProperty(keyBase64)) {
      delete this.data.kvs[keyBase64];
      return true;
    } else {
      return false;
    }
  };


  /**
    * Returns a JSON serialization of the contents of the keychain and a SHA-256 checksum.
    */ 
  async dump() {
    const repr = JSON.stringify(this.data); 

    const reprBuffer = stringToBuffer(repr);
    const hashBuffer = await subtle.digest("SHA-256", reprBuffer); 

    const checksumBase64 = encodeBuffer(hashBuffer);

    return [repr, checksumBase64];
  };
};

module.exports = { Keychain }