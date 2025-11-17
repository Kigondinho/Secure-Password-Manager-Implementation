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
    
    // Define the required algorithm parameters, including 'hash' for HMAC
    let algorithmParams;
    if (algorithmName === "HMAC") {
        // FIX: HmacImportParams requires the 'hash' property
        algorithmParams = { name: "HMAC", hash: "SHA-256", length: 256 };
    } else { // AES-GCM case
        algorithmParams = { name: algorithmName, length: 256 };
    }

    return await subtle.importKey(
        "raw",
        rawKeyBuffer,
        algorithmParams, 
        false, 
        keyUsages
    );
}

/**
 * Encapsulates PBKDF2 and subsequent sub-key derivation. (O(1) time complexity)
 */
async function deriveKeys(password, saltBuffer) {
    const passwordBuffer = stringToBuffer(password);
    
    // 1. Import raw password key for PBKDF2
    const rawKey = await subtle.importKey(
      "raw", 
      passwordBuffer, 
      "PBKDF2", 
      false, 
      ["deriveKey"]
    );

    const pbkdf2Params = { 
        name: "PBKDF2", 
        salt: saltBuffer, 
        iterations: PBKDF2_ITERATIONS, 
        hash: "SHA-256" 
    };

    // 2. Derive Master Key (k). The deriveKey call for HMAC *must* specify the hash.
    const masterKeyK = await subtle.deriveKey(
        pbkdf2Params, rawKey, 
        { name: "HMAC", hash: "SHA-256", length: 256 }, 
        true, 
        ["sign", "verify"]
    );
    
    // 3. Derive Sub-Keys (HMAC as PRF) using the corrected helper
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

    Buffer.from(valueBuffer).copy(paddedBuffer, 1);

    return paddedBuffer.buffer; 
}

/**
 * Reverses padding on the decrypted buffer.
 */
function unpadValue(paddedBuffer) {
    const buffer = Buffer.from(paddedBuffer);
    const actualLength = buffer.readUInt8(0);
    
    if (actualLength > MAX_PASSWORD_LENGTH) {
        throw new Error("Integrity check failed: decrypted password length is corrupt.");
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

  /** * Creates an empty keychain with the given password. (O(1) runtime)
   */
  static async init(password) {
    const salt = getRandomBytes(PBKDF2_SALT_LENGTH);
    const saltBase64 = encodeBuffer(salt);
    
    const { kMAC, kENC } = await deriveKeys(password, salt);

    return new Keychain(saltBase64, kMAC, kENC);
  }
    
  /**
    * Loads the keychain state from the provided representation (repr). (O(n) runtime)
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
        // Explicitly throw "Invalid password" if key derivation fails or produces garbage keys
        throw new Error("Invalid password provided. Password verification failed."); 
    }

    // 3. Rollback Attack Defense (Integrity Check) (O(n) time)
    if (trustedDataCheck !== undefined) {
      const reprBuffer = stringToBuffer(repr);
      const computedHashBuffer = await subtle.digest("SHA-256", reprBuffer);
      const computedHashBase64 = encodeBuffer(computedHashBuffer);
      
      if (computedHashBase64 !== trustedDataCheck) { 
          throw new Error("Integrity check failed: Database content has been tampered with or rolled back.");
      }
    }
    
    // 4. Instantiate and Return
    const keychain = new Keychain(saltBase64, kMAC, kENC);
    keychain.data.kvs = loadedData.kvs; 
    
    return keychain;
  };
    
  /** * Inserts the domain and associated data into the KVS. (O(1) runtime)
   */
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

  /** * Fetches the data (as a string) corresponding to the given domain. (O(1) runtime)
   */
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
    * Removes the record with name from the password manager. (O(1) runtime)
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
    * Returns a JSON serialization of the contents of the keychain and a SHA-256 checksum. (O(n) runtime)
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