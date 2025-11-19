import { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } from "./lib";

// Use standard Web Crypto API
const subtle = window.crypto.subtle;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;
const PBKDF2_SALT_LENGTH = 16;
const AES_GCM_IV_LENGTH = 12;
const MAC_KEY_INFO = stringToBuffer("MAC_KEY_DERIVATION");
const ENC_KEY_INFO = stringToBuffer("AES_KEY_DERIVATION");
const AUTH_TAG_INFO = stringToBuffer("AUTH_TAG_VERIFICATION_DATA");

/********* Helper Functions ********/

/**
 * Executes only the PBKDF2 step to derive the master key (k).
 */
async function deriveMasterKey(password, saltBuffer) {
  const passwordBuffer = stringToBuffer(password);

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

  // Derive Master Key (k). This key is usable for HMAC (needed for derivation/auth tag).
  return await subtle.deriveKey(
    pbkdf2Params,
    rawKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true, // Must be extractable/usable for sub-key derivation
    ["sign", "verify"]
  );
}

/**
 * Derives a sub-key from the master key k using HMAC-SHA256 as a PRF.
 */
async function deriveSubKey(masterKey, info, keyUsages, algorithmName) {
  const rawKeyBuffer = await subtle.sign("HMAC", masterKey, info);

  let algorithmParams;
  if (algorithmName === "HMAC") {
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
 * Derives kMAC and kENC subkeys.
 */
async function deriveSubKeys(masterKeyK) {
  const kMAC = await deriveSubKey(masterKeyK, MAC_KEY_INFO, ["sign", "verify"], "HMAC");
  const kENC = await deriveSubKey(masterKeyK, ENC_KEY_INFO, ["encrypt", "decrypt"], "AES-GCM");
  return { kMAC, kENC };
}

/**
 * Pads the password value to a fixed length.
 * Uses Uint8Array for browser compatibility instead of Node Buffer.
 */
function padValue(value) {
  const valueBuffer = stringToBuffer(value);
  const padded = new Uint8Array(MAX_PASSWORD_LENGTH + 1);

  if (valueBuffer.length > MAX_PASSWORD_LENGTH) {
    throw new Error("Password too long");
  }

  padded[0] = valueBuffer.length;
  padded.set(valueBuffer, 1);
  return padded;
}

/**
 * Reverses padding on the decrypted buffer.
 */
function unpadValue(paddedBuffer) {
  const view = new Uint8Array(paddedBuffer);
  const length = view[0];
  
  if (length > MAX_PASSWORD_LENGTH) {
      throw new Error("Integrity check failed: decrypted password length is corrupt.");
  }

  return bufferToString(view.slice(1, 1 + length));
}

/********* Implementation ********/

export class Keychain {
  constructor(saltBase64, authTagBase64, kMAC, kENC) {
    this.data = {
      salt: saltBase64,
      authTag: authTagBase64, // NEW: Authentication Tag for load verification
      kvs: {}
    };
    this.secrets = {
      kMAC: kMAC,
      kENC: kENC
    };
  }

  /**
   * Creates an empty keychain with the given password.
   */
  static async init(password) {
    const salt = getRandomBytes(PBKDF2_SALT_LENGTH);
    const saltBase64 = encodeBuffer(salt);

    // 1. Derive Master Key (k)
    const masterKeyK = await deriveMasterKey(password, salt);

    // 2. Derive Sub-Keys (kMAC, kENC)
    const { kMAC, kENC } = await deriveSubKeys(masterKeyK);

    // 3. Derive Authentication Tag T = HMAC(k, "AUTH_TAG_VERIFICATION_DATA")
    const authTagBuffer = await subtle.sign("HMAC", masterKeyK, AUTH_TAG_INFO);
    const authTagBase64 = encodeBuffer(authTagBuffer);

    return new Keychain(saltBase64, authTagBase64, kMAC, kENC);
  }

  /**
   * Loads the keychain state from the provided representation (repr).
   */
  static async load(password, repr, trustedDataCheck) {
    // 1. Deserialize the data
    let loadedData;
    try {
      loadedData = JSON.parse(repr);
    } catch (e) {
      throw new Error("Invalid keychain representation format.");
    }

    // 2. Password Authentication
    const saltBase64 = loadedData.salt;
    const saltBuffer = decodeBuffer(saltBase64);
    const storedAuthTagBase64 = loadedData.authTag; // Retrieve stored tag

    let masterKeyK;
    try {
      // Derive Master Key (k) using the user's password and stored salt
      masterKeyK = await deriveMasterKey(password, saltBuffer);

      // Calculate verification tag T' = HMAC(k', "AUTH_TAG_VERIFICATION_DATA")
      const computedAuthTagBuffer = await subtle.sign("HMAC", masterKeyK, AUTH_TAG_INFO);
      const computedAuthTagBase64 = encodeBuffer(computedAuthTagBuffer);

      // **AUTHENTICATION CHECK**: Compare T' with stored T.
      if (computedAuthTagBase64 !== storedAuthTagBase64) {
        throw new Error("Invalid password provided. Password verification failed.");
      }
    } catch (e) {
      if (e.message.includes("Invalid password")) {
        throw e;
      }
      throw new Error("Invalid password provided. Password verification failed.");
    }

    // 3. Derive Sub-Keys (kMAC, kENC) using the authenticated master key
    const { kMAC, kENC } = await deriveSubKeys(masterKeyK);

    // 4. Rollback Attack Defense (Integrity Check)
    if (trustedDataCheck !== undefined && trustedDataCheck !== null) {
      const reprBuffer = stringToBuffer(repr);
      const computedHashBuffer = await subtle.digest("SHA-256", reprBuffer);
      const computedHashBase64 = encodeBuffer(computedHashBuffer);

      if (computedHashBase64 !== trustedDataCheck) {
        throw new Error("Integrity check failed: Database content has been tampered with or rolled back.");
      }
    }

    // 5. Instantiate and Return
    const keychain = new Keychain(saltBase64, storedAuthTagBase64, kMAC, kENC);
    keychain.data.kvs = loadedData.kvs;

    return keychain;
  }

  /**
   * Inserts the domain and associated data into the KVS.
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

  /**
   * Fetches the data (as a string) corresponding to the given domain.
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
  }

  /**
   * Returns a JSON serialization of the contents of the keychain and a SHA-256 checksum.
   */
  async dump() {
    const repr = JSON.stringify(this.data);

    const reprBuffer = stringToBuffer(repr);
    const hashBuffer = await subtle.digest("SHA-256", reprBuffer);

    const checksumBase64 = encodeBuffer(hashBuffer);

    return [repr, checksumBase64];
  }
}