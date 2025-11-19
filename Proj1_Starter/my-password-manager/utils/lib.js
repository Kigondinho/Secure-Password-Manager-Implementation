// Replaces require('crypto') with window.crypto
export function stringToBuffer(str) {
  return new TextEncoder().encode(str);
}

export function bufferToString(buf) {
  return new TextDecoder().decode(buf);
}

export function encodeBuffer(buf) {
  // Browser-compatible Base64 encoding
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function decodeBuffer(base64) {
  // Browser-compatible Base64 decoding
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

export function getRandomBytes(len) {
  return window.crypto.getRandomValues(new Uint8Array(len));
}