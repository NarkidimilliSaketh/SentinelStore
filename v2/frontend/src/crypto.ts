// src/crypto.ts

import nacl from 'tweetnacl';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/hashes/utils';
// Import from the correct, existing library 'shamirs-secret-sharing'
import { split, combine } from 'shamirs-secret-sharing';

export async function initializeModules() {
  return Promise.resolve();
}

// --- Helper functions (Unchanged) ---
export function uint8ArrayToBase64(data: Uint8Array): string {
    const CHUNK_SIZE = 0x8000;
    let result = '';
    for (let i = 0; i < data.length; i += CHUNK_SIZE) {
        const chunk = data.subarray(i, i + CHUNK_SIZE);
        result += String.fromCharCode.apply(null, Array.from(chunk));
    }
    return btoa(result);
}

export function base64ToUint8Array(base64: string): Uint8Array {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

// --- Core Cryptographic Functions (Unchanged) ---
export async function hashData(data: Uint8Array): Promise<string> {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data as BufferSource);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  return pbkdf2(sha512, password, salt, { c: 100000, dkLen: 32 });
}

export function generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const keyPair = nacl.box.keyPair();
  return { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey };
}

export function encryptAsymmetric(message: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  const ephemeralKeyPair = nacl.box.keyPair();
  const nonce = randomBytes(nacl.box.nonceLength);
  const encryptedMessage = nacl.box(message, nonce, recipientPublicKey, ephemeralKeyPair.secretKey);
  const fullMessage = new Uint8Array(ephemeralKeyPair.publicKey.length + nonce.length + encryptedMessage.length);
  fullMessage.set(ephemeralKeyPair.publicKey);
  fullMessage.set(nonce, ephemeralKeyPair.publicKey.length);
  fullMessage.set(encryptedMessage, ephemeralKeyPair.publicKey.length + nonce.length);
  return fullMessage;
}

export function decryptAsymmetric(fullMessage: Uint8Array, userSecretKey: Uint8Array): Uint8Array | null {
  const senderPublicKey = fullMessage.slice(0, nacl.box.publicKeyLength);
  const nonce = fullMessage.slice(nacl.box.publicKeyLength, nacl.box.publicKeyLength + nacl.box.nonceLength);
  const ciphertext = fullMessage.slice(nacl.box.publicKeyLength + nacl.box.nonceLength);
  return nacl.box.open(ciphertext, nonce, senderPublicKey, userSecretKey);
}

export function generateSymmetricKey(): Uint8Array {
  return randomBytes(nacl.secretbox.keyLength);
}

export function encryptSymmetric(data: Uint8Array, key: Uint8Array): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(nacl.secretbox.nonceLength);
  const ciphertext = nacl.secretbox(data, nonce, key);
  return { ciphertext, nonce };
}
export function decryptSymmetric(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null {
  return nacl.secretbox.open(ciphertext, nonce, key);
}

// --- Fault Tolerance using a Standard Shamir's Library (Simplified) ---
export function createShares(data: Uint8Array, totalShares: number, requiredShares: number): Uint8Array[] {
  // The library takes the secret as bytes and returns shares as bytes. This is perfect.
  const shares = split(data, { shares: totalShares, threshold: requiredShares });
  return shares;
}

export function combineShares(receivedShares: Uint8Array[]): Uint8Array {
  // The library takes the byte shares and returns the reconstructed secret as bytes.
  const combined = combine(receivedShares);
  return combined;
}

// --- Shared utility function ---
export type ImportanceLevel = 'Normal' | 'Important' | 'Critical';

export function getShamirParams(importance: ImportanceLevel): { n: number; k: number } {
  switch (importance) {
    case 'Normal': return { n: 5, k: 3 };
    case 'Important': return { n: 7, k: 5 };
    case 'Critical': return { n: 10, k: 7 };
  }
}