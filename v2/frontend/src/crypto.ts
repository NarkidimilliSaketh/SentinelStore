// src/crypto.ts

import nacl from 'tweetnacl';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha512 } from '@noble/hashes/sha512';
import { randomBytes } from '@noble/hashes/utils';
import secrets from 'secrets.js';

// --- (No complex initialization needed) ---
export async function initializeModules() {
  return Promise.resolve();
}

// --- Helper functions for Hex and Base64 conversions ---
function uint8ArrayToHex(arr: Uint8Array): string {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToUint8Array(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

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

// --- Core Cryptographic Functions ---

export async function hashData(data: Uint8Array): Promise<string> {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data as BufferSource);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  return pbkdf2(sha512, password, salt, { c: 100000, dkLen: 32 });
}

// --- NEW: Asymmetric (Public/Private Key) Cryptography ---

/**
 * Generates a new public/private key pair for a user.
 */
export function generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const keyPair = nacl.box.keyPair();
  return { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey };
}

/**
 * Encrypts a message (like a File Key) for a recipient using their public key.
 * @param message The data to encrypt.
 * @param recipientPublicKey The public key of the person who should be able to decrypt it.
 * @returns The encrypted message (ciphertext).
 */
export function encryptAsymmetric(message: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  // We need a temporary, random key pair for the sender for this operation
  const ephemeralKeyPair = nacl.box.keyPair();
  const nonce = randomBytes(nacl.box.nonceLength);
  
  const encryptedMessage = nacl.box(
    message,
    nonce,
    recipientPublicKey,
    ephemeralKeyPair.secretKey
  );

  // The final package must include the nonce and the sender's public key for decryption
  const fullMessage = new Uint8Array(ephemeralKeyPair.publicKey.length + nonce.length + encryptedMessage.length);
  fullMessage.set(ephemeralKeyPair.publicKey);
  fullMessage.set(nonce, ephemeralKeyPair.publicKey.length);
  fullMessage.set(encryptedMessage, ephemeralKeyPair.publicKey.length + nonce.length);
  
  return fullMessage;
}

/**
 * Decrypts a message that was encrypted with the user's public key.
 * @param fullMessage The encrypted package from encryptAsymmetric.
 * @param userSecretKey The user's own private/secret key.
 * @returns The decrypted message, or null if decryption fails.
 */
export function decryptAsymmetric(fullMessage: Uint8Array, userSecretKey: Uint8Array): Uint8Array | null {
  const senderPublicKey = fullMessage.slice(0, nacl.box.publicKeyLength);
  const nonce = fullMessage.slice(nacl.box.publicKeyLength, nacl.box.publicKeyLength + nacl.box.nonceLength);
  const ciphertext = fullMessage.slice(nacl.box.publicKeyLength + nacl.box.nonceLength);

  return nacl.box.open(
    ciphertext,
    nonce,
    senderPublicKey,
    userSecretKey
  );
}

// --- Symmetric (Secret Key) Cryptography ---

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

// --- Fault Tolerance (Unchanged) ---

export function createShares(data: Uint8Array, totalShares: number, requiredShares: number): Uint8Array[] {
  const dataHex = uint8ArrayToHex(data);
  const sharesHex = secrets.share(dataHex, totalShares, requiredShares);
  return sharesHex.map((share: string) => new TextEncoder().encode(share));
}

export function combineShares(receivedShares: Uint8Array[]): Uint8Array {
  const sharesHex = receivedShares.map(shard => new TextDecoder().decode(shard));
  const combinedHex = secrets.combine(sharesHex);
  return hexToUint8Array(combinedHex);
}