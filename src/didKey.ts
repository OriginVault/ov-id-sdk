import { storePrivateKey } from './storePrivateKeys.js';
import { ed25519 } from '@noble/curves/ed25519';
import multibase from 'multibase';

/**
 * Generates a `did:key` from an Ed25519 private key.
 * @param privateKey - A 32-byte Ed25519 private key (Uint8Array).
 * @returns The corresponding `did:key` DID string.
 */
export async function generateDIDKey(privateKey: Uint8Array): Promise<{ id: string, didKey: string }> {
  // Derive the public key from the private key
  const publicKeyBytes = await ed25519.getPublicKey(privateKey);

  // Encode in multibase (base64)
  const encodedKey = Buffer.from(multibase.encode('base58btc', publicKeyBytes));
  const id = encodedKey.toString('utf-8');
  // Construct and return the `did:key`
  return { didKey: `did:key:${id}`, id };
}

/**
 * Extracts the Ed25519 public key from a `did:key`.
 * @param didKey - The `did:key` string.
 * @returns The corresponding public key as a Uint8Array.
 */
export function extractPublicKeyFromDIDKey(didKey: string): Uint8Array {
  // Remove `did:key:` prefix
  const base58EncodedKey = didKey.split(":")[2];

  // Decode from multibase (base58btc)
  const decodedKey = multibase.decode(base58EncodedKey);

  // Remove the first byte (0xed) which is the multicodec prefix for Ed25519
  return decodedKey.slice(1);
}

/**
 * Generates a `did:key`, stores the private key securely, and returns the DID.
 * @param userId - The user's unique identifier.
 * @returns The generated `did:key` DID.
 */
export async function createAndStoreDIDKey(userId: string): Promise<string> {
  // Generate a new Ed25519 private key
  const privateKey: Uint8Array = ed25519.utils.randomPrivateKey();

  // Generate `did:key`
  const didKey = await generateDIDKey(privateKey);

  // Store the private key securely
  await storePrivateKey(userId, privateKey, didKey.id);

  console.log(`✅ DID Key Created: ${didKey.didKey}`);
  return didKey.didKey;
}