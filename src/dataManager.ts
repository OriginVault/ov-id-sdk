import { x25519 } from '@noble/curves/ed25519';
import sodium from 'libsodium-wrappers';

export async function encryptData(publicKeyBytes, message) {
    // Validate the public key length
    if (publicKeyBytes.length !== 32) {
        throw new Error('Invalid public key length. Expected 32 bytes.');
    }

    // Step 2: Convert Ed25519 to X25519
    const x25519PublicKey = x25519.getPublicKey(publicKeyBytes);

    // Encrypt data using libsodium.js
    await sodium.ready;
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const encryptedMessage = sodium.crypto_box_easy(
        Buffer.from(message), // Message
        nonce,
        x25519PublicKey, // Receiver's public key
        sodium.crypto_box_keypair().privateKey // Your private key (for sender authentication)
    );

    // Return the encrypted message and nonce
    return { encryptedMessage, nonce };
}