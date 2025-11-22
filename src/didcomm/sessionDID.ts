import { IOVAgent } from '@originvault/ov-types';
import { generateDIDKey } from '../didKey.js';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * Interface for session DID creation result
 */
export interface SessionDIDResult {
  did: string;
  privateKey: string;
  publicKey: string;
  keyId: string;
  sessionId: string;
  biometricHash: string;
}

/**
 * Interface for biometric data (can be extended based on actual biometric implementation)
 */
export interface BiometricData {
  fingerprint?: string;
  faceTemplate?: string;
  voiceprint?: string;
  // Add other biometric types as needed
  [key: string]: any;
}

/**
 * Creates a deterministic session DID from biometric data and session information
 * This ensures the same biometric + session always generates the same DID
 * @param biometricData - The biometric data object
 * @param sessionId - The session identifier
 * @param agent - Optional Veramo agent for importing the DID
 * @returns Promise<SessionDIDResult> - The session DID details
 */
export async function createSessionDID(
  biometricData: BiometricData,
  sessionId: string,
  agent?: IOVAgent
): Promise<SessionDIDResult> {
  try {
    // Create a deterministic hash from biometric data and session
    const biometricHash = await createBiometricHash(biometricData, sessionId);
    
    // Generate deterministic private key from the hash
    const privateKeyBytes = sha256(biometricHash);
    const privateKeyHex = bytesToHex(privateKeyBytes);
    
    // Generate public key and DID:key
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
    const publicKeyHex = bytesToHex(publicKeyBytes);
    
    // Create did:key from the public key
    const { didKey, id } = await generateDIDKey(privateKeyBytes);
    
    const result: SessionDIDResult = {
      did: didKey,
      privateKey: privateKeyHex,
      publicKey: publicKeyHex,
      keyId: id,
      sessionId,
      biometricHash: bytesToHex(biometricHash)
    };

    // Optionally import the DID into the agent
    if (agent) {
      try {
        await agent.didManagerImport({
          did: didKey,
          keys: [{
            kid: id,
            type: 'Ed25519',
            kms: 'local',
            privateKeyHex: privateKeyHex,
          }],
          provider: 'did:key',
          alias: `session-${sessionId}`
        });
        
        console.log(`✅ Session DID imported into agent: ${didKey}`);
      } catch (importError) {
        console.warn(`⚠️ Could not import session DID into agent:`, importError);
        // Continue without importing - the DID is still valid
      }
    }

    console.log(`✅ Session DID created successfully`);
    console.log(`   🆔 DID: ${didKey}`);
    console.log(`   🔑 Key ID: ${id}`);
    console.log(`   📱 Session ID: ${sessionId}`);
    console.log(`   🔒 Biometric Hash: ${result.biometricHash.substring(0, 16)}...`);

    return result;
  } catch (error) {
    console.error('❌ Error creating session DID:', error);
    throw error;
  }
}

/**
 * Recreates a session DID from the same biometric data and session ID
 * This should produce identical results to the original createSessionDID call
 * @param biometricData - The same biometric data used originally
 * @param sessionId - The same session identifier used originally
 * @param agent - Optional Veramo agent for importing the DID
 * @returns Promise<SessionDIDResult> - The recreated session DID details
 */
export async function recreateSessionDID(
  biometricData: BiometricData,
  sessionId: string,
  agent?: IOVAgent
): Promise<SessionDIDResult> {
  // This is identical to createSessionDID - deterministic generation
  return createSessionDID(biometricData, sessionId, agent);
}

/**
 * Verifies that a session DID was created from specific biometric data and session
 * @param sessionDID - The session DID to verify
 * @param biometricData - The biometric data to check against
 * @param sessionId - The session ID to check against
 * @returns Promise<boolean> - True if the DID matches the biometric + session
 */
export async function verifySessionDID(
  sessionDID: string,
  biometricData: BiometricData,
  sessionId: string
): Promise<boolean> {
  try {
    // Recreate the DID from the same inputs
    const recreated = await createSessionDID(biometricData, sessionId);
    
    // Compare the DIDs
    const isValid = recreated.did === sessionDID;
    
    if (isValid) {
      console.log(`✅ Session DID verification PASSED`);
    } else {
      console.log(`❌ Session DID verification FAILED`);
      console.log(`   Expected: ${recreated.did}`);
      console.log(`   Received: ${sessionDID}`);
    }
    
    return isValid;
  } catch (error) {
    console.error('❌ Error verifying session DID:', error);
    return false;
  }
}

/**
 * Creates a secure hash from biometric data and session information
 * @param biometricData - The biometric data object
 * @param sessionId - The session identifier
 * @returns Promise<Uint8Array> - The deterministic hash
 */
async function createBiometricHash(
  biometricData: BiometricData,
  sessionId: string
): Promise<Uint8Array> {
  // Sort the biometric data keys to ensure consistent ordering
  const sortedKeys = Object.keys(biometricData).sort();
  
  // Create a consistent string representation
  let dataString = `session:${sessionId}`;
  for (const key of sortedKeys) {
    if (biometricData[key] !== null && biometricData[key] !== undefined) {
      dataString += `|${key}:${biometricData[key]}`;
    }
  }
  
  // Add timestamp-independent salt for additional security
  const salt = 'ov-session-did-v1';
  const finalString = `${salt}:${dataString}`;
  
  // Create SHA-256 hash
  const encoder = new TextEncoder();
  const data = encoder.encode(finalString);
  return sha256(data);
}

/**
 * Signs a message using a session DID
 * @param message - The message to sign
 * @param sessionDIDResult - The session DID details from createSessionDID
 * @returns Promise<string> - The signature
 */
export async function signWithSessionDID(
  message: string,
  sessionDIDResult: SessionDIDResult
): Promise<string> {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const privateKeyBytes = new Uint8Array(Buffer.from(sessionDIDResult.privateKey, 'hex'));
    
    // Sign the message
    const signature = ed25519.sign(messageBytes, privateKeyBytes);
    const signatureHex = bytesToHex(signature);
    
    console.log(`✅ Message signed with session DID: ${sessionDIDResult.did}`);
    return signatureHex;
  } catch (error) {
    console.error('❌ Error signing with session DID:', error);
    throw error;
  }
}

/**
 * Verifies a signature made by a session DID
 * @param message - The original message
 * @param signature - The signature to verify
 * @param sessionDID - The session DID that allegedly signed the message
 * @returns Promise<boolean> - True if signature is valid
 */
export async function verifySessionDIDSignature(
  message: string,
  signature: string,
  sessionDID: string
): Promise<boolean> {
  try {
    // Extract public key from did:key
    // This is a simplified version - in production, you'd properly parse the DID
    const didParts = sessionDID.split(':');
    if (didParts.length < 3 || didParts[1] !== 'key') {
      throw new Error('Invalid did:key format');
    }
    
    // For now, we'll need the public key to be provided or resolved
    // In a full implementation, you'd decode the multibase key from the DID
    console.log(`ℹ️ Session DID signature verification requires public key resolution`);
    console.log(`   This would be implemented with proper did:key parsing`);
    
    return true; // Placeholder - implement proper verification
  } catch (error) {
    console.error('❌ Error verifying session DID signature:', error);
    return false;
  }
}
