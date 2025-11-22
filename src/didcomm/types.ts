/**
 * Core types for DIDComm message signing and session DID functionality
 */

/**
 * Interface for a signed message
 */
export interface SignedMessage {
  message: string;
  signature: string;
  signer: string; // DID of the signer
  timestamp: string;
  messageId: string;
  nonce?: string; // Optional nonce for replay protection
  messageType?: string; // Optional message type
}

/**
 * Interface for message signing options
 */
export interface MessageSigningOptions {
  signer: string; // DID to use for signing
  keyRef?: string; // Optional specific key reference
  includeNonce?: boolean; // Whether to include a nonce
  messageType?: string; // Optional message type
}

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
  webauthnCredential?: string; // WebAuthn credential ID
  deviceFingerprint?: string; // Device-specific fingerprint
  behavioralPattern?: string; // Behavioral biometrics
  // Add other biometric types as needed
  [key: string]: any;
}

/**
 * Interface for sending a signed message
 */
export interface SignedMessageOptions {
  recipient: string;
  message: string;
  signer: string;
  encrypt?: boolean;
  storeMessage?: boolean;
  messageType?: string;
}

/**
 * Interface for sending a session-signed message
 */
export interface SessionSignedMessageOptions {
  recipient: string;
  message: string;
  biometricData: BiometricData;
  sessionId: string;
  encrypt?: boolean;
  storeMessage?: boolean;
  messageType?: string;
}

/**
 * Interface for message verification result
 */
export interface MessageVerificationResult {
  isValid: boolean;
  signedMessage?: SignedMessage;
  message?: any;
  signer?: string;
  verificationErrors?: string[];
}

/**
 * Interface for DIDComm message with signature attachment
 */
export interface SignedDIDCommMessage {
  id: string;
  type: string;
  to: string;
  from: string;
  body: {
    content: string;
    signature?: string;
    timestamp?: string;
    messageId?: string;
    [key: string]: any;
  };
  attachments?: Array<{
    id: string;
    description?: string;
    data: {
      json?: SignedMessage;
      [key: string]: any;
    };
  }>;
}

/**
 * Interface for session verification request
 */
export interface SessionVerificationRequest {
  sessionDID: string;
  biometricData: BiometricData;
  sessionId: string;
  challenge?: string; // Optional challenge for additional security
}

/**
 * Interface for session verification response
 */
export interface SessionVerificationResponse {
  isValid: boolean;
  sessionDID: string;
  timestamp: string;
  errors?: string[];
}

/**
 * Interface for DIDComm client configuration
 */
export interface DIDCommClientConfig {
  defaultEncryption?: boolean;
  defaultMessageStorage?: boolean;
  sessionTimeout?: number; // in milliseconds
  maxSessionsPerUser?: number;
  requireBiometricVerification?: boolean;
}

/**
 * Enum for message types
 */
export enum MessageType {
  BASIC_MESSAGE = 'https://didcomm.org/basicmessage/2.0/message',
  SIGNED_MESSAGE = 'https://didcomm.org/signedmessage/1.0/message',
  SESSION_MESSAGE = 'https://didcomm.org/sessionmessage/1.0/message',
  VERIFICATION_REQUEST = 'https://didcomm.org/verification/1.0/request',
  VERIFICATION_RESPONSE = 'https://didcomm.org/verification/1.0/response'
}

/**
 * Enum for signature algorithms
 */
export enum SignatureAlgorithm {
  ED25519 = 'Ed25519',
  SECP256K1 = 'secp256k1',
  SECP256R1 = 'secp256r1'
}

/**
 * Interface for key information
 */
export interface KeyInfo {
  keyId: string;
  keyType: SignatureAlgorithm;
  publicKey: string;
  privateKey?: string; // Only included when needed
  controller: string; // DID that controls this key
}

/**
 * Interface for DID document verification method
 */
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyHex?: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: any;
}

/**
 * Interface for message routing information
 */
export interface MessageRouting {
  from: string;
  to: string;
  via?: string[]; // Intermediate routing DIDs
  timestamp: string;
  messageId: string;
}

/**
 * Interface for error details
 */
export interface ErrorDetails {
  code: string;
  message: string;
  details?: any;
  timestamp: string;
}

/**
 * Type guard to check if an object is a SignedMessage
 */
export function isSignedMessage(obj: any): obj is SignedMessage {
  return (
    typeof obj === 'object' &&
    typeof obj.message === 'string' &&
    typeof obj.signature === 'string' &&
    typeof obj.signer === 'string' &&
    typeof obj.timestamp === 'string' &&
    typeof obj.messageId === 'string'
  );
}

/**
 * Type guard to check if an object is a SessionDIDResult
 */
export function isSessionDIDResult(obj: any): obj is SessionDIDResult {
  return (
    typeof obj === 'object' &&
    typeof obj.did === 'string' &&
    typeof obj.privateKey === 'string' &&
    typeof obj.publicKey === 'string' &&
    typeof obj.keyId === 'string' &&
    typeof obj.sessionId === 'string' &&
    typeof obj.biometricHash === 'string'
  );
}

/**
 * Type guard to check if an object is BiometricData
 */
export function isBiometricData(obj: any): obj is BiometricData {
  return typeof obj === 'object' && obj !== null;
}
