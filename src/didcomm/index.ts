/**
 * DIDComm Module - Enhanced messaging with signatures and session DIDs
 * 
 * This module provides comprehensive DIDComm functionality including:
 * - Message signing and verification
 * - Session DID creation from biometric data
 * - Enhanced DIDComm client for secure messaging
 * - TypeScript types and interfaces
 */

// Core message signing functionality
export {
  signMessage,
  verifyMessageSignature,
  signDIDCommMessage,
  verifyDIDCommMessageSignature
} from './messageSigning.js';

// Session DID functionality
export {
  createSessionDID,
  recreateSessionDID,
  verifySessionDID,
  signWithSessionDID,
  verifySessionDIDSignature
} from './sessionDID.js';

// Enhanced DIDComm client
export {
  DIDCommClient
} from './didcommClient.js';

// Types and interfaces
export type {
  SignedMessage,
  MessageSigningOptions,
  SessionDIDResult,
  BiometricData,
  SignedMessageOptions,
  SessionSignedMessageOptions,
  MessageVerificationResult,
  SignedDIDCommMessage,
  SessionVerificationRequest,
  SessionVerificationResponse,
  DIDCommClientConfig,
  KeyInfo,
  VerificationMethod,
  MessageRouting,
  ErrorDetails
} from './types.js';

export {
  MessageType,
  SignatureAlgorithm,
  isSignedMessage,
  isSessionDIDResult,
  isBiometricData
} from './types.js';

// Re-export existing messenger functionality for convenience
export {
  encryptMessage,
  decryptMessage,
  sendMessage
} from '../messanger.js';
