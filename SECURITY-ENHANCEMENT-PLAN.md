# OV-ID-SDK - Security Enhancement Development Plan

## Project Overview

This document outlines the critical security enhancement plan for ov-id-sdk, addressing multiple high-severity vulnerabilities and implementing enterprise-grade security features that can be shared with cheqd-studio.

## Critical Security Issues Identified

### 🚨 **IMMEDIATE FIXES REQUIRED**

1. **Fallback Signature Verification Always Returns True** (CRITICAL)
   - Location: `src/didcomm/messageSigning.ts:195`
   - Risk: Complete authentication bypass
   - Impact: Any message can be verified as valid

2. **Weak Encryption Implementation** (CRITICAL)
   - Location: `src/encryption.ts:9-18`
   - Risk: No salt, vulnerable CBC mode, no authentication
   - Impact: Data can be decrypted by attackers

3. **Private Keys in Plaintext** (CRITICAL)
   - Location: `src/storePrivateKeys.ts:229`
   - Risk: Keys exposed in file system
   - Impact: Complete compromise of user identities

4. **Hardcoded Default Encryption Key** (HIGH)
   - Location: `src/storePrivateKeys.ts:28`
   - Risk: Predictable encryption
   - Impact: All data encrypted with known key

## Development Phases

## Phase 1: Critical Security Fixes (Week 1)

### 1.1 Fix Signature Verification Vulnerability

**File**: `src/didcomm/messageSigning.ts` (Update)

**Current Vulnerable Code**:
```typescript
// ❌ CRITICAL VULNERABILITY
async function fallbackSignatureVerification(): Promise<boolean> {
    console.warn('⚠️  Using basic signature validation - cryptographic verification not implemented');
    return true; // ALWAYS TRUE - CRITICAL SECURITY HOLE
}
```

**Fixed Implementation**:
```typescript
import * as ed25519 from '@noble/ed25519';
import { bases } from 'multiformats/basics';

async function cryptographicSignatureVerification(
  signedMessage: SignedMessage,
  signaturePayload: string,
  identifier: any
): Promise<boolean> {
  try {
    // Get the public key from the DID document
    const verificationMethod = identifier.keys[0];
    if (!verificationMethod.publicKeyHex) {
      console.error('❌ No public key found in verification method');
      return false;
    }

    // Convert signature from base64 to bytes
    const signatureBytes = Buffer.from(signedMessage.signature, 'base64');
    const messageBytes = Buffer.from(signaturePayload, 'utf8');
    const publicKeyBytes = Buffer.from(verificationMethod.publicKeyHex, 'hex');

    // Verify Ed25519 signature
    const isValid = await ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    
    if (isValid) {
      console.log(`✅ Cryptographic signature verification PASSED for ${signedMessage.signer}`);
    } else {
      console.log(`❌ Cryptographic signature verification FAILED for ${signedMessage.signer}`);
    }

    return isValid;
  } catch (error) {
    console.error('❌ Error in cryptographic signature verification:', error);
    return false;
  }
}
```

**Tasks**:
- [ ] Replace fallback verification with proper cryptography
- [ ] Implement Ed25519 signature verification
- [ ] Add public key validation
- [ ] Test signature verification thoroughly
- [ ] Add error handling for edge cases

**Priority**: CRITICAL - Must be fixed immediately
**Estimated Time**: 1 day

### 1.2 Fix Encryption Implementation

**File**: `src/encryption.ts` (Complete Rewrite)

**Current Vulnerable Code**:
```typescript
// ❌ VULNERABLE ENCRYPTION
export function encryptPrivateKey(privateKey, password) {
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(password).digest(); // No salt!
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv); // Vulnerable CBC mode
}
```

**Secure Implementation**:
```typescript
import crypto from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(crypto.scrypt);

export interface SecureEncryptionResult {
  encryptedData: string;
  iv: string;
  salt: string;
  authTag: string;
  algorithm: string;
}

export async function encryptPrivateKeySecure(
  privateKey: string, 
  password: string
): Promise<SecureEncryptionResult> {
  try {
    // Generate cryptographically secure salt and IV
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Derive key using scrypt (much stronger than SHA256)
    const derivedKey = await scryptAsync(password, salt, 32) as Buffer;
    
    // Use AES-256-GCM for authenticated encryption
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv);
    
    let encryptedData = cipher.update(privateKey, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    
    // Get authentication tag for integrity verification
    const authTag = cipher.getAuthTag();
    
    // Zero out derived key from memory
    derivedKey.fill(0);
    
    return {
      encryptedData,
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      authTag: authTag.toString('hex'),
      algorithm: 'aes-256-gcm'
    };
  } catch (error) {
    throw new Error(`Secure encryption failed: ${error.message}`);
  }
}

export async function decryptPrivateKeySecure(
  encryptedResult: SecureEncryptionResult,
  password: string
): Promise<string> {
  try {
    // Derive the same key using stored salt
    const salt = Buffer.from(encryptedResult.salt, 'hex');
    const derivedKey = await scryptAsync(password, salt, 32) as Buffer;
    
    // Prepare for decryption
    const iv = Buffer.from(encryptedResult.iv, 'hex');
    const authTag = Buffer.from(encryptedResult.authTag, 'hex');
    
    // Use AES-256-GCM for authenticated decryption
    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
    decipher.setAuthTag(authTag);
    
    let decryptedData = decipher.update(encryptedResult.encryptedData, 'hex', 'utf8');
    decryptedData += decipher.final('utf8');
    
    // Zero out derived key from memory
    derivedKey.fill(0);
    
    return decryptedData;
  } catch (error) {
    throw new Error(`Secure decryption failed: ${error.message}`);
  }
}
```

**Tasks**:
- [ ] Replace vulnerable encryption with secure implementation
- [ ] Add proper salt generation
- [ ] Use AES-GCM instead of CBC
- [ ] Add authentication tags
- [ ] Implement secure key derivation
- [ ] Add memory protection

**Priority**: CRITICAL - Must be fixed immediately
**Estimated Time**: 1 day

### 1.3 Secure Key Storage

**File**: `src/security/secure-key-storage.ts` (New)

**Current Vulnerable Code**:
```typescript
// ❌ PLAINTEXT KEY STORAGE
fs.writeFileSync(KEYRING_FILE, JSON.stringify(kr.getPairs().map(pair => pair.toJson())));
```

**Secure Implementation**:
```typescript
import fs from 'fs';
import path from 'path';
import os from 'os';
import { encryptPrivateKeySecure, decryptPrivateKeySecure, SecureEncryptionResult } from '../encryption.js';

export interface SecureKeyEntry {
  keyId: string;
  did: string;
  encryptedPrivateKey: SecureEncryptionResult;
  publicKeyHex: string;
  createdAt: string;
  lastAccessed?: string;
  isActive: boolean;
}

export interface SecureKeystore {
  version: string;
  createdAt: string;
  keys: SecureKeyEntry[];
  metadata: {
    encryptionVersion: string;
    totalKeys: number;
  };
}

export class SecureKeyStorage {
  private static instance: SecureKeyStorage;
  private keystorePath: string;
  private backupPath: string;

  private constructor() {
    this.keystorePath = path.join(os.homedir(), '.originvault-secure-keystore.json');
    this.backupPath = path.join(os.homedir(), '.originvault-keystore-backup.json');
  }

  public static getInstance(): SecureKeyStorage {
    if (!SecureKeyStorage.instance) {
      SecureKeyStorage.instance = new SecureKeyStorage();
    }
    return SecureKeyStorage.instance;
  }

  public async storeKey(
    keyId: string,
    did: string,
    privateKeyHex: string,
    publicKeyHex: string,
    password: string
  ): Promise<void> {
    try {
      // Encrypt the private key securely
      const encryptedPrivateKey = await encryptPrivateKeySecure(privateKeyHex, password);
      
      // Load existing keystore or create new one
      const keystore = await this.loadKeystore();
      
      // Create key entry
      const keyEntry: SecureKeyEntry = {
        keyId,
        did,
        encryptedPrivateKey,
        publicKeyHex,
        createdAt: new Date().toISOString(),
        isActive: true
      };
      
      // Add or update key
      const existingIndex = keystore.keys.findIndex(k => k.keyId === keyId);
      if (existingIndex >= 0) {
        keystore.keys[existingIndex] = keyEntry;
      } else {
        keystore.keys.push(keyEntry);
      }
      
      // Update metadata
      keystore.metadata.totalKeys = keystore.keys.length;
      
      // Create backup before writing
      await this.createBackup(keystore);
      
      // Write to file with proper permissions
      await this.writeKeystoreSecurely(keystore);
      
      console.log(`✅ Securely stored key ${keyId} for DID ${did}`);
    } catch (error) {
      console.error(`❌ Failed to store key ${keyId}:`, error);
      throw error;
    }
  }

  public async retrieveKey(keyId: string, password: string): Promise<{
    privateKeyHex: string;
    publicKeyHex: string;
  } | null> {
    try {
      const keystore = await this.loadKeystore();
      const keyEntry = keystore.keys.find(k => k.keyId === keyId && k.isActive);
      
      if (!keyEntry) {
        console.error(`❌ Key ${keyId} not found or inactive`);
        return null;
      }
      
      // Decrypt private key
      const privateKeyHex = await decryptPrivateKeySecure(keyEntry.encryptedPrivateKey, password);
      
      // Update last accessed time
      keyEntry.lastAccessed = new Date().toISOString();
      await this.writeKeystoreSecurely(keystore);
      
      return {
        privateKeyHex,
        publicKeyHex: keyEntry.publicKeyHex
      };
    } catch (error) {
      console.error(`❌ Failed to retrieve key ${keyId}:`, error);
      return null;
    }
  }

  public async listKeys(): Promise<SecureKeyEntry[]> {
    try {
      const keystore = await this.loadKeystore();
      return keystore.keys.filter(k => k.isActive);
    } catch (error) {
      console.error('❌ Failed to list keys:', error);
      return [];
    }
  }

  public async deleteKey(keyId: string): Promise<boolean> {
    try {
      const keystore = await this.loadKeystore();
      const keyIndex = keystore.keys.findIndex(k => k.keyId === keyId);
      
      if (keyIndex >= 0) {
        // Mark as inactive instead of deleting (for audit trail)
        keystore.keys[keyIndex].isActive = false;
        keystore.metadata.totalKeys = keystore.keys.filter(k => k.isActive).length;
        
        await this.writeKeystoreSecurely(keystore);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error(`❌ Failed to delete key ${keyId}:`, error);
      return false;
    }
  }

  private async loadKeystore(): Promise<SecureKeystore> {
    try {
      if (fs.existsSync(this.keystorePath)) {
        const data = fs.readFileSync(this.keystorePath, 'utf8');
        return JSON.parse(data);
      } else {
        // Create new keystore
        return {
          version: '1.0.0',
          createdAt: new Date().toISOString(),
          keys: [],
          metadata: {
            encryptionVersion: '1.0.0',
            totalKeys: 0
          }
        };
      }
    } catch (error) {
      console.error('❌ Failed to load keystore:', error);
      throw new Error('Failed to load secure keystore');
    }
  }

  private async writeKeystoreSecurely(keystore: SecureKeystore): Promise<void> {
    try {
      // Write to temporary file first
      const tempPath = this.keystorePath + '.tmp';
      fs.writeFileSync(tempPath, JSON.stringify(keystore, null, 2), {
        mode: 0o600 // Read/write for owner only
      });
      
      // Atomic move to final location
      fs.renameSync(tempPath, this.keystorePath);
      
      // Set secure permissions
      fs.chmodSync(this.keystorePath, 0o600);
    } catch (error) {
      console.error('❌ Failed to write keystore securely:', error);
      throw error;
    }
  }

  private async createBackup(keystore: SecureKeystore): Promise<void> {
    try {
      if (fs.existsSync(this.keystorePath)) {
        fs.copyFileSync(this.keystorePath, this.backupPath);
        fs.chmodSync(this.backupPath, 0o600);
      }
    } catch (error) {
      console.warn('⚠️  Failed to create keystore backup:', error);
    }
  }
}
```

**Tasks**:
- [ ] Create secure key storage service
- [ ] Replace plaintext storage with encrypted storage
- [ ] Add proper file permissions
- [ ] Implement backup mechanism
- [ ] Add atomic write operations
- [ ] Test key storage operations

**Priority**: CRITICAL - Must be fixed immediately
**Estimated Time**: 2 days

## Phase 2: Envelope Encryption Implementation (Weeks 2-3)

### 2.1 Envelope Encryption Service

**File**: `src/security/envelope-encryption.service.ts` (New)

**Objectives**:
- Implement DEK/KEK encryption pattern
- Replace single master key architecture
- Enable secure key rotation
- Add memory protection

**Implementation**:
```typescript
import crypto from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(crypto.scrypt);

export interface EnvelopeEncryptionResult {
  encryptedData: string;
  encryptedDEK: string;
  keyId: string;
  iv: string;
  salt: string;
  authTag: string;
  algorithm: string;
  version: number;
}

export interface KeyMetadata {
  keyId: string;
  algorithm: string;
  createdAt: Date;
  expiresAt?: Date;
  version: number;
  isActive: boolean;
  rotationCount: number;
}

export class EnvelopeEncryptionService {
  private static instance: EnvelopeEncryptionService;
  private currentDEK: Buffer;
  private currentKeyId: string;
  private keyMetadata: Map<string, KeyMetadata> = new Map();
  private masterKey: Buffer;

  private constructor() {
    this.initializeMasterKey();
    this.initializeDEK();
  }

  public static getInstance(): EnvelopeEncryptionService {
    if (!EnvelopeEncryptionService.instance) {
      EnvelopeEncryptionService.instance = new EnvelopeEncryptionService();
    }
    return EnvelopeEncryptionService.instance;
  }

  private initializeMasterKey(): void {
    // Get master key from environment or generate secure one
    const masterKeyHex = process.env.OV_MASTER_ENCRYPTION_KEY;
    if (!masterKeyHex) {
      // Generate and warn about missing configuration
      console.warn('⚠️  OV_MASTER_ENCRYPTION_KEY not set, generating temporary key');
      console.warn('⚠️  This key will not persist across restarts');
      this.masterKey = crypto.randomBytes(32);
    } else {
      this.masterKey = Buffer.from(masterKeyHex, 'hex');
    }
  }

  private async initializeDEK(): Promise<void> {
    // Generate cryptographically secure DEK
    this.currentDEK = crypto.randomBytes(32);
    this.currentKeyId = `dek_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    
    // Store metadata
    this.keyMetadata.set(this.currentKeyId, {
      keyId: this.currentKeyId,
      algorithm: 'AES-256-GCM',
      createdAt: new Date(),
      version: 1,
      isActive: true,
      rotationCount: 0
    });

    console.log(`🔑 Initialized new DEK: ${this.currentKeyId}`);
  }

  public async encrypt(data: string): Promise<EnvelopeEncryptionResult> {
    try {
      // Generate random IV and salt for this encryption operation
      const iv = crypto.randomBytes(16);
      const salt = crypto.randomBytes(32);
      
      // Create cipher with current DEK
      const cipher = crypto.createCipheriv('aes-256-gcm', this.currentDEK, iv);
      
      // Add additional authenticated data (AAD)
      const aad = Buffer.from(this.currentKeyId, 'utf8');
      cipher.setAAD(aad);
      
      // Encrypt the data
      let encryptedData = cipher.update(data, 'utf8', 'hex');
      encryptedData += cipher.final('hex');
      
      // Get authentication tag
      const authTag = cipher.getAuthTag();
      
      // Encrypt DEK with KEK (master key)
      const encryptedDEK = await this.encryptDEK(this.currentDEK, salt);
      
      return {
        encryptedData,
        encryptedDEK,
        keyId: this.currentKeyId,
        iv: iv.toString('hex'),
        salt: salt.toString('hex'),
        authTag: authTag.toString('hex'),
        algorithm: 'AES-256-GCM',
        version: 1
      };
    } catch (error) {
      throw new Error(`Envelope encryption failed: ${error.message}`);
    }
  }

  public async decrypt(encryptionResult: EnvelopeEncryptionResult): Promise<string> {
    try {
      // Decrypt DEK with KEK
      const dek = await this.decryptDEK(
        encryptionResult.encryptedDEK, 
        Buffer.from(encryptionResult.salt, 'hex')
      );
      
      // Prepare for decryption
      const iv = Buffer.from(encryptionResult.iv, 'hex');
      const authTag = Buffer.from(encryptionResult.authTag, 'hex');
      
      // Create decipher
      const decipher = crypto.createDecipheriv('aes-256-gcm', dek, iv);
      decipher.setAuthTag(authTag);
      
      // Set additional authenticated data
      const aad = Buffer.from(encryptionResult.keyId, 'utf8');
      decipher.setAAD(aad);
      
      // Decrypt the data
      let decryptedData = decipher.update(encryptionResult.encryptedData, 'hex', 'utf8');
      decryptedData += decipher.final('utf8');
      
      // Zero out DEK from memory
      dek.fill(0);
      
      return decryptedData;
    } catch (error) {
      throw new Error(`Envelope decryption failed: ${error.message}`);
    }
  }

  private async encryptDEK(dek: Buffer, salt: Buffer): Promise<string> {
    // Derive KEK from master key using the salt
    const kek = await scryptAsync(this.masterKey, salt, 32) as Buffer;
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
    
    let encrypted = cipher.update(dek, undefined, 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Zero out KEK from memory
    kek.fill(0);
    
    // Return combined encrypted DEK with metadata
    return JSON.stringify({
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    });
  }

  private async decryptDEK(encryptedDEK: string, salt: Buffer): Promise<Buffer> {
    const dekData = JSON.parse(encryptedDEK);
    
    // Derive KEK from master key using the salt
    const kek = await scryptAsync(this.masterKey, salt, 32) as Buffer;
    
    const iv = Buffer.from(dekData.iv, 'hex');
    const authTag = Buffer.from(dekData.authTag, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(dekData.encrypted, 'hex');
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    // Zero out KEK from memory
    kek.fill(0);
    
    return decrypted;
  }

  public async rotateKeys(): Promise<string> {
    const oldKeyId = this.currentKeyId;
    
    // Mark old key as inactive
    const oldMetadata = this.keyMetadata.get(oldKeyId);
    if (oldMetadata) {
      oldMetadata.isActive = false;
      oldMetadata.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    }
    
    // Generate new DEK
    await this.initializeDEK();
    
    console.log(`🔄 Rotated encryption keys: ${oldKeyId} → ${this.currentKeyId}`);
    
    return oldKeyId;
  }

  public getCurrentKeyId(): string {
    return this.currentKeyId;
  }

  public getKeyMetadata(keyId: string): KeyMetadata | undefined {
    return this.keyMetadata.get(keyId);
  }

  public async zeroizeMemory(): Promise<void> {
    // Zero out sensitive memory
    this.currentDEK.fill(0);
    this.masterKey.fill(0);
    
    console.log('🧹 Zeroized sensitive memory');
  }
}
```

**Tasks**:
- [ ] Create envelope encryption service
- [ ] Implement DEK/KEK pattern
- [ ] Add secure key derivation
- [ ] Implement memory protection
- [ ] Add key rotation capability
- [ ] Create comprehensive tests

**Priority**: CRITICAL
**Estimated Time**: 3 days

## Phase 3: DIDComm Security Enhancement (Weeks 4-5)

### 3.1 Secure DIDComm Client

**File**: `src/didcomm/secure-didcomm-client.ts` (New)

**Objectives**:
- Replace vulnerable message signing
- Add proper signature verification
- Implement secure message encryption
- Add replay attack protection

**Implementation**:
```typescript
import { IOVAgent } from '@originvault/ov-types';
import { EnvelopeEncryptionService } from '../security/envelope-encryption.service.js';
import { SecureKeyStorage } from '../security/secure-key-storage.js';
import * as ed25519 from '@noble/ed25519';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

export interface SecureSignedMessage {
  message: string;
  signature: string;
  signer: string;
  timestamp: string;
  messageId: string;
  nonce: string;
  keyId: string;
  algorithm: string;
  version: number;
}

export interface SecureDIDCommMessage {
  id: string;
  type: string;
  from: string;
  to: string;
  body: any;
  signature: SecureSignedMessage;
  encrypted?: boolean;
  timestamp: string;
}

export class SecureDIDCommClient {
  private agent: IOVAgent;
  private envelopeService: EnvelopeEncryptionService;
  private keyStorage: SecureKeyStorage;
  private nonceStore: Set<string> = new Set(); // For replay attack prevention

  constructor(agent: IOVAgent) {
    this.agent = agent;
    this.envelopeService = EnvelopeEncryptionService.getInstance();
    this.keyStorage = SecureKeyStorage.getInstance();
  }

  public async sendSecureMessage(
    recipient: string,
    messageType: string,
    content: any,
    signerDID: string,
    password: string,
    encrypt: boolean = true
  ): Promise<SecureDIDCommMessage> {
    try {
      console.log(`📤 Sending secure message from ${signerDID} to ${recipient}`);
      
      // Create base DIDComm message
      const messageId = uuidv4();
      const timestamp = new Date().toISOString();
      const nonce = crypto.randomBytes(16).toString('hex');
      
      let messageBody = content;
      
      // Encrypt message content if requested
      if (encrypt) {
        const encryptedResult = await this.envelopeService.encrypt(JSON.stringify(content));
        messageBody = {
          encrypted: true,
          data: encryptedResult
        };
      }
      
      const didcommMessage = {
        id: messageId,
        type: messageType,
        from: signerDID,
        to: recipient,
        body: messageBody,
        timestamp
      };
      
      // Create signature payload
      const signaturePayload = JSON.stringify({
        messageId,
        type: messageType,
        from: signerDID,
        to: recipient,
        body: messageBody,
        timestamp,
        nonce
      });
      
      // Sign the message
      const signature = await this.signMessageSecurely(signaturePayload, signerDID, password);
      
      const secureMessage: SecureDIDCommMessage = {
        ...didcommMessage,
        signature: {
          ...signature,
          nonce
        },
        encrypted: encrypt
      };
      
      console.log(`✅ Secure message created with ID: ${messageId}`);
      return secureMessage;
      
    } catch (error) {
      console.error('❌ Failed to send secure message:', error);
      throw error;
    }
  }

  public async verifySecureMessage(message: SecureDIDCommMessage): Promise<boolean> {
    try {
      console.log(`🔍 Verifying secure message from ${message.from}`);
      
      // Check for replay attacks
      if (this.nonceStore.has(message.signature.nonce)) {
        console.error('❌ Replay attack detected: nonce already used');
        return false;
      }
      
      // Check message age (prevent old message replay)
      const messageAge = Date.now() - new Date(message.timestamp).getTime();
      if (messageAge > 5 * 60 * 1000) { // 5 minutes
        console.error('❌ Message too old, potential replay attack');
        return false;
      }
      
      // Verify signature
      const isValidSignature = await this.verifyMessageSignature(message.signature);
      if (!isValidSignature) {
        console.error('❌ Invalid message signature');
        return false;
      }
      
      // Add nonce to store (with cleanup after 10 minutes)
      this.nonceStore.add(message.signature.nonce);
      setTimeout(() => {
        this.nonceStore.delete(message.signature.nonce);
      }, 10 * 60 * 1000);
      
      console.log(`✅ Secure message verification PASSED for ${message.from}`);
      return true;
      
    } catch (error) {
      console.error('❌ Error verifying secure message:', error);
      return false;
    }
  }

  private async signMessageSecurely(
    payload: string,
    signerDID: string,
    password: string
  ): Promise<SecureSignedMessage> {
    try {
      // Get the DID identifier
      const identifier = await this.agent.didManagerGet({ did: signerDID });
      if (!identifier || !identifier.keys || identifier.keys.length === 0) {
        throw new Error(`No keys found for DID: ${signerDID}`);
      }

      const keyRef = identifier.keys[0].kid;
      
      // Retrieve private key securely
      const keyData = await this.keyStorage.retrieveKey(keyRef, password);
      if (!keyData) {
        throw new Error(`Failed to retrieve private key for ${keyRef}`);
      }

      // Convert to bytes for signing
      const payloadBytes = Buffer.from(payload, 'utf8');
      const privateKeyBytes = Buffer.from(keyData.privateKeyHex, 'hex');
      
      // Sign with Ed25519
      const signature = await ed25519.sign(payloadBytes, privateKeyBytes);
      
      // Zero out private key from memory
      privateKeyBytes.fill(0);
      
      return {
        message: payload,
        signature: Buffer.from(signature).toString('base64'),
        signer: signerDID,
        timestamp: new Date().toISOString(),
        messageId: uuidv4(),
        nonce: crypto.randomBytes(16).toString('hex'),
        keyId: keyRef,
        algorithm: 'Ed25519',
        version: 1
      };
    } catch (error) {
      throw new Error(`Secure message signing failed: ${error.message}`);
    }
  }

  private async verifyMessageSignature(signedMessage: SecureSignedMessage): Promise<boolean> {
    try {
      // Get the DID identifier
      const identifier = await this.agent.didManagerGet({ did: signedMessage.signer });
      if (!identifier || !identifier.keys || identifier.keys.length === 0) {
        console.error(`No keys found for DID: ${signedMessage.signer}`);
        return false;
      }

      // Get public key
      const key = identifier.keys.find(k => k.kid === signedMessage.keyId) || identifier.keys[0];
      const publicKeyBytes = Buffer.from(key.publicKeyHex, 'hex');
      
      // Verify signature
      const signatureBytes = Buffer.from(signedMessage.signature, 'base64');
      const messageBytes = Buffer.from(signedMessage.message, 'utf8');
      
      const isValid = await ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
      
      return isValid;
    } catch (error) {
      console.error('❌ Error verifying message signature:', error);
      return false;
    }
  }

  public async decryptMessageContent(message: SecureDIDCommMessage): Promise<any> {
    if (!message.encrypted || !message.body.encrypted) {
      return message.body;
    }
    
    try {
      const decryptedContent = await this.envelopeService.decrypt(message.body.data);
      return JSON.parse(decryptedContent);
    } catch (error) {
      throw new Error(`Failed to decrypt message content: ${error.message}`);
    }
  }
}
```

**Tasks**:
- [ ] Create secure DIDComm client
- [ ] Implement proper signature verification
- [ ] Add replay attack protection
- [ ] Implement secure message encryption
- [ ] Add message validation
- [ ] Create comprehensive tests

**Estimated Time**: 5 days

## Phase 4: Integration with Cheqd Studio (Weeks 6-7)

### 4.1 Shared Security Library

**File**: `src/shared/security-bridge.service.ts` (New)

**Objectives**:
- Create interface for cheqd-studio integration
- Share encryption capabilities
- Coordinate key operations
- Enable cross-repo security

**Implementation**:
```typescript
import { EnvelopeEncryptionService } from '../security/envelope-encryption.service.js';
import { SecureKeyStorage } from '../security/secure-key-storage.js';

export interface SecurityBridgeConfig {
  cheqdStudioEndpoint?: string;
  sharedSecretKey?: string;
  enableCrossRepoSync?: boolean;
}

export interface KeySyncRequest {
  operation: 'create' | 'update' | 'rotate' | 'delete';
  keyId: string;
  did: string;
  customerId: string;
  metadata: any;
}

export class SecurityBridgeService {
  private static instance: SecurityBridgeService;
  private config: SecurityBridgeConfig;
  private envelopeService: EnvelopeEncryptionService;
  private keyStorage: SecureKeyStorage;

  private constructor(config: SecurityBridgeConfig) {
    this.config = config;
    this.envelopeService = EnvelopeEncryptionService.getInstance();
    this.keyStorage = SecureKeyStorage.getInstance();
  }

  public static getInstance(config?: SecurityBridgeConfig): SecurityBridgeService {
    if (!SecurityBridgeService.instance && config) {
      SecurityBridgeService.instance = new SecurityBridgeService(config);
    }
    return SecurityBridgeService.instance;
  }

  // Shared encryption methods for cheqd-studio
  public async encryptForCheqdStudio(data: string): Promise<any> {
    return await this.envelopeService.encrypt(data);
  }

  public async decryptFromCheqdStudio(encryptionResult: any): Promise<string> {
    return await this.envelopeService.decrypt(encryptionResult);
  }

  // Key synchronization with cheqd-studio
  public async syncKeyWithCheqdStudio(request: KeySyncRequest): Promise<void> {
    if (!this.config.enableCrossRepoSync) {
      return;
    }

    try {
      // Send key operation to cheqd-studio
      const response = await fetch(`${this.config.cheqdStudioEndpoint}/api/key-sync`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-OV-SDK-Secret': this.config.sharedSecretKey || ''
        },
        body: JSON.stringify(request)
      });

      if (!response.ok) {
        throw new Error(`Key sync failed: ${response.statusText}`);
      }

      console.log(`✅ Synced key operation with cheqd-studio: ${request.operation} ${request.keyId}`);
    } catch (error) {
      console.error(`❌ Failed to sync key with cheqd-studio:`, error);
      // Don't throw - this is a sync operation that shouldn't break the main flow
    }
  }

  // Coordinate key rotation across repositories
  public async coordinateKeyRotation(did: string, customerId: string): Promise<void> {
    try {
      // Notify cheqd-studio about pending key rotation
      const rotationPlan = {
        did,
        customerId,
        timestamp: new Date().toISOString(),
        source: 'ov-id-sdk'
      };

      await fetch(`${this.config.cheqdStudioEndpoint}/api/key-rotation/coordinate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-OV-SDK-Secret': this.config.sharedSecretKey || ''
        },
        body: JSON.stringify(rotationPlan)
      });

      console.log(`✅ Coordinated key rotation with cheqd-studio for DID: ${did}`);
    } catch (error) {
      console.error(`❌ Failed to coordinate key rotation:`, error);
    }
  }
}
```

**Tasks**:
- [ ] Create security bridge service
- [ ] Implement shared encryption methods
- [ ] Add key synchronization
- [ ] Create coordination protocols
- [ ] Add error handling
- [ ] Test integration scenarios

**Estimated Time**: 4 days

## Phase 5: Key Rotation & Lifecycle Management (Weeks 8-9)

### 5.1 Key Rotation Service

**File**: `src/security/key-rotation.service.ts` (New)

**Objectives**:
- Implement automated key rotation
- Add rotation scheduling
- Enable emergency rotation
- Coordinate with cheqd-studio

**Implementation**:
```typescript
import { EnvelopeEncryptionService } from './envelope-encryption.service.js';
import { SecurityBridgeService } from '../shared/security-bridge.service.js';
import { SecureKeyStorage } from './secure-key-storage.js';

export interface KeyRotationPlan {
  rotationId: string;
  did: string;
  keyIds: string[];
  rotationType: 'scheduled' | 'emergency' | 'manual';
  estimatedDuration: number;
  coordinateWithCheqd: boolean;
}

export interface KeyRotationResult {
  rotationId: string;
  success: boolean;
  rotatedKeys: string[];
  failedKeys: string[];
  errors: string[];
  duration: number;
  cheqdStudioSynced: boolean;
}

export class KeyRotationService {
  private static instance: KeyRotationService;
  private envelopeService: EnvelopeEncryptionService;
  private keyStorage: SecureKeyStorage;
  private securityBridge: SecurityBridgeService;

  private constructor() {
    this.envelopeService = EnvelopeEncryptionService.getInstance();
    this.keyStorage = SecureKeyStorage.getInstance();
    this.securityBridge = SecurityBridgeService.getInstance();
  }

  public static getInstance(): KeyRotationService {
    if (!KeyRotationService.instance) {
      KeyRotationService.instance = new KeyRotationService();
    }
    return KeyRotationService.instance;
  }

  public async createRotationPlan(did: string): Promise<KeyRotationPlan> {
    try {
      // Get all keys associated with the DID
      const keys = await this.keyStorage.listKeys();
      const didKeys = keys.filter(k => k.did === did);
      
      return {
        rotationId: uuidv4(),
        did,
        keyIds: didKeys.map(k => k.keyId),
        rotationType: 'manual',
        estimatedDuration: didKeys.length * 30, // 30 seconds per key
        coordinateWithCheqd: true
      };
    } catch (error) {
      throw new Error(`Failed to create rotation plan: ${error.message}`);
    }
  }

  public async executeKeyRotation(plan: KeyRotationPlan, password: string): Promise<KeyRotationResult> {
    const startTime = Date.now();
    const result: KeyRotationResult = {
      rotationId: plan.rotationId,
      success: false,
      rotatedKeys: [],
      failedKeys: [],
      errors: [],
      duration: 0,
      cheqdStudioSynced: false
    };

    try {
      console.log(`🔄 Starting key rotation for DID: ${plan.did}`);
      
      // Step 1: Rotate envelope encryption keys
      const oldEnvelopeKeyId = await this.envelopeService.rotateKeys();
      result.rotatedKeys.push(oldEnvelopeKeyId);
      
      // Step 2: Re-encrypt all keys with new envelope key
      for (const keyId of plan.keyIds) {
        try {
          await this.rotateIndividualKey(keyId, password);
          result.rotatedKeys.push(keyId);
        } catch (error) {
          result.failedKeys.push(keyId);
          result.errors.push(`Failed to rotate key ${keyId}: ${error.message}`);
        }
      }
      
      // Step 3: Coordinate with cheqd-studio if enabled
      if (plan.coordinateWithCheqd) {
        try {
          await this.securityBridge.coordinateKeyRotation(plan.did, 'unknown');
          result.cheqdStudioSynced = true;
        } catch (error) {
          result.errors.push(`Failed to sync with cheqd-studio: ${error.message}`);
        }
      }
      
      result.success = result.failedKeys.length === 0;
      result.duration = Date.now() - startTime;
      
      console.log(`${result.success ? '✅' : '❌'} Key rotation completed for DID: ${plan.did}`);
      console.log(`   Rotated: ${result.rotatedKeys.length}, Failed: ${result.failedKeys.length}`);
      console.log(`   Duration: ${result.duration}ms`);
      
      return result;
    } catch (error) {
      result.errors.push(`Key rotation failed: ${error.message}`);
      result.duration = Date.now() - startTime;
      return result;
    }
  }

  private async rotateIndividualKey(keyId: string, password: string): Promise<void> {
    // Retrieve current key
    const keyData = await this.keyStorage.retrieveKey(keyId, password);
    if (!keyData) {
      throw new Error(`Key ${keyId} not found`);
    }
    
    // Re-encrypt with new envelope key
    const keys = await this.keyStorage.listKeys();
    const keyEntry = keys.find(k => k.keyId === keyId);
    if (!keyEntry) {
      throw new Error(`Key entry ${keyId} not found`);
    }
    
    // Store with new encryption
    await this.keyStorage.storeKey(
      keyId,
      keyEntry.did,
      keyData.privateKeyHex,
      keyData.publicKeyHex,
      password
    );
    
    console.log(`🔄 Rotated key: ${keyId}`);
  }

  public async scheduleRotation(schedule: string, did: string): Promise<void> {
    // Implementation for scheduled key rotation
    // This would integrate with a cron-like scheduler
    console.log(`📅 Scheduled key rotation for DID ${did}: ${schedule}`);
  }

  public async emergencyRotation(did: string, password: string): Promise<KeyRotationResult> {
    console.log(`🚨 Emergency key rotation initiated for DID: ${did}`);
    
    const plan = await this.createRotationPlan(did);
    plan.rotationType = 'emergency';
    plan.coordinateWithCheqd = true;
    
    return await this.executeKeyRotation(plan, password);
  }
}
```

**Tasks**:
- [ ] Create key rotation service
- [ ] Implement rotation planning
- [ ] Add rotation execution
- [ ] Create emergency rotation
- [ ] Add scheduling capability
- [ ] Test rotation scenarios

**Estimated Time**: 4 days

## Phase 6: Security Hardening (Weeks 10-11)

### 6.1 Memory Protection Service

**File**: `src/security/memory-protection.service.ts` (New)

**Objectives**:
- Implement secure memory handling
- Add automatic memory cleanup
- Prevent memory dumps
- Add memory monitoring

**Implementation**:
```typescript
export class MemoryProtectionService {
  private static instance: MemoryProtectionService;
  private sensitiveBuffers: Set<Buffer> = new Set();
  private cleanupInterval: NodeJS.Timeout;

  private constructor() {
    // Set up automatic cleanup every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.performCleanup();
    }, 5 * 60 * 1000);
  }

  public static getInstance(): MemoryProtectionService {
    if (!MemoryProtectionService.instance) {
      MemoryProtectionService.instance = new MemoryProtectionService();
    }
    return MemoryProtectionService.instance;
  }

  public registerSensitiveBuffer(buffer: Buffer): void {
    this.sensitiveBuffers.add(buffer);
  }

  public zeroizeBuffer(buffer: Buffer): void {
    buffer.fill(0);
    this.sensitiveBuffers.delete(buffer);
  }

  public performCleanup(): void {
    let cleanedCount = 0;
    for (const buffer of this.sensitiveBuffers) {
      buffer.fill(0);
      cleanedCount++;
    }
    this.sensitiveBuffers.clear();
    
    if (cleanedCount > 0) {
      console.log(`🧹 Cleaned ${cleanedCount} sensitive buffers from memory`);
    }
  }

  public shutdown(): void {
    clearInterval(this.cleanupInterval);
    this.performCleanup();
  }
}
```

**Tasks**:
- [ ] Create memory protection service
- [ ] Implement buffer tracking
- [ ] Add automatic cleanup
- [ ] Create monitoring
- [ ] Test memory protection
- [ ] Add performance monitoring

**Estimated Time**: 2 days

### 6.2 Security Validation Service

**File**: `src/security/security-validation.service.ts` (New)

**Objectives**:
- Validate security configuration
- Check encryption integrity
- Verify key consistency
- Monitor security health

**Implementation**:
```typescript
export interface SecurityValidationResult {
  isValid: boolean;
  issues: SecurityIssue[];
  recommendations: string[];
  score: number; // 0-100
}

export interface SecurityIssue {
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  remediation: string;
}

export class SecurityValidationService {
  public async validateSecurityState(): Promise<SecurityValidationResult>
  public async validateKeyIntegrity(): Promise<ValidationResult>
  public async validateEncryptionConfig(): Promise<ValidationResult>
  public async generateSecurityReport(): Promise<SecurityReport>
}
```

**Tasks**:
- [ ] Create security validation service
- [ ] Implement configuration validation
- [ ] Add integrity checks
- [ ] Create security scoring
- [ ] Add report generation
- [ ] Test validation scenarios

**Estimated Time**: 3 days

## Phase 7: Testing & Quality Assurance (Weeks 12-13)

### 7.1 Comprehensive Security Testing

**Test Categories**:
1. **Unit Tests** - All security services
2. **Integration Tests** - Cross-service functionality
3. **Security Tests** - Penetration testing
4. **Performance Tests** - Encryption overhead
5. **Compatibility Tests** - Backward compatibility

**Files**:
- `src/__tests__/security/envelope-encryption.test.ts`
- `src/__tests__/security/key-rotation.test.ts`
- `src/__tests__/security/didcomm-security.test.ts`
- `src/__tests__/integration/cheqd-studio-integration.test.ts`
- `src/__tests__/performance/encryption-performance.test.ts`

**Test Scenarios**:
```typescript
describe('Security Test Suite', () => {
  describe('Envelope Encryption', () => {
    test('should encrypt and decrypt data correctly');
    test('should handle key rotation without data loss');
    test('should protect against tampering');
    test('should zeroize memory after operations');
  });

  describe('Message Signing', () => {
    test('should sign messages with Ed25519');
    test('should verify signatures correctly');
    test('should reject invalid signatures');
    test('should prevent replay attacks');
  });

  describe('Key Management', () => {
    test('should store keys securely');
    test('should retrieve keys correctly');
    test('should rotate keys successfully');
    test('should handle key deletion');
  });

  describe('Integration', () => {
    test('should sync with cheqd-studio');
    test('should coordinate key operations');
    test('should handle communication failures');
  });
});
```

**Tasks**:
- [ ] Create comprehensive test suite
- [ ] Implement security-specific tests
- [ ] Add performance benchmarks
- [ ] Create integration tests
- [ ] Add compatibility tests
- [ ] Run security audits

**Estimated Time**: 6 days

### 7.2 Migration Testing

**File**: `src/__tests__/migration/security-migration.test.ts`

**Objectives**:
- Test migration from current vulnerable implementation
- Validate data integrity during migration
- Test rollback procedures
- Verify performance impact

**Tasks**:
- [ ] Create migration test suite
- [ ] Test data migration accuracy
- [ ] Validate rollback procedures
- [ ] Test performance impact
- [ ] Verify API compatibility
- [ ] Test error scenarios

**Estimated Time**: 3 days

## Phase 8: Documentation & Release (Weeks 14-15)

### 8.1 Security Documentation

**Files**:
- `docs/SECURITY-ARCHITECTURE.md`
- `docs/MIGRATION-GUIDE.md`
- `docs/API-SECURITY.md`
- `docs/INTEGRATION-GUIDE.md`

**Content**:
- Security architecture overview
- Migration from vulnerable implementation
- API security guidelines
- Integration with cheqd-studio
- Best practices and recommendations

**Tasks**:
- [ ] Create security architecture documentation
- [ ] Write migration guide
- [ ] Document API security
- [ ] Create integration guide
- [ ] Add troubleshooting guide
- [ ] Create security checklist

**Estimated Time**: 4 days

### 8.2 Release Preparation

**Objectives**:
- Prepare secure release package
- Update version numbers
- Create release notes
- Prepare deployment guides

**Tasks**:
- [ ] Update package.json version
- [ ] Create release notes
- [ ] Package secure distribution
- [ ] Create deployment guides
- [ ] Test release package
- [ ] Prepare rollback package

**Estimated Time**: 2 days

## Environment Configuration

### New Required Variables
```bash
# Master encryption key for envelope encryption
OV_MASTER_ENCRYPTION_KEY=your-32-byte-hex-key-here

# Security configuration
OV_ENABLE_ENVELOPE_ENCRYPTION=true
OV_ENABLE_MEMORY_PROTECTION=true
OV_KEY_ROTATION_ENABLED=true

# Integration with cheqd-studio
OV_CHEQD_STUDIO_ENDPOINT=https://your-cheqd-studio.com
OV_CHEQD_STUDIO_SECRET=your-shared-secret
OV_ENABLE_CROSS_REPO_SYNC=true

# Security monitoring
OV_ENABLE_SECURITY_MONITORING=true
OV_SECURITY_LOG_LEVEL=info
```

### Deprecated Variables
```bash
# These should be removed after migration
ENCRYPTION_KEY  # Replaced by OV_MASTER_ENCRYPTION_KEY
```

## Breaking Changes

### API Changes
1. **Message Signing API**
   - Old: `signMessage(agent, message, options)`
   - New: `secureClient.sendSecureMessage(recipient, type, content, signer, password)`

2. **Key Storage API**
   - Old: `storePrivateKey(keyName, privateKey, kid)`
   - New: `keyStorage.storeKey(keyId, did, privateKeyHex, publicKeyHex, password)`

3. **Encryption API**
   - Old: `encryptPrivateKey(privateKey, password)`
   - New: `envelopeService.encrypt(data)` with proper result structure

### Migration Path
1. **Phase 1**: Add new APIs alongside old ones
2. **Phase 2**: Migrate data to new format
3. **Phase 3**: Deprecate old APIs
4. **Phase 4**: Remove old APIs in next major version

## Success Metrics

### Security Improvements
- [ ] All critical vulnerabilities fixed
- [ ] Envelope encryption implemented
- [ ] Secure key storage implemented
- [ ] Proper signature verification
- [ ] Memory protection active

### Performance Targets
- [ ] <20ms additional latency for security operations
- [ ] <10% CPU overhead for security features
- [ ] <5MB additional memory usage
- [ ] 99.9% uptime during operations

### Integration Success
- [ ] Successful integration with cheqd-studio
- [ ] Shared security capabilities working
- [ ] Cross-repo key coordination functional
- [ ] Security state synchronization active

## Risk Assessment

### High Priority Risks
1. **Breaking Existing Integrations**
   - Mitigation: Backward compatibility layer
   - Testing: Comprehensive integration testing
   - Recovery: Rollback to previous version

2. **Performance Impact**
   - Mitigation: Performance optimization
   - Testing: Load testing with new security
   - Monitoring: Real-time performance metrics

3. **Data Migration Issues**
   - Mitigation: Comprehensive backup strategy
   - Testing: Migration testing with real data
   - Recovery: Automated rollback procedures

### Medium Priority Risks
1. **Integration Complexity**
   - Mitigation: Phased integration approach
   - Testing: Step-by-step integration testing
   - Recovery: Independent operation fallback

2. **User Experience Impact**
   - Mitigation: Seamless migration process
   - Testing: User experience testing
   - Recovery: Quick rollback capability

## Dependencies

### New Dependencies
```json
{
  "@noble/ed25519": "^2.2.3",
  "@noble/hashes": "^1.7.1",
  "libsodium-wrappers": "^0.7.13"
}
```

### Updated Dependencies
- Ensure all crypto dependencies are up to date
- Remove any deprecated encryption libraries
- Add security-focused utilities

## Post-Release Monitoring

### Security Metrics
- Encryption/decryption success rates
- Signature verification success rates
- Key rotation success rates
- Memory protection effectiveness

### Performance Metrics
- Encryption operation latency
- Memory usage patterns
- CPU overhead from security operations
- Key storage operation performance

### Integration Metrics
- Cheqd-studio sync success rate
- Cross-repo operation success rate
- Communication failure rates
- Data consistency validation

## Maintenance Schedule

### Daily
- Monitor security logs
- Check for failed operations
- Verify system health

### Weekly
- Review security metrics
- Check for performance issues
- Validate key integrity

### Monthly
- Security audit review
- Performance optimization
- Update security documentation

### Quarterly
- Comprehensive security assessment
- Penetration testing
- Architecture review

This development plan addresses all critical security vulnerabilities in ov-id-sdk while creating a foundation for secure integration with cheqd-studio. The implementation prioritizes immediate security fixes while building toward enterprise-grade security capabilities.
