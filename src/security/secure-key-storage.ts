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