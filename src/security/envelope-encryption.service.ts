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
  private currentDEK!: Buffer;
  private currentKeyId!: string;
  private keyMetadata: Map<string, KeyMetadata> = new Map();
  private masterKey!: Buffer;

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
      throw new Error(`Envelope encryption failed: ${error instanceof Error ? error.message : String(error)}`);
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
      throw new Error(`Envelope decryption failed: ${error instanceof Error ? error.message : String(error)}`);
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