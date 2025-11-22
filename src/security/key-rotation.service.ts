import { EnvelopeEncryptionService } from './envelope-encryption.service.js';
import { SecurityBridgeService } from '../shared/security-bridge.service.js';
import { SecureKeyStorage } from './secure-key-storage.js';
import { v4 as uuidv4 } from 'uuid';

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
      throw new Error(`Failed to create rotation plan: ${error instanceof Error ? error.message : String(error)}`);
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
          result.errors.push(`Failed to rotate key ${keyId}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      
      // Step 3: Coordinate with cheqd-studio if enabled
      if (plan.coordinateWithCheqd) {
        try {
          await this.securityBridge.coordinateKeyRotation(plan.did, 'unknown');
          result.cheqdStudioSynced = true;
        } catch (error) {
          result.errors.push(`Failed to sync with cheqd-studio: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      
      result.success = result.failedKeys.length === 0;
      result.duration = Date.now() - startTime;
      
      console.log(`${result.success ? '✅' : '❌'} Key rotation completed for DID: ${plan.did}`);
      console.log(`   Rotated: ${result.rotatedKeys.length}, Failed: ${result.failedKeys.length}`);
      console.log(`   Duration: ${result.duration}ms`);
      
      return result;
    } catch (error) {
      result.errors.push(`Key rotation failed: ${error instanceof Error ? error.message : String(error)}`);
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