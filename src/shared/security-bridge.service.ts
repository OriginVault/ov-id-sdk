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