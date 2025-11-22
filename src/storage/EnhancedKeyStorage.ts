import { KeyEncryptionService, EncryptedKeyData } from '../encryption.js';
import { storePrivateKey, retrievePrivateKey } from '../storePrivateKeys.js';
import { KeyEntity } from './entities/KeyEntity.js';
import { Repository } from 'typeorm';

export interface StoredKey {
  keyId: string;
  algorithm: string;
  keyType: 'signing' | 'encryption' | 'quantum';
  publicKeyHex: string;
  encryptedPrivateKey: EncryptedKeyData;
  metadata?: any;
}

export class EnhancedKeyStorage {
  private keyEncryptionService: KeyEncryptionService;
  private keyRepository: Repository<KeyEntity>;

  constructor(encryptionKey: string, keyRepository: Repository<KeyEntity>) {
    this.keyEncryptionService = new KeyEncryptionService(encryptionKey);
    this.keyRepository = keyRepository;
  }

  /**
   * Encrypt a private key
   */
  async encryptKey(privateKey: string): Promise<EncryptedKeyData> {
    return await this.keyEncryptionService.encryptKey(privateKey);
  }

  /**
   * Store a key with encryption
   */
  async storeKey(did: string, key: StoredKey): Promise<void> {
    // Store encrypted private key in database
    const keyEntity = new KeyEntity();
    keyEntity.did = did;
    keyEntity.keyId = key.keyId;
    keyEntity.algorithm = key.algorithm;
    keyEntity.keyType = key.keyType;
    keyEntity.publicKeyHex = key.publicKeyHex;
    keyEntity.encryptedPrivateKeyHex = JSON.stringify(key.encryptedPrivateKey);
    keyEntity.metadata = key.metadata;
    
    await this.keyRepository.save(keyEntity);

    // Also store in OS keyring for traditional keys
    if (key.keyType !== 'quantum') {
      const decryptedPrivateKeyString = await this.keyEncryptionService.decryptKey(key.encryptedPrivateKey);
      const decryptedPrivateKey = new Uint8Array(Buffer.from(decryptedPrivateKeyString, 'hex'));
      await storePrivateKey(key.keyId, decryptedPrivateKey, key.keyId);
    }
  }

  /**
   * Retrieve a key
   */
  async retrieveKey(did: string, keyId: string): Promise<StoredKey | null> {
    const keyEntity = await this.keyRepository.findOne({
      where: { did, keyId }
    });

    if (!keyEntity) {
      return null;
    }

    const encryptedPrivateKey: EncryptedKeyData = JSON.parse(keyEntity.encryptedPrivateKeyHex);
    
    return {
      keyId: keyEntity.keyId,
      algorithm: keyEntity.algorithm,
      keyType: keyEntity.keyType as 'signing' | 'encryption' | 'quantum',
      publicKeyHex: keyEntity.publicKeyHex,
      encryptedPrivateKey,
      metadata: keyEntity.metadata
    };
  }

  /**
   * Get decrypted private key
   */
  async getDecryptedPrivateKey(did: string, keyId: string): Promise<string | null> {
    const storedKey = await this.retrieveKey(did, keyId);
    if (!storedKey) {
      return null;
    }

    return await this.keyEncryptionService.decryptKey(storedKey.encryptedPrivateKey);
  }

  /**
   * List all keys for a DID
   */
  async listKeys(did: string): Promise<StoredKey[]> {
    const keyEntities = await this.keyRepository.find({
      where: { did }
    });

    return keyEntities.map(entity => ({
      keyId: entity.keyId,
      algorithm: entity.algorithm,
      keyType: entity.keyType as 'signing' | 'encryption' | 'quantum',
      publicKeyHex: entity.publicKeyHex,
      encryptedPrivateKey: JSON.parse(entity.encryptedPrivateKeyHex),
      metadata: entity.metadata
    }));
  }

  /**
   * Delete a key
   */
  async deleteKey(did: string, keyId: string): Promise<void> {
    await this.keyRepository.delete({ did, keyId });
    
    // Also remove from OS keyring if it exists
    try {
      await retrievePrivateKey(keyId); // Check if exists
      // If it exists, we should remove it, but storePrivateKeys doesn't have a delete function
      // This would need to be implemented in storePrivateKeys.ts
    } catch (error) {
      // Key doesn't exist in keyring, that's fine
    }
  }
}
