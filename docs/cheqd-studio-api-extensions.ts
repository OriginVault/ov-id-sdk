/**
 * Cheqd Studio API Extensions for OV-ID-SDK Integration
 * 
 * This file contains the API extensions that need to be added to cheqd-studio
 * to support seamless integration with the enhanced OV-ID-SDK security features.
 */

import type { Request, Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { SecurityBridgeService } from '@originvault/ov-id-sdk';

// =============================================================================
// TYPES AND INTERFACES
// =============================================================================

export interface KeySyncRequest {
  operation: 'create' | 'update' | 'rotate' | 'delete';
  keyId: string;
  did: string;
  customerId: string;
  metadata: {
    keyType?: string;
    purpose?: string;
    algorithm?: string;
    [key: string]: any;
  };
}

export interface KeySyncResponse {
  success: boolean;
  operation: string;
  keyId: string;
  timestamp: string;
  cheqdStudioKeyId?: string;
}

export interface KeyRotationPlan {
  did: string;
  customerId: string;
  timestamp: string;
  source: 'ov-id-sdk' | 'cheqd-studio';
  rotationType?: 'scheduled' | 'emergency' | 'manual';
  estimatedDuration?: number;
}

export interface KeyRotationResponse {
  success: boolean;
  coordinated: boolean;
  rotationId: string;
  timestamp: string;
  affectedKeys: string[];
}

export interface SecurityStateRequest {
  timestamp: string;
  source: 'ov-id-sdk' | 'cheqd-studio';
  securityScore: number;
  issues: Array<{
    severity: 'low' | 'medium' | 'high' | 'critical';
    category: string;
    description: string;
  }>;
}

export interface SecurityStateResponse {
  success: boolean;
  synchronized: boolean;
  timestamp: string;
  recommendations: string[];
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

/**
 * Security sync middleware for validating OV-ID-SDK requests
 */
export const securitySyncMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const secret = req.headers['x-ov-sdk-secret'] as string;
  const expectedSecret = process.env.OV_SDK_SECRET;
  
  if (!secret || !expectedSecret) {
    return res.status(StatusCodes.UNAUTHORIZED).json({
      error: 'Security secret not provided',
      code: 'MISSING_SECRET'
    });
  }
  
  if (secret !== expectedSecret) {
    return res.status(StatusCodes.UNAUTHORIZED).json({
      error: 'Invalid security secret',
      code: 'INVALID_SECRET'
    });
  }
  
  // Add request metadata
  req.ovSdkRequest = {
    timestamp: new Date().toISOString(),
    source: 'ov-id-sdk'
  };
  
  next();
};

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      ovSdkRequest?: {
        timestamp: string;
        source: string;
      };
    }
  }
}

// =============================================================================
// KEY SYNC CONTROLLER
// =============================================================================

export class KeySyncController {
  private securityBridge: SecurityBridgeService;
  
  constructor() {
    this.securityBridge = SecurityBridgeService.getInstance({
      cheqdStudioEndpoint: process.env.OV_SDK_ENDPOINT || 'http://localhost:3000',
      sharedSecretKey: process.env.OV_SDK_SECRET || '',
      enableCrossRepoSync: true
    });
  }
  
  /**
   * Handle key synchronization requests from OV-ID-SDK
   * POST /api/key-sync
   */
  public async syncKey(req: Request, res: Response): Promise<void> {
    try {
      const { operation, keyId, did, customerId, metadata }: KeySyncRequest = req.body;
      
      // Validate request
      if (!operation || !keyId || !did || !customerId) {
        res.status(StatusCodes.BAD_REQUEST).json({
          error: 'Missing required fields',
          code: 'MISSING_FIELDS',
          required: ['operation', 'keyId', 'did', 'customerId']
        });
        return;
      }
      
      // Process key sync operation
      let cheqdStudioKeyId: string | undefined;
      
      switch (operation) {
        case 'create':
          cheqdStudioKeyId = await this.createKey(keyId, did, customerId, metadata);
          break;
          
        case 'update':
          cheqdStudioKeyId = await this.updateKey(keyId, did, customerId, metadata);
          break;
          
        case 'rotate':
          cheqdStudioKeyId = await this.rotateKey(keyId, did, customerId, metadata);
          break;
          
        case 'delete':
          await this.deleteKey(keyId, did, customerId, metadata);
          break;
          
        default:
          res.status(StatusCodes.BAD_REQUEST).json({
            error: 'Invalid operation',
            code: 'INVALID_OPERATION',
            validOperations: ['create', 'update', 'rotate', 'delete']
          });
          return;
      }
      
      const response: KeySyncResponse = {
        success: true,
        operation,
        keyId,
        timestamp: new Date().toISOString(),
        cheqdStudioKeyId
      };
      
      // Log the operation
      console.log(`[KEY-SYNC] ${operation} ${keyId} for DID ${did}: SUCCESS`);
      
      res.status(StatusCodes.OK).json(response);
      
    } catch (error) {
      console.error('[KEY-SYNC] Error:', error);
      
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        error: 'Key sync operation failed',
        code: 'SYNC_FAILED',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  private async createKey(keyId: string, did: string, customerId: string, metadata: any): Promise<string> {
    // Implementation for creating a key in cheqd-studio
    // This would integrate with your existing key management system
    
    console.log(`[KEY-SYNC] Creating key ${keyId} for DID ${did}`);
    
    // Generate a cheqd-studio specific key ID
    const cheqdStudioKeyId = `cheqd_${keyId}_${Date.now()}`;
    
    // Store the key mapping
    await this.storeKeyMapping(keyId, cheqdStudioKeyId, did, customerId, metadata);
    
    return cheqdStudioKeyId;
  }
  
  private async updateKey(keyId: string, did: string, customerId: string, metadata: any): Promise<string> {
    // Implementation for updating a key in cheqd-studio
    
    console.log(`[KEY-SYNC] Updating key ${keyId} for DID ${did}`);
    
    // Find existing key mapping
    const mapping = await this.getKeyMapping(keyId, did);
    if (!mapping) {
      throw new Error(`Key mapping not found for ${keyId}`);
    }
    
    // Update the key metadata
    await this.updateKeyMapping(mapping.cheqdStudioKeyId, metadata);
    
    return mapping.cheqdStudioKeyId;
  }
  
  private async rotateKey(keyId: string, did: string, customerId: string, metadata: any): Promise<string> {
    // Implementation for rotating a key in cheqd-studio
    
    console.log(`[KEY-SYNC] Rotating key ${keyId} for DID ${did}`);
    
    // Find existing key mapping
    const mapping = await this.getKeyMapping(keyId, did);
    if (!mapping) {
      throw new Error(`Key mapping not found for ${keyId}`);
    }
    
    // Perform key rotation
    const newCheqdStudioKeyId = await this.performKeyRotation(mapping.cheqdStudioKeyId, metadata);
    
    // Update the mapping
    await this.updateKeyMapping(keyId, { ...metadata, rotatedAt: new Date().toISOString() });
    
    return newCheqdStudioKeyId;
  }
  
  private async deleteKey(keyId: string, did: string, customerId: string, metadata: any): Promise<void> {
    // Implementation for deleting a key in cheqd-studio
    
    console.log(`[KEY-SYNC] Deleting key ${keyId} for DID ${did}`);
    
    // Find existing key mapping
    const mapping = await this.getKeyMapping(keyId, did);
    if (!mapping) {
      throw new Error(`Key mapping not found for ${keyId}`);
    }
    
    // Mark key as deleted (soft delete for audit trail)
    await this.markKeyAsDeleted(mapping.cheqdStudioKeyId, metadata);
  }
  
  // Helper methods (implement based on your database/storage system)
  private async storeKeyMapping(ovSdkKeyId: string, cheqdStudioKeyId: string, did: string, customerId: string, metadata: any): Promise<void> {
    // Store the mapping between OV-ID-SDK key ID and cheqd-studio key ID
    // This could be in a database, Redis, or other storage system
  }
  
  private async getKeyMapping(ovSdkKeyId: string, did: string): Promise<{ cheqdStudioKeyId: string; metadata: any } | null> {
    // Retrieve the key mapping
    return null; // Implement based on your storage system
  }
  
  private async updateKeyMapping(cheqdStudioKeyId: string, metadata: any): Promise<void> {
    // Update key metadata
  }
  
  private async performKeyRotation(cheqdStudioKeyId: string, metadata: any): Promise<string> {
    // Perform the actual key rotation
    return `rotated_${cheqdStudioKeyId}_${Date.now()}`;
  }
  
  private async markKeyAsDeleted(cheqdStudioKeyId: string, metadata: any): Promise<void> {
    // Mark key as deleted
  }
}

// =============================================================================
// KEY ROTATION CONTROLLER
// =============================================================================

export class KeyRotationController {
  private securityBridge: SecurityBridgeService;
  
  constructor() {
    this.securityBridge = SecurityBridgeService.getInstance({
      cheqdStudioEndpoint: process.env.OV_SDK_ENDPOINT || 'http://localhost:3000',
      sharedSecretKey: process.env.OV_SDK_SECRET || '',
      enableCrossRepoSync: true
    });
  }
  
  /**
   * Coordinate key rotation with OV-ID-SDK
   * POST /api/key-rotation/coordinate
   */
  public async coordinateRotation(req: Request, res: Response): Promise<void> {
    try {
      const { did, customerId, timestamp, source, rotationType, estimatedDuration }: KeyRotationPlan = req.body;
      
      // Validate request
      if (!did || !customerId || !timestamp || !source) {
        res.status(StatusCodes.BAD_REQUEST).json({
          error: 'Missing required fields',
          code: 'MISSING_FIELDS',
          required: ['did', 'customerId', 'timestamp', 'source']
        });
        return;
      }
      
      console.log(`[KEY-ROTATION] Coordinating rotation for DID ${did} from ${source}`);
      
      // Generate rotation ID
      const rotationId = `rotation_${did}_${Date.now()}`;
      
      // Get all keys associated with this DID
      const affectedKeys = await this.getKeysForDID(did);
      
      // Coordinate with OV-ID-SDK if needed
      if (source === 'cheqd-studio') {
        await this.notifyOVSDK(rotationId, did, customerId, affectedKeys);
      }
      
      // Perform local key rotation
      await this.performLocalKeyRotation(did, affectedKeys, rotationType);
      
      const response: KeyRotationResponse = {
        success: true,
        coordinated: true,
        rotationId,
        timestamp: new Date().toISOString(),
        affectedKeys
      };
      
      console.log(`[KEY-ROTATION] Rotation ${rotationId} completed successfully`);
      
      res.status(StatusCodes.OK).json(response);
      
    } catch (error) {
      console.error('[KEY-ROTATION] Error:', error);
      
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        error: 'Key rotation coordination failed',
        code: 'ROTATION_FAILED',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  private async getKeysForDID(did: string): Promise<string[]> {
    // Get all keys associated with the DID
    // This would query your key storage system
    return [`key_${did}_1`, `key_${did}_2`];
  }
  
  private async notifyOVSDK(rotationId: string, did: string, customerId: string, affectedKeys: string[]): Promise<void> {
    // Notify OV-ID-SDK about the key rotation
    try {
      await this.securityBridge.coordinateKeyRotation(did, customerId);
    } catch (error) {
      console.warn('[KEY-ROTATION] Failed to notify OV-ID-SDK:', error);
      // Don't fail the entire operation if notification fails
    }
  }
  
  private async performLocalKeyRotation(did: string, keys: string[], rotationType?: string): Promise<void> {
    // Perform the actual key rotation in cheqd-studio
    console.log(`[KEY-ROTATION] Rotating ${keys.length} keys for DID ${did} (${rotationType || 'manual'})`);
    
    for (const keyId of keys) {
      // Implement key rotation logic
      console.log(`[KEY-ROTATION] Rotating key ${keyId}`);
    }
  }
}

// =============================================================================
// SECURITY STATE CONTROLLER
// =============================================================================

export class SecurityStateController {
  /**
   * Synchronize security state with OV-ID-SDK
   * POST /api/security/state
   */
  public async syncSecurityState(req: Request, res: Response): Promise<void> {
    try {
      const { timestamp, source, securityScore, issues }: SecurityStateRequest = req.body;
      
      console.log(`[SECURITY-STATE] Syncing security state from ${source} (score: ${securityScore})`);
      
      // Process security issues
      const recommendations = await this.processSecurityIssues(issues);
      
      // Update local security state
      await this.updateLocalSecurityState(securityScore, issues, recommendations);
      
      const response: SecurityStateResponse = {
        success: true,
        synchronized: true,
        timestamp: new Date().toISOString(),
        recommendations
      };
      
      res.status(StatusCodes.OK).json(response);
      
    } catch (error) {
      console.error('[SECURITY-STATE] Error:', error);
      
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        error: 'Security state sync failed',
        code: 'SYNC_FAILED',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  /**
   * Get current security state
   * GET /api/security/state
   */
  public async getSecurityState(req: Request, res: Response): Promise<void> {
    try {
      const securityState = await this.getLocalSecurityState();
      
      res.status(StatusCodes.OK).json(securityState);
      
    } catch (error) {
      console.error('[SECURITY-STATE] Error:', error);
      
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        error: 'Failed to get security state',
        code: 'GET_FAILED',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  private async processSecurityIssues(issues: Array<{ severity: string; category: string; description: string }>): Promise<string[]> {
    const recommendations: string[] = [];
    
    for (const issue of issues) {
      switch (issue.severity) {
        case 'critical':
          recommendations.push(`CRITICAL: ${issue.description} - Immediate action required`);
          break;
        case 'high':
          recommendations.push(`HIGH: ${issue.description} - Address within 24 hours`);
          break;
        case 'medium':
          recommendations.push(`MEDIUM: ${issue.description} - Address within 1 week`);
          break;
        case 'low':
          recommendations.push(`LOW: ${issue.description} - Address when convenient`);
          break;
      }
    }
    
    return recommendations;
  }
  
  private async updateLocalSecurityState(score: number, issues: any[], recommendations: string[]): Promise<void> {
    // Update local security state storage
    console.log(`[SECURITY-STATE] Updated local security state (score: ${score}, issues: ${issues.length})`);
  }
  
  private async getLocalSecurityState(): Promise<any> {
    // Get current local security state
    return {
      score: 95,
      issues: [],
      lastUpdated: new Date().toISOString()
    };
  }
}

// =============================================================================
// ROUTE SETUP
// =============================================================================

/**
 * Setup routes for OV-ID-SDK integration
 * Add this to your cheqd-studio Express app
 */
export function setupOVSDKIntegrationRoutes(app: any) {
  const keySyncController = new KeySyncController();
  const keyRotationController = new KeyRotationController();
  const securityStateController = new SecurityStateController();
  
  // Key sync routes
  app.post('/api/key-sync', securitySyncMiddleware, (req: Request, res: Response) => {
    keySyncController.syncKey(req, res);
  });
  
  // Key rotation routes
  app.post('/api/key-rotation/coordinate', securitySyncMiddleware, (req: Request, res: Response) => {
    keyRotationController.coordinateRotation(req, res);
  });
  
  // Security state routes
  app.post('/api/security/state', securitySyncMiddleware, (req: Request, res: Response) => {
    securityStateController.syncSecurityState(req, res);
  });
  
  app.get('/api/security/state', (req: Request, res: Response) => {
    securityStateController.getSecurityState(req, res);
  });
  
  console.log('[OV-SDK-INTEGRATION] Routes configured successfully');
}

// =============================================================================
// ENVIRONMENT CONFIGURATION
// =============================================================================

/**
 * Required environment variables for cheqd-studio
 * Add these to your .env file
 */
export const requiredEnvVars = {
  OV_SDK_ENDPOINT: 'https://your-ov-sdk-instance.com',
  OV_SDK_SECRET: 'your-shared-secret-here',
  OV_ENABLE_SDK_INTEGRATION: 'true',
  OV_MASTER_ENCRYPTION_KEY: 'your-32-byte-hex-key-here'
};

/**
 * Validate environment configuration
 */
export function validateEnvironment(): boolean {
  const missing = Object.entries(requiredEnvVars).filter(([key, value]) => {
    const envValue = process.env[key];
    return !envValue || envValue === value;
  });
  
  if (missing.length > 0) {
    console.error('[OV-SDK-INTEGRATION] Missing or invalid environment variables:');
    missing.forEach(([key]) => {
      console.error(`  - ${key}`);
    });
    return false;
  }
  
  console.log('[OV-SDK-INTEGRATION] Environment configuration validated');
  return true;
}
