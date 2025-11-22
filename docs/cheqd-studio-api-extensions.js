/**
 * Cheqd Studio API Extensions for OV-ID-SDK Integration
 *
 * This file contains the API extensions that need to be added to cheqd-studio
 * to support seamless integration with the enhanced OV-ID-SDK security features.
 */
import { StatusCodes } from 'http-status-codes';
import { SecurityBridgeService } from '@originvault/ov-id-sdk';
// =============================================================================
// MIDDLEWARE
// =============================================================================
/**
 * Security sync middleware for validating OV-ID-SDK requests
 */
export const securitySyncMiddleware = (req, res, next) => {
    const secret = req.headers['x-ov-sdk-secret'];
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
// =============================================================================
// KEY SYNC CONTROLLER
// =============================================================================
export class KeySyncController {
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
    async syncKey(req, res) {
        try {
            const { operation, keyId, did, customerId, metadata } = req.body;
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
            let cheqdStudioKeyId;
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
            const response = {
                success: true,
                operation,
                keyId,
                timestamp: new Date().toISOString(),
                cheqdStudioKeyId
            };
            // Log the operation
            console.log(`[KEY-SYNC] ${operation} ${keyId} for DID ${did}: SUCCESS`);
            res.status(StatusCodes.OK).json(response);
        }
        catch (error) {
            console.error('[KEY-SYNC] Error:', error);
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
                error: 'Key sync operation failed',
                code: 'SYNC_FAILED',
                details: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    }
    async createKey(keyId, did, customerId, metadata) {
        // Implementation for creating a key in cheqd-studio
        // This would integrate with your existing key management system
        console.log(`[KEY-SYNC] Creating key ${keyId} for DID ${did}`);
        // Generate a cheqd-studio specific key ID
        const cheqdStudioKeyId = `cheqd_${keyId}_${Date.now()}`;
        // Store the key mapping
        await this.storeKeyMapping(keyId, cheqdStudioKeyId, did, customerId, metadata);
        return cheqdStudioKeyId;
    }
    async updateKey(keyId, did, customerId, metadata) {
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
    async rotateKey(keyId, did, customerId, metadata) {
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
    async deleteKey(keyId, did, customerId, metadata) {
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
    async storeKeyMapping(ovSdkKeyId, cheqdStudioKeyId, did, customerId, metadata) {
        // Store the mapping between OV-ID-SDK key ID and cheqd-studio key ID
        // This could be in a database, Redis, or other storage system
    }
    async getKeyMapping(ovSdkKeyId, did) {
        // Retrieve the key mapping
        return null; // Implement based on your storage system
    }
    async updateKeyMapping(cheqdStudioKeyId, metadata) {
        // Update key metadata
    }
    async performKeyRotation(cheqdStudioKeyId, metadata) {
        // Perform the actual key rotation
        return `rotated_${cheqdStudioKeyId}_${Date.now()}`;
    }
    async markKeyAsDeleted(cheqdStudioKeyId, metadata) {
        // Mark key as deleted
    }
}
// =============================================================================
// KEY ROTATION CONTROLLER
// =============================================================================
export class KeyRotationController {
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
    async coordinateRotation(req, res) {
        try {
            const { did, customerId, timestamp, source, rotationType, estimatedDuration } = req.body;
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
            const response = {
                success: true,
                coordinated: true,
                rotationId,
                timestamp: new Date().toISOString(),
                affectedKeys
            };
            console.log(`[KEY-ROTATION] Rotation ${rotationId} completed successfully`);
            res.status(StatusCodes.OK).json(response);
        }
        catch (error) {
            console.error('[KEY-ROTATION] Error:', error);
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
                error: 'Key rotation coordination failed',
                code: 'ROTATION_FAILED',
                details: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    }
    async getKeysForDID(did) {
        // Get all keys associated with the DID
        // This would query your key storage system
        return [`key_${did}_1`, `key_${did}_2`];
    }
    async notifyOVSDK(rotationId, did, customerId, affectedKeys) {
        // Notify OV-ID-SDK about the key rotation
        try {
            await this.securityBridge.coordinateKeyRotation(did, customerId);
        }
        catch (error) {
            console.warn('[KEY-ROTATION] Failed to notify OV-ID-SDK:', error);
            // Don't fail the entire operation if notification fails
        }
    }
    async performLocalKeyRotation(did, keys, rotationType) {
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
    async syncSecurityState(req, res) {
        try {
            const { timestamp, source, securityScore, issues } = req.body;
            console.log(`[SECURITY-STATE] Syncing security state from ${source} (score: ${securityScore})`);
            // Process security issues
            const recommendations = await this.processSecurityIssues(issues);
            // Update local security state
            await this.updateLocalSecurityState(securityScore, issues, recommendations);
            const response = {
                success: true,
                synchronized: true,
                timestamp: new Date().toISOString(),
                recommendations
            };
            res.status(StatusCodes.OK).json(response);
        }
        catch (error) {
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
    async getSecurityState(req, res) {
        try {
            const securityState = await this.getLocalSecurityState();
            res.status(StatusCodes.OK).json(securityState);
        }
        catch (error) {
            console.error('[SECURITY-STATE] Error:', error);
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
                error: 'Failed to get security state',
                code: 'GET_FAILED',
                details: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    }
    async processSecurityIssues(issues) {
        const recommendations = [];
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
    async updateLocalSecurityState(score, issues, recommendations) {
        // Update local security state storage
        console.log(`[SECURITY-STATE] Updated local security state (score: ${score}, issues: ${issues.length})`);
    }
    async getLocalSecurityState() {
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
export function setupOVSDKIntegrationRoutes(app) {
    const keySyncController = new KeySyncController();
    const keyRotationController = new KeyRotationController();
    const securityStateController = new SecurityStateController();
    // Key sync routes
    app.post('/api/key-sync', securitySyncMiddleware, (req, res) => {
        keySyncController.syncKey(req, res);
    });
    // Key rotation routes
    app.post('/api/key-rotation/coordinate', securitySyncMiddleware, (req, res) => {
        keyRotationController.coordinateRotation(req, res);
    });
    // Security state routes
    app.post('/api/security/state', securitySyncMiddleware, (req, res) => {
        securityStateController.syncSecurityState(req, res);
    });
    app.get('/api/security/state', (req, res) => {
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
export function validateEnvironment() {
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
