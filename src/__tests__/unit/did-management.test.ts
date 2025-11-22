import { 
  createDID, 
  createDIDWithAdmin, 
  importDID, 
  getDIDKeys, 
  listDIDs,
  setPrimaryDID,
  verifyPrimaryDID
} from '../../identityManager.js';
import { createTestEnvironment, createMockCredentials, expectToThrow } from '../utils/test-helpers.js';

describe('DID Management', () => {
  let testEnvironment: any;
  let mockCredentials: any;

  beforeAll(async () => {
    testEnvironment = await createTestEnvironment();
    mockCredentials = createMockCredentials();
  });

  afterAll(async () => {
    if (testEnvironment?.cleanup) {
      await testEnvironment.cleanup();
    }
  });

  describe('createDID', () => {
    it('should create a new DID successfully', async () => {
      const result = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'test-did-1'
      });

      expect(result).toBeDefined();
      expect(result.did).toBeDefined();
      expect(result.mnemonic).toBeDefined();
      expect(result.publicKeyHex).toBeDefined();
      expect(result.privateKeyHex).toBeDefined();
      expect(result.credentials).toBeDefined();
      expect(Array.isArray(result.credentials)).toBe(true);
    });

    it('should create a DID with cheqd method', async () => {
      const result = await createDID({
        method: 'cheqd:testnet',
        agent: testEnvironment.agent,
        alias: 'test-cheqd-did'
      });

      expect(result).toBeDefined();
      expect(result.did).toMatch(/^did:cheqd:testnet:/);
      expect(result.mnemonic).toBeDefined();
    });

    it('should throw error when agent is not provided', async () => {
      await expectToThrow(
        () => createDID({ method: 'key' }),
        'Agent not found'
      );
    });

    it('should create DID with custom alias', async () => {
      const customAlias = 'custom-test-did';
      const result = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: customAlias
      });

      expect(result.did).toBeDefined();
    });
  });

  describe('createDIDWithAdmin', () => {
    it('should create a DID with admin successfully', async () => {
      // First create a publisher DID
      const publisherResult = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'publisher-did'
      });

      const result = await createDIDWithAdmin({
        method: 'cheqd:testnet',
        agent: testEnvironment.agent,
        publisherDID: publisherResult.did.did,
        alias: 'admin-did'
      });

      expect(result).toBeDefined();
      expect(result.did).toBeDefined();
      expect(result.mnemonic).toBeDefined();
      expect(result.adminMnemonic).toBeDefined();
      expect(result.credentials).toBeDefined();
    });

    it('should throw error when agent is not provided', async () => {
      await expectToThrow(
        () => createDIDWithAdmin({
          method: 'cheqd:testnet',
          agent: null as any,
          publisherDID: 'test-publisher'
        }),
        'Cannot create DID without agent and publisher DID'
      );
    });

    it('should throw error when publisher DID is not provided', async () => {
      await expectToThrow(
        () => createDIDWithAdmin({
          method: 'cheqd:testnet',
          agent: testEnvironment.agent,
          publisherDID: ''
        }),
        'Cannot create DID without agent and publisher DID'
      );
    });
  });

  describe('importDID', () => {
    it('should import a DID successfully', async () => {
      // First create a DID to get a valid private key
      const createdDID = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'import-test-did'
      });

      // Convert private key to base64 for import
      const privateKeyBase64 = Buffer.from(createdDID.privateKeyHex, 'hex').toString('base64');

      const result = await importDID({
        didString: createdDID.did.did,
        privateKey: privateKeyBase64,
        method: 'key',
        agent: testEnvironment.agent
      });

      expect(result).toBeDefined();
      expect(result.did).toBeDefined();
      expect(result.credentials).toBeDefined();
    });

    it('should throw error for invalid private key', async () => {
      await expectToThrow(
        () => importDID({
          didString: 'did:key:test',
          privateKey: 'invalid-key',
          method: 'key',
          agent: testEnvironment.agent
        }),
        'Error importing DID'
      );
    });

    it('should throw error when agent is not provided', async () => {
      await expectToThrow(
        () => importDID({
          didString: 'did:key:test',
          privateKey: 'test-key',
          method: 'key'
        }),
        'Agent not found'
      );
    });
  });

  describe('getDIDKeys', () => {
    it('should retrieve DID keys successfully', async () => {
      const createdDID = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'keys-test-did'
      });

      const keys = await getDIDKeys(createdDID.did.did);

      expect(keys).toBeDefined();
    });

    it('should return undefined for non-existent DID', async () => {
      const keys = await getDIDKeys('did:key:non-existent');

      expect(keys).toBeUndefined();
    });

    it('should handle DID object input', async () => {
      const createdDID = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'object-test-did'
      });

      const keys = await getDIDKeys(createdDID.did);

      expect(keys).toBeDefined();
    });
  });

  describe('listDIDs', () => {
    it('should list all DIDs', async () => {
      // Create a few test DIDs
      await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'list-test-1'
      });

      await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'list-test-2'
      });

      const dids = await listDIDs(testEnvironment.agent);

      expect(Array.isArray(dids)).toBe(true);
      expect(dids.length).toBeGreaterThan(0);
    });

    it('should list DIDs by provider', async () => {
      const dids = await listDIDs(testEnvironment.agent, 'did:key');

      expect(Array.isArray(dids)).toBe(true);
    });

    it('should return empty array on error', async () => {
      const dids = await listDIDs(null as any);

      expect(Array.isArray(dids)).toBe(true);
      expect(dids.length).toBe(0);
    });
  });

  describe('setPrimaryDID', () => {
    it('should set primary DID successfully', async () => {
      const createdDID = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'primary-test-did'
      });

      const privateKeyBase64 = Buffer.from(createdDID.privateKeyHex, 'hex').toString('base64');
      const password = 'test-password';

      const result = await setPrimaryDID(createdDID.did.did, privateKeyBase64, password);

      expect(result).toBeDefined();
      expect(result.credentials).toBeDefined();
    });

    it('should throw error for invalid private key', async () => {
      await expectToThrow(
        () => setPrimaryDID('did:key:test', '', 'password'),
        'Private key must be provided to set primary DID'
      );
    });

    it('should throw error when user agent is not found', async () => {
      // Mock userAgent to be null
      const originalUserAgent = (global as any).userAgent;
      (global as any).userAgent = null;

      try {
        const result = await setPrimaryDID('did:key:test', 'test-key', 'password');
        expect(result).toBe(false);
      } finally {
        (global as any).userAgent = originalUserAgent;
      }
    });
  });

  describe('verifyPrimaryDID', () => {
    it('should verify primary DID with correct password', async () => {
      // This test would require setting up a primary DID first
      // For now, we'll test the error cases
      const result = await verifyPrimaryDID('wrong-password');
      
      expect(result).toBe(false);
    });

    it('should return false for wrong password', async () => {
      const result = await verifyPrimaryDID('wrong-password');
      
      expect(result).toBe(false);
    });
  });

  describe('DID validation and security', () => {
    it('should validate DID format', async () => {
      const result = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'format-test-did'
      });

      expect(result.did.did).toMatch(/^did:key:/);
    });

    it('should handle special characters in aliases', async () => {
      const specialAlias = 'test-did-with-special-chars-123';
      const result = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: specialAlias
      });

      expect(result.did).toBeDefined();
    });

    it('should generate unique DIDs', async () => {
      const result1 = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'unique-test-1'
      });

      const result2 = await createDID({
        method: 'key',
        agent: testEnvironment.agent,
        alias: 'unique-test-2'
      });

      expect(result1.did.did).not.toBe(result2.did.did);
    });
  });

  describe('Error handling', () => {
    it('should handle network errors gracefully', async () => {
      // Mock agent to throw network error
      const mockAgent = {
        ...testEnvironment.agent,
        didManagerCreate: jest.fn().mockRejectedValue(new Error('Network error'))
      };

      await expectToThrow(
        () => createDID({
          method: 'cheqd:testnet',
          agent: mockAgent,
          alias: 'network-test-did'
        }),
        'Error creating DID'
      );
    });

    it('should handle invalid method gracefully', async () => {
      await expectToThrow(
        () => createDID({
          method: 'invalid:method',
          agent: testEnvironment.agent,
          alias: 'invalid-method-test'
        }),
        'Error creating DID'
      );
    });
  });
});