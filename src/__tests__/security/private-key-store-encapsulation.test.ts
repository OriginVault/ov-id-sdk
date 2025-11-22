import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { 
  createOVAgent, 
  createCheqdProvider, 
  CheqdNetwork, 
  keyStore,
  getPrivateKeyStore 
} from '../../OVAgent.js';
import { packageStore, parentStore } from '../../packageAgent.js';
import { createResource } from '../../resourceManager.js';
import { CheqdDIDProvider } from '@cheqd/did-provider-cheqd';

describe('Private Key Store Encapsulation Security Tests', () => {
  let testAgent: any;
  let testProvider: CheqdDIDProvider;

  beforeEach(() => {
    // Create a test provider and agent
    testProvider = createCheqdProvider(
      CheqdNetwork.Testnet, 
      'test-seed', 
      'https://rpc.cheqd.network'
    );
    testAgent = createOVAgent({ 
      cheqdProvider: testProvider, 
      universalResolver: {}, 
      additionalResolvers: {} 
    });
  });

  afterEach(() => {
    // Clean up
    testAgent = null;
    testProvider = null;
  });

  describe('Private Key Store Access Control', () => {
    it('should not export privateKeyStore directly', () => {
      // This test verifies that privateKeyStore is not directly accessible
      // from the main export
      const ovAgentModule = require('../../OVAgent.js');
      
      // privateKeyStore should not be in the exports
      expect(ovAgentModule.privateKeyStore).toBeUndefined();
      
      // But getPrivateKeyStore function should be available for internal use
      expect(typeof ovAgentModule.getPrivateKeyStore).toBe('function');
    });

    it('should not expose privateKeyStore in packageStore', () => {
      // Verify that packageStore doesn't expose privateKeyStore
      expect(packageStore.privateKeyStore).toBeUndefined();
      
      // But other expected properties should be present
      expect(packageStore.agent).toBeDefined();
      expect(packageStore.keyStore).toBeDefined();
      expect(packageStore.initialize).toBeDefined();
    });

    it('should not expose privateKeyStore in parentStore', () => {
      // Verify that parentStore doesn't expose privateKeyStore
      expect(parentStore.privateKeyStore).toBeUndefined();
      
      // But other expected properties should be present
      expect(parentStore.agent).toBeDefined();
      expect(parentStore.keyStore).toBeDefined();
      expect(parentStore.initialize).toBeDefined();
    });

    it('should allow internal access to privateKeyStore via getPrivateKeyStore', () => {
      // This test verifies that internal functions can still access the private key store
      const internalKeyStore = getPrivateKeyStore();
      
      expect(internalKeyStore).toBeDefined();
      expect(typeof internalKeyStore.getKey).toBe('function');
      expect(typeof internalKeyStore.setKey).toBe('function');
    });
  });

  describe('Agent Initialization Security', () => {
    it('should initialize agent without exposing private keys', async () => {
      // Test that agent initialization works without exposing private keys
      const result = await packageStore.initialize({
        payerSeed: 'test-seed',
        didRecoveryPhrase: 'test recovery phrase'
      });

      // Verify the result doesn't contain privateKeyStore
      expect(result.privateKeyStore).toBeUndefined();
      
      // But should contain other expected properties
      expect(result.agent).toBeDefined();
      expect(result.did).toBeDefined();
      expect(result.cheqdMainnetProvider).toBeDefined();
      expect(result.cheqdTestnetProvider).toBeDefined();
    });

    it('should initialize parent agent without exposing private keys', async () => {
      // Test that parent agent initialization works without exposing private keys
      const result = await parentStore.initialize({
        payerSeed: 'test-seed',
        didRecoveryPhrase: 'test recovery phrase'
      });

      // Verify the result doesn't contain privateKeyStore
      expect(result.privateKeyStore).toBeUndefined();
      
      // But should contain other expected properties
      expect(result.agent).toBeDefined();
      expect(result.did).toBeDefined();
      expect(result.cheqdMainnetProvider).toBeDefined();
      expect(result.cheqdTestnetProvider).toBeDefined();
    });
  });

  describe('Resource Creation Security', () => {
    it('should create resources without requiring external keyStore parameter', async () => {
      // This test verifies that createResource can work with internal key store
      // without requiring the keyStore to be passed as a parameter
      
      const testData = { test: 'data' };
      const testDid = 'did:cheqd:testnet:test123';
      const testName = 'test-resource';
      const testVersion = '1.0.0';
      const testResourceType = 'TestResource';

      // Mock the getDIDKeys function to return test data
      const mockGetDIDKeys = jest.fn().mockResolvedValue({
        keyName: testDid,
        kid: 'test-key-id'
      });

      // Mock the getVerifiedAuthentication function
      const mockGetVerifiedAuthentication = jest.fn().mockResolvedValue({
        id: 'test-verification-method-id'
      });

      // Mock the provider.createResource method
      const mockCreateResource = jest.fn().mockResolvedValue('test-result');

      // We can't easily test the full createResource function without mocking
      // the entire cheqd provider, but we can test that the function signature
      // no longer requires keyStore parameter
      
      // This test mainly verifies that the function can be called without keyStore
      expect(() => {
        // This should not throw an error about missing keyStore parameter
        createResource({
          did: testDid,
          name: testName,
          version: testVersion,
          provider: testProvider,
          agent: testAgent,
          data: testData,
          resourceType: testResourceType
        });
      }).not.toThrow();
    });
  });

  describe('Key Store Interface Security', () => {
    it('should maintain keyStore interface without private key exposure', () => {
      // Verify that the public keyStore interface is still available
      expect(keyStore).toBeDefined();
      expect(typeof keyStore.getKey).toBe('function');
      expect(typeof keyStore.setKey).toBe('function');
    });

    it('should separate public and private key stores', () => {
      // Verify that public keyStore and private key store are different instances
      const publicKeyStore = keyStore;
      const privateKeyStore = getPrivateKeyStore();
      
      expect(publicKeyStore).not.toBe(privateKeyStore);
    });
  });

  describe('Export Security', () => {
    it('should not expose private key store in main SDK export', () => {
      // Test that the main SDK export doesn't expose private key store
      const sdk = require('../../index.js');
      
      // These should not be accessible from the main export
      expect(sdk.privateKeyStore).toBeUndefined();
      
      // But other expected exports should be present
      expect(sdk.createOVAgent).toBeDefined();
      expect(sdk.createCheqdProvider).toBeDefined();
      expect(sdk.CheqdNetwork).toBeDefined();
    });
  });
});
