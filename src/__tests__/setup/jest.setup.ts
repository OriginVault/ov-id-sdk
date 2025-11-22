import 'dotenv/config';
import { setupTestEnv } from '../utils/test-helpers.js';

// Global test setup
beforeAll(() => {
  setupTestEnv();
});

// Global test cleanup
afterAll(() => {
  // Cleanup is handled by individual test files
});

// Increase timeout for integration tests
jest.setTimeout(30000);

// Mock console methods to reduce noise in tests
const originalConsole = { ...console };
beforeEach(() => {
  console.log = jest.fn();
  console.warn = jest.fn();
  console.error = jest.fn();
});

afterEach(() => {
  console.log = originalConsole.log;
  console.warn = originalConsole.warn;
  console.error = originalConsole.error;
});
