import 'dotenv/config';
import { beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import { setupTestEnv } from '../utils/test-helpers.js';

beforeAll(() => {
  setupTestEnv();
});

afterAll(() => {
  // optional global cleanup if needed
});

beforeEach(() => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});













