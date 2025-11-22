# OV-ID-SDK Test Suite

This directory contains comprehensive tests for the OV-ID-SDK, covering unit tests, integration tests, security tests, and performance tests.

## Test Structure

```
src/__tests__/
├── setup/                    # Test setup and configuration
│   └── jest.setup.ts        # Global test setup
├── utils/                    # Test utilities and helpers
│   └── test-helpers.ts      # Common test utilities
├── unit/                     # Unit tests for individual modules
│   ├── aes-rsa-encryption.test.ts
│   ├── encryption.test.ts
│   └── did-management.test.ts
├── integration/              # Integration tests
│   ├── didcomm-integration.test.ts
│   └── security-integration.test.ts
├── security/                 # Security-focused tests
│   ├── secure-key-storage.test.ts
│   ├── envelope-encryption.test.ts
│   ├── aes-rsa-encryption.test.ts
│   ├── didcomm-security.test.ts
│   ├── comprehensive-security.test.ts
│   ├── environment-key-handling.test.ts
│   ├── private-key-store-encapsulation.test.ts
│   └── standalone-security.test.ts
├── performance/              # Performance and load tests
│   ├── load-testing.test.ts
│   └── security-performance.test.ts
└── mocks/                    # Mock services and data
    └── mock-services.ts
```

## Running Tests

### All Tests
```bash
npm test
```

### Specific Test Categories
```bash
# Unit tests only
npm run test:unit

# Integration tests only
npm run test:integration

# Security tests only
npm run test:security

# Performance tests only
npm run test:performance
```

### Test Modes
```bash
# Watch mode for development
npm run test:watch

# CI mode with coverage
npm run test:ci

# Debug mode with verbose output
npm run test:debug
```

## Test Categories

### Unit Tests
- **AES-RSA Encryption**: Tests for hybrid encryption functionality
- **Encryption Module**: Tests for secure encryption/decryption operations
- **DID Management**: Tests for DID creation, import, and management

### Integration Tests
- **DIDComm Integration**: End-to-end tests for DIDComm messaging
- **Security Integration**: Multi-layer security workflow tests

### Security Tests
- **Secure Key Storage**: Tests for encrypted key storage and retrieval
- **Envelope Encryption**: Tests for envelope encryption service
- **Comprehensive Security**: Full security validation and reporting
- **Environment Key Handling**: Tests for secure environment variable handling
- **Private Key Store Encapsulation**: Tests for secure key store isolation

### Performance Tests
- **Load Testing**: High-volume operation testing
- **Security Performance**: Performance testing for security operations

## Test Utilities

### TestEnvironment
Provides a complete test environment with:
- Mock Veramo agent
- Test DIDs and keys
- Cleanup functionality

### MockCredentials
Generates test credentials for:
- Test users
- Test issuers
- Biometric data

### PerformanceTimer
Utility for measuring test performance:
```typescript
const timer = new PerformanceTimer();
timer.start();
// ... perform operation
const duration = timer.stop();
```

### Test Assertions
Helper functions for common test assertions:
- `isValidHex()`: Validates hexadecimal strings
- `isValidBase64()`: Validates base64 strings
- `isValidDID()`: Validates DID format
- `isValidTimestamp()`: Validates timestamp format

## Test Data

### Mock Data Generators
- `generatePrivateKey()`: Generates test private keys
- `generatePublicKey()`: Generates test public keys
- `generateDID()`: Generates test DIDs
- `generateMessage()`: Generates test messages
- `generatePassword()`: Generates test passwords

### Biometric Data
- `createTestBiometricData()`: Creates test biometric data for session DIDs

## Security Testing

### Encryption Testing
- AES-256-GCM encryption/decryption
- RSA-OAEP key encryption
- Hybrid AES-RSA encryption
- Envelope encryption patterns

### Key Management Testing
- Secure key storage and retrieval
- Key rotation and management
- Memory protection and zeroization
- Key integrity validation

### Security Validation
- Overall security state validation
- Key integrity checks
- Encryption configuration validation
- Security reporting

## Performance Testing

### Load Testing
- High-volume encryption operations
- Concurrent operation handling
- Memory usage monitoring
- Throughput measurement

### Stress Testing
- Sustained load testing
- Mixed operation testing
- Memory leak detection
- Performance degradation monitoring

## Coverage Requirements

The test suite maintains the following coverage thresholds:
- **Branches**: 70%
- **Functions**: 70%
- **Lines**: 70%
- **Statements**: 70%

## Test Configuration

### Jest Configuration
- ESM support with TypeScript
- 30-second timeout for integration tests
- Coverage reporting in multiple formats
- Transform configuration for dependencies

### Environment Setup
- Test environment variables
- Mock services and dependencies
- Cleanup procedures
- Memory management

## Best Practices

### Test Organization
- Group related tests in describe blocks
- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)
- Clean up resources after tests

### Security Testing
- Test both positive and negative cases
- Validate error handling
- Test edge cases and boundary conditions
- Verify security properties

### Performance Testing
- Measure and log performance metrics
- Test under various load conditions
- Monitor memory usage
- Validate performance requirements

## Debugging Tests

### Common Issues
1. **Timeout errors**: Increase timeout for integration tests
2. **Memory leaks**: Use `global.gc()` for garbage collection
3. **Async operations**: Ensure proper async/await usage
4. **Mock services**: Verify mock implementations

### Debug Commands
```bash
# Run specific test file
npm test -- --testPathPattern=aes-rsa-encryption

# Run with verbose output
npm run test:debug

# Run with coverage
npm test -- --coverage
```

## Contributing

When adding new tests:
1. Follow the existing test structure
2. Add appropriate test categories
3. Include both positive and negative test cases
4. Add performance tests for critical operations
5. Update this README with new test information
6. Ensure test coverage requirements are met