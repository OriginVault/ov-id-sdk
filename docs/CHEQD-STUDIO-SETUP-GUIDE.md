# Cheqd Studio Integration Setup Guide

## Quick Start

This guide will help you set up the integration between OV-ID-SDK and cheqd-studio in just a few steps.

## Prerequisites

- Node.js 20+ installed
- Access to both OV-ID-SDK and cheqd-studio repositories
- Basic understanding of DID and key management concepts

## Step 1: Configure OV-ID-SDK

### 1.1 Install Dependencies

```bash
cd ov-id-sdk
npm install
```

### 1.2 Set Up Security Configuration

```bash
# Run the security setup script
npm run setup-security

# This will:
# - Generate a secure master encryption key
# - Create .env file with security configuration
# - Set up required directories
```

### 1.3 Configure Environment Variables

Edit your `.env` file:

```bash
# Required security configuration
OV_MASTER_ENCRYPTION_KEY=your-generated-32-byte-hex-key
OV_ENABLE_ENVELOPE_ENCRYPTION=true
OV_ENABLE_MEMORY_PROTECTION=true
OV_KEY_ROTATION_ENABLED=true

# Cheqd Studio integration
OV_CHEQD_STUDIO_ENDPOINT=https://your-cheqd-studio.com
OV_CHEQD_STUDIO_SECRET=your-shared-secret-here
OV_ENABLE_CROSS_REPO_SYNC=true
```

## Step 2: Configure Cheqd Studio

### 2.1 Install OV-ID-SDK

```bash
cd cheqd-studio
npm install @originvault/ov-id-sdk@latest
```

### 2.2 Add Environment Variables

Add to your cheqd-studio `.env` file:

```bash
# OV-ID-SDK integration
OV_SDK_ENDPOINT=https://your-ov-sdk-instance.com
OV_SDK_SECRET=your-shared-secret-here
OV_ENABLE_SDK_INTEGRATION=true
OV_MASTER_ENCRYPTION_KEY=your-generated-32-byte-hex-key
```

### 2.3 Add API Extensions

Copy the API extensions from `ov-id-sdk/docs/cheqd-studio-api-extensions.ts` to your cheqd-studio project:

```bash
# Copy the API extensions
cp ov-id-sdk/docs/cheqd-studio-api-extensions.ts cheqd-studio/src/controllers/api/ov-sdk-integration.ts
```

### 2.4 Set Up Routes

Add to your cheqd-studio Express app:

```typescript
// In your main app file (e.g., app.ts or index.ts)
import { setupOVSDKIntegrationRoutes, validateEnvironment } from './src/controllers/api/ov-sdk-integration.js';

// Validate environment before starting
if (!validateEnvironment()) {
  console.error('❌ Environment validation failed');
  process.exit(1);
}

// Set up OV-ID-SDK integration routes
setupOVSDKIntegrationRoutes(app);

console.log('✅ OV-ID-SDK integration routes configured');
```

## Step 3: Test the Integration

### 3.1 Run Security Tests

```bash
# In ov-id-sdk directory
npm run test:security
```

### 3.2 Run Integration Example

```bash
# In ov-id-sdk directory
npx tsx examples/cheqd-studio-integration-example.ts
```

### 3.3 Test Cross-Repository Communication

```bash
# Start cheqd-studio
cd cheqd-studio
npm start

# In another terminal, test the integration
cd ov-id-sdk
npx tsx examples/cheqd-studio-integration-example.ts
```

## Step 4: Production Deployment

### 4.1 Security Checklist

- [ ] Master encryption key is securely generated and backed up
- [ ] Shared secrets are strong and unique
- [ ] TLS certificates are installed and valid
- [ ] Environment variables are properly configured
- [ ] Network connectivity between services is verified
- [ ] Security validation tests are passing

### 4.2 Monitoring Setup

```bash
# Enable detailed security logging
OV_SECURITY_LOG_LEVEL=info
OV_ENABLE_DETAILED_SECURITY_LOGS=true
OV_LOG_SECURITY_EVENTS_TO_FILE=true
```

### 4.3 Backup Configuration

```bash
# Enable automatic backups
OV_ENABLE_AUTOMATIC_BACKUP=true
OV_BACKUP_INTERVAL_HOURS=24
OV_MAX_BACKUPS_TO_KEEP=30
```

## Troubleshooting

### Common Issues

#### 1. Connection Timeout
```
Error: Connection timeout to cheqd-studio
```

**Solution:**
- Check network connectivity
- Verify endpoint URLs
- Check firewall settings
- Ensure cheqd-studio is running

#### 2. Authentication Failures
```
Error: Invalid security secret
```

**Solution:**
- Verify `OV_CHEQD_STUDIO_SECRET` matches on both sides
- Check secret format (no spaces, special characters)
- Ensure secrets are properly loaded from environment

#### 3. Encryption/Decryption Errors
```
Error: Secure decryption failed
```

**Solution:**
- Verify `OV_MASTER_ENCRYPTION_KEY` is identical on both platforms
- Check key format (64-character hex string)
- Ensure both platforms use same encryption version

#### 4. Key Sync Failures
```
Error: Key sync operation failed
```

**Solution:**
- Check cheqd-studio API endpoints are accessible
- Verify request/response formats
- Review error logs for specific details
- Ensure database/storage is properly configured

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# OV-ID-SDK
OV_SECURITY_LOG_LEVEL=debug
OV_ENABLE_DETAILED_SECURITY_LOGS=true

# Cheqd Studio
DEBUG=ov-sdk-integration
LOG_LEVEL=debug
```

## API Endpoints Reference

### OV-ID-SDK Security Bridge

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/security/encrypt` | POST | Encrypt data for cheqd-studio |
| `/api/security/decrypt` | POST | Decrypt data from cheqd-studio |
| `/api/security/sync-key` | POST | Sync key operations |
| `/api/security/rotate-key` | POST | Coordinate key rotation |
| `/api/security/validate` | GET | Security state validation |

### Cheqd Studio Integration

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/key-sync` | POST | Receive key sync operations |
| `/api/key-rotation/coordinate` | POST | Coordinate key rotation |
| `/api/security/state` | GET/POST | Security state management |

## Security Best Practices

### 1. Key Management
- Use strong, unique master encryption keys
- Rotate keys regularly (recommended: every 90 days)
- Store keys securely (HSM recommended for production)
- Never commit keys to version control

### 2. Network Security
- Use TLS 1.3 for all communications
- Implement certificate pinning
- Use VPN or private networks when possible
- Monitor network traffic for anomalies

### 3. Access Control
- Implement proper authentication
- Use least privilege principle
- Monitor and audit all access
- Regular security reviews

### 4. Data Protection
- Encrypt all sensitive data in transit and at rest
- Implement data retention policies
- Regular security audits
- Backup and recovery procedures

## Support

### Getting Help

1. **Documentation**: Check the integration guide and examples
2. **Issues**: Report issues in the GitHub repository
3. **Security**: Report security issues privately to security@originvault.box

### Regular Maintenance

- **Weekly**: Review security logs and sync status
- **Monthly**: Security validation reports and performance optimization
- **Quarterly**: Comprehensive security audit and disaster recovery testing

---

This setup guide provides a quick path to getting OV-ID-SDK and cheqd-studio working together securely. For more detailed information, see the full integration guide and examples.
