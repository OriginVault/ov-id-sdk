#!/usr/bin/env node

/**
 * OV-ID-SDK Security Setup Script
 * 
 * This script helps users configure their security environment
 * for the enhanced OV-ID-SDK with enterprise-grade security features.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('🔐 OV-ID-SDK Security Setup');
console.log('============================\n');

// Generate a secure master encryption key
function generateMasterKey() {
  return crypto.randomBytes(32).toString('hex');
}

// Check if .env file exists
const envPath = path.join(__dirname, '..', '.env');
const templatePath = path.join(__dirname, '..', 'security.env.template');

if (!fs.existsSync(envPath)) {
  console.log('📝 Creating .env file from template...');
  
  if (fs.existsSync(templatePath)) {
    const template = fs.readFileSync(templatePath, 'utf8');
    const masterKey = generateMasterKey();
    
    // Replace placeholder with generated key
    const envContent = template.replace('your-32-byte-hex-key-here', masterKey);
    
    fs.writeFileSync(envPath, envContent);
    console.log('✅ .env file created successfully!');
    console.log(`🔑 Generated master encryption key: ${masterKey.substring(0, 8)}...`);
    console.log('⚠️  IMPORTANT: Keep this key secure and backed up!');
  } else {
    console.log('❌ Security template not found. Please create .env manually.');
    process.exit(1);
  }
} else {
  console.log('📄 .env file already exists.');
  
  // Check if master key is configured
  const envContent = fs.readFileSync(envPath, 'utf8');
  if (envContent.includes('your-32-byte-hex-key-here')) {
    console.log('⚠️  Master encryption key not configured!');
    console.log('🔧 Updating with generated key...');
    
    const masterKey = generateMasterKey();
    const updatedContent = envContent.replace('your-32-byte-hex-key-here', masterKey);
    fs.writeFileSync(envPath, updatedContent);
    
    console.log('✅ Master encryption key configured!');
    console.log(`🔑 Generated key: ${masterKey.substring(0, 8)}...`);
  } else {
    console.log('✅ Master encryption key already configured.');
  }
}

// Create logs directory
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
  console.log('📁 Created logs directory');
}

// Create backups directory
const backupsDir = path.join(__dirname, '..', 'backups', 'security');
if (!fs.existsSync(backupsDir)) {
  fs.mkdirSync(backupsDir, { recursive: true });
  console.log('📁 Created backups directory');
}

console.log('\n🎉 Security setup completed!');
console.log('\n📋 Next steps:');
console.log('1. Review and customize your .env file');
console.log('2. Set up cheqd-studio integration (if applicable)');
console.log('3. Run security validation: npm run test:security');
console.log('4. Start using the enhanced security features!');
console.log('\n📚 Documentation: See SECURITY-ENHANCEMENT-PLAN.md for details');
