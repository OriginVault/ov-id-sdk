#!/usr/bin/env node

/**
 * Example: Using PostgreSQL Database for Private Key Storage
 * 
 * This example shows how to configure the ov-id-sdk to use a PostgreSQL database
 * for persistent, encrypted private key storage instead of in-memory storage.
 * 
 * This approach is similar to how cheqd-studio handles private key storage.
 */

import { 
    initializePrivateKeyStorage, 
    createOVAgent, 
    createCheqdProvider, 
    CheqdNetwork,
    createDatabaseConfigFromEnv 
} from '../dist/index.js';

async function main() {
    console.log('🔐 Database Private Key Storage Example\n');
    
    // Method 1: Automatic initialization from environment variables
    console.log('Method 1: Auto-initialization from environment variables');
    console.log('Required environment variables:');
    console.log('- POSTGRES_HOST or DB_HOST');
    console.log('- POSTGRES_PORT or DB_PORT (default: 5432)');
    console.log('- POSTGRES_USER or DB_USER');
    console.log('- POSTGRES_PASSWORD or DB_PASSWORD');
    console.log('- POSTGRES_DB or DB_NAME');
    console.log('- PRIVATE_KEY_ENCRYPTION_SECRET (for encryption)\n');
    
    try {
        // Initialize database storage automatically
        const dbConnection = await initializePrivateKeyStorage();
        
        if (dbConnection) {
            console.log('✅ Database storage initialized successfully!');
            
            // Create agent with database-backed private key storage
            const provider = createCheqdProvider(
                CheqdNetwork.Testnet, 
                'test-seed', 
                'https://rpc.cheqd.network'
            );
            
            const agent = createOVAgent({
                cheqdProvider: provider,
                universalResolver: {},
                dbConnection // This will use the database for both key store and private key store
            });
            
            console.log('🎉 Agent created with database-backed private key storage!');
            console.log('📊 Private keys will be stored encrypted in PostgreSQL');
            
            // Clean up
            await dbConnection.destroy();
            
        } else {
            console.log('⚠️  No database configuration found, using in-memory storage');
            console.log('💡 Set database environment variables to enable persistent storage');
        }
        
    } catch (error) {
        console.error('❌ Error:', error);
    }
}

// Method 2: Manual configuration example
async function manualConfigurationExample() {
    console.log('\n🔧 Method 2: Manual database configuration');
    
    try {
        const { createPrivateKeyDatabase } = await import('../dist/database-config.js');
        
        // Manual database configuration
        const dbConfig = {
            host: 'localhost',
            port: 5432,
            username: 'postgres',
            password: 'your-password',
            database: 'originvault_keys',
            ssl: false, // Set to true in production
            synchronize: true, // Only in development
            logging: false
        };
        
        console.log('📝 Manual configuration:', dbConfig);
        
        // Create and initialize database connection
        const dataSource = createPrivateKeyDatabase(dbConfig);
        await dataSource.initialize();
        
        console.log('✅ Manual database connection successful!');
        
        // Create agent with manual database configuration
        const provider = createCheqdProvider(
            CheqdNetwork.Testnet, 
            'test-seed', 
            'https://rpc.cheqd.network'
        );
        
        const agent = createOVAgent({
            cheqdProvider: provider,
            universalResolver: {},
            dbConnection: dataSource
        });
        
        console.log('🎉 Agent created with manual database configuration!');
        
        // Clean up
        await dataSource.destroy();
        
    } catch (error) {
        console.error('❌ Manual configuration error:', error);
    }
}

// Run examples
main().then(() => {
    return manualConfigurationExample();
}).then(() => {
    console.log('\n🏁 Examples completed!');
    console.log('\n💡 Benefits of database storage:');
    console.log('   - Persistent storage (survives restarts)');
    console.log('   - Encrypted at rest');
    console.log('   - Scalable and reliable');
    console.log('   - Similar to cheqd-studio architecture');
    console.log('   - Production-ready security');
}).catch(console.error);
