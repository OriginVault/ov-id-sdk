import { DataSource } from 'typeorm';
import { Entities } from '@veramo/data-store';

/**
 * Configuration options for private key database storage
 */
export interface PrivateKeyDatabaseConfig {
    host: string;
    port: number;
    username: string;
    password: string;
    database: string;
    ssl?: boolean;
    synchronize?: boolean;
    logging?: boolean;
}

/**
 * Creates a TypeORM DataSource configured for private key storage
 * This provides persistent, encrypted storage similar to cheqd-studio
 */
export function createPrivateKeyDatabase(config: PrivateKeyDatabaseConfig): DataSource {
    const {
        host,
        port,
        username,
        password,
        database,
        ssl = true,
        synchronize = false, // Set to true only in development
        logging = false
    } = config;

    return new DataSource({
        type: 'postgres',
        host,
        port,
        username,
        password,
        database,
        ssl: ssl ? { rejectUnauthorized: false } : false,
        synchronize, // Be careful with this in production
        logging,
        entities: Entities,
        migrations: [],
        subscribers: [],
        // Add connection pooling for better performance
        extra: {
            max: 10, // Maximum number of connections in pool
            min: 2,  // Minimum number of connections in pool
            idle_timeout_millis: 30000,
            connection_timeout_millis: 2000,
        }
    });
}

/**
 * Creates a database configuration from environment variables
 * Similar to how cheqd-studio configures its database
 */
export function createDatabaseConfigFromEnv(): PrivateKeyDatabaseConfig | null {
    const host = process.env.POSTGRES_HOST || process.env.DB_HOST;
    const username = process.env.POSTGRES_USER || process.env.DB_USER;
    const password = process.env.POSTGRES_PASSWORD || process.env.DB_PASSWORD;
    const database = process.env.POSTGRES_DB || process.env.DB_NAME;
    const port = parseInt(process.env.POSTGRES_PORT || process.env.DB_PORT || '5432');

    // Check if all required variables are present
    if (!host || !username || !password || !database) {
        console.log('🔍 Database environment variables not found, using in-memory storage');
        return null;
    }

    return {
        host,
        port,
        username,
        password,
        database,
        ssl: process.env.DB_SSL === 'true' || process.env.NODE_ENV === 'production',
        synchronize: process.env.DB_SYNCHRONIZE === 'true' || process.env.NODE_ENV === 'development',
        logging: process.env.DB_LOGGING === 'true'
    };
}

/**
 * Helper function to initialize database connection for private key storage
 */
export async function initializePrivateKeyDatabase(): Promise<DataSource | null> {
    try {
        const config = createDatabaseConfigFromEnv();
        
        if (!config) {
            return null;
        }

        console.log('🔌 Connecting to private key database...');
        const dataSource = createPrivateKeyDatabase(config);
        await dataSource.initialize();
        
        console.log('✅ Private key database connected successfully');
        console.log(`📊 Database: ${config.database}@${config.host}:${config.port}`);
        
        return dataSource;
    } catch (error) {
        console.error('❌ Failed to connect to private key database:', error);
        console.log('⚠️  Falling back to in-memory storage');
        return null;
    }
}
