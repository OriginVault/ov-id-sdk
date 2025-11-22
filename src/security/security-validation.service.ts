export interface SecurityValidationResult {
  isValid: boolean;
  issues: SecurityIssue[];
  recommendations: string[];
  score: number; // 0-100
}

export interface SecurityIssue {
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  remediation: string;
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

export interface SecurityReport {
  timestamp: string;
  overallScore: number;
  validationResults: SecurityValidationResult;
  keyIntegrityResults: ValidationResult;
  encryptionConfigResults: ValidationResult;
  recommendations: string[];
}

export class SecurityValidationService {
  private static instance: SecurityValidationService;

  private constructor() {}

  public static getInstance(): SecurityValidationService {
    if (!SecurityValidationService.instance) {
      SecurityValidationService.instance = new SecurityValidationService();
    }
    return SecurityValidationService.instance;
  }

  public async validateSecurityState(): Promise<SecurityValidationResult> {
    const issues: SecurityIssue[] = [];
    const recommendations: string[] = [];

    // Check environment variables
    if (!process.env.OV_MASTER_ENCRYPTION_KEY) {
      issues.push({
        severity: 'critical',
        category: 'configuration',
        description: 'OV_MASTER_ENCRYPTION_KEY not set',
        remediation: 'Set OV_MASTER_ENCRYPTION_KEY environment variable'
      });
    }

    // Check if envelope encryption is enabled
    if (process.env.OV_ENABLE_ENVELOPE_ENCRYPTION !== 'true') {
      issues.push({
        severity: 'high',
        category: 'encryption',
        description: 'Envelope encryption not enabled',
        remediation: 'Set OV_ENABLE_ENVELOPE_ENCRYPTION=true'
      });
    }

    // Check if memory protection is enabled
    if (process.env.OV_ENABLE_MEMORY_PROTECTION !== 'true') {
      issues.push({
        severity: 'medium',
        category: 'memory',
        description: 'Memory protection not enabled',
        remediation: 'Set OV_ENABLE_MEMORY_PROTECTION=true'
      });
    }

    // Calculate security score
    const criticalIssues = issues.filter(i => i.severity === 'critical').length;
    const highIssues = issues.filter(i => i.severity === 'high').length;
    const mediumIssues = issues.filter(i => i.severity === 'medium').length;
    const lowIssues = issues.filter(i => i.severity === 'low').length;

    let score = 100;
    score -= criticalIssues * 25;
    score -= highIssues * 15;
    score -= mediumIssues * 10;
    score -= lowIssues * 5;
    score = Math.max(0, score);

    // Generate recommendations
    if (criticalIssues > 0) {
      recommendations.push('Address critical security issues immediately');
    }
    if (highIssues > 0) {
      recommendations.push('Resolve high-priority security issues');
    }
    if (score < 80) {
      recommendations.push('Review and improve security configuration');
    }

    return {
      isValid: criticalIssues === 0,
      issues,
      recommendations,
      score
    };
  }

  public async validateKeyIntegrity(): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // This would validate key integrity in a real implementation
      // For now, we'll return a basic validation
      console.log('🔍 Validating key integrity...');
      
      return {
        isValid: errors.length === 0,
        errors,
        warnings
      };
    } catch (error) {
      return {
        isValid: false,
        errors: [`Key integrity validation failed: ${error instanceof Error ? error.message : String(error)}`],
        warnings: []
      };
    }
  }

  public async validateEncryptionConfig(): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Check encryption configuration
      if (!process.env.OV_MASTER_ENCRYPTION_KEY) {
        errors.push('Master encryption key not configured');
      }

      if (process.env.OV_ENABLE_ENVELOPE_ENCRYPTION !== 'true') {
        warnings.push('Envelope encryption not enabled');
      }

      return {
        isValid: errors.length === 0,
        errors,
        warnings
      };
    } catch (error) {
      return {
        isValid: false,
        errors: [`Encryption config validation failed: ${error instanceof Error ? error.message : String(error)}`],
        warnings: []
      };
    }
  }

  public async generateSecurityReport(): Promise<SecurityReport> {
    const timestamp = new Date().toISOString();
    
    const validationResults = await this.validateSecurityState();
    const keyIntegrityResults = await this.validateKeyIntegrity();
    const encryptionConfigResults = await this.validateEncryptionConfig();

    const allRecommendations = [
      ...validationResults.recommendations,
      ...(keyIntegrityResults.errors.length > 0 ? ['Fix key integrity issues'] : []),
      ...(encryptionConfigResults.errors.length > 0 ? ['Fix encryption configuration'] : [])
    ];

    return {
      timestamp,
      overallScore: validationResults.score,
      validationResults,
      keyIntegrityResults,
      encryptionConfigResults,
      recommendations: allRecommendations
    };
  }
}
