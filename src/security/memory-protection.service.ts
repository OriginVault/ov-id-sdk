export class MemoryProtectionService {
  private static instance: MemoryProtectionService;
  private sensitiveBuffers: Set<Buffer> = new Set();
  private cleanupInterval: NodeJS.Timeout;

  private constructor() {
    // Set up automatic cleanup every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.performCleanup();
    }, 5 * 60 * 1000);
  }

  public static getInstance(): MemoryProtectionService {
    if (!MemoryProtectionService.instance) {
      MemoryProtectionService.instance = new MemoryProtectionService();
    }
    return MemoryProtectionService.instance;
  }

  public registerSensitiveBuffer(buffer: Buffer): void {
    this.sensitiveBuffers.add(buffer);
  }

  public zeroizeBuffer(buffer: Buffer): void {
    if (buffer && typeof buffer.fill === 'function') {
      buffer.fill(0);
    }
    this.sensitiveBuffers.delete(buffer);
  }

  public performCleanup(): void {
    let cleanedCount = 0;
    for (const buffer of this.sensitiveBuffers) {
      if (buffer && typeof buffer.fill === 'function') {
        buffer.fill(0);
        cleanedCount++;
      }
    }
    this.sensitiveBuffers.clear();
    
    if (cleanedCount > 0) {
      console.log(`🧹 Cleaned ${cleanedCount} sensitive buffers from memory`);
    }
  }

  public shutdown(): void {
    clearInterval(this.cleanupInterval);
    this.performCleanup();
  }
}