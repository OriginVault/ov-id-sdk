#!/usr/bin/env node

/**
 * Test Runner Script for OV-ID-SDK
 * 
 * This script provides a convenient way to run different test suites
 * with various configurations and options.
 */

const { execSync } = require('child_process');
const path = require('path');

// ANSI color codes for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function runCommand(command, description) {
  log(`\n${colors.cyan}${description}${colors.reset}`);
  log(`${colors.yellow}Running: ${command}${colors.reset}\n`);
  
  try {
    execSync(command, { 
      stdio: 'inherit',
      cwd: process.cwd()
    });
    log(`${colors.green}✅ ${description} completed successfully${colors.reset}`);
    return true;
  } catch (error) {
    log(`${colors.red}❌ ${description} failed${colors.reset}`);
    return false;
  }
}

function showHelp() {
  log(`${colors.bright}OV-ID-SDK Test Runner${colors.reset}\n`);
  log('Usage: node scripts/run-tests.js [options]\n');
  log('Options:');
  log('  --all, -a           Run all tests');
  log('  --unit, -u          Run unit tests only');
  log('  --integration, -i   Run integration tests only');
  log('  --security, -s      Run security tests only');
  log('  --performance, -p   Run performance tests only');
  log('  --coverage, -c      Run tests with coverage');
  log('  --watch, -w         Run tests in watch mode');
  log('  --debug, -d         Run tests in debug mode');
  log('  --ci                Run tests in CI mode');
  log('  --help, -h          Show this help message\n');
  log('Examples:');
  log('  node scripts/run-tests.js --all');
  log('  node scripts/run-tests.js --unit --coverage');
  log('  node scripts/run-tests.js --security --watch');
  log('  node scripts/run-tests.js --performance --debug');
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    showHelp();
    return;
  }
  
  let testCommand = 'jest';
  let testArgs = [];
  let description = 'Running tests';
  
  // Parse arguments
  if (args.includes('--all') || args.includes('-a')) {
    testArgs.push('--testPathPattern=__tests__');
    description = 'Running all tests';
  } else if (args.includes('--unit') || args.includes('-u')) {
    testArgs.push('--testPathPattern=unit');
    description = 'Running unit tests';
  } else if (args.includes('--integration') || args.includes('-i')) {
    testArgs.push('--testPathPattern=integration');
    description = 'Running integration tests';
  } else if (args.includes('--security') || args.includes('-s')) {
    testArgs.push('--testPathPattern=security');
    description = 'Running security tests';
  } else if (args.includes('--performance') || args.includes('-p')) {
    testArgs.push('--testPathPattern=performance');
    description = 'Running performance tests';
  }
  
  // Add additional options
  if (args.includes('--coverage') || args.includes('-c')) {
    testArgs.push('--coverage');
    description += ' with coverage';
  }
  
  if (args.includes('--watch') || args.includes('-w')) {
    testArgs.push('--watch');
    description += ' in watch mode';
  }
  
  if (args.includes('--debug') || args.includes('-d')) {
    testArgs.push('--detectOpenHandles', '--forceExit', '--verbose');
    description += ' in debug mode';
  }
  
  if (args.includes('--ci')) {
    testArgs.push('--ci', '--coverage', '--watchAll=false');
    description += ' in CI mode';
  }
  
  // Build final command
  const finalCommand = `${testCommand} ${testArgs.join(' ')}`;
  
  // Run the tests
  const success = runCommand(finalCommand, description);
  
  if (success) {
    log(`\n${colors.green}${colors.bright}🎉 All tests completed successfully!${colors.reset}`);
  } else {
    log(`\n${colors.red}${colors.bright}💥 Some tests failed. Please check the output above.${colors.reset}`);
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  log(`${colors.red}Uncaught Exception: ${error.message}${colors.reset}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  log(`${colors.red}Unhandled Rejection at: ${promise}, reason: ${reason}${colors.reset}`);
  process.exit(1);
});

main();












