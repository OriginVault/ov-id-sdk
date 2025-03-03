import { exec } from 'child_process';
import util from 'util';

const execPromise = util.promisify(exec);

/**
 * Executes a shell script with the given arguments.
 * @param {string} scriptPath - The path to the shell script.
 * @param {string[]} args - An array of arguments to pass to the script.
 * @returns {Promise<string>} - The stdout from the script execution.
 * @throws {Error} - If the script execution fails.
 */
async function executeScript(scriptPath: string, args: string[] = []): Promise<string> {
    const command = `${scriptPath} ${args.join(' ')}`;
    try {
        const { stdout, stderr } = await execPromise(command);
        if (stderr) {
            throw new Error(`Error executing script: ${stderr}`);
        }
        return stdout;
    } catch (error: unknown) {
        if (error instanceof Error) {
            throw new Error(`Failed to execute script: ${error.message}`);
        }
        throw new Error('Failed to execute script: Unknown error');
    }
}

/**
 * Signs a commit using a shell script.
 * @param {string} commitHash - The hash of the commit to sign.
 * @returns {Promise<void>}
 */
export async function signCommit(commitHash: string): Promise<void> {
    const scriptPath = './scripts/sign-commit.sh'; // Path to your shell script
    try {
        const output = await executeScript(scriptPath, [commitHash]);
        console.log(`Commit signed successfully: ${output}`);
    } catch (error: unknown) {
        if (error instanceof Error) {
            console.error(`Failed to sign commit: ${error.message}`);
        } else {
            console.error('Failed to sign commit: Unknown error');
        }
    }
}

/**
 * Signs a release using a shell script.
 * @param {string} releaseTag - The tag of the release to sign.
 * @returns {Promise<void>}
 */
export async function signRelease(releaseTag: string): Promise<void> {
    const scriptPath = './scripts/sign-release.sh'; // Path to your shell script
    try {
        const output = await executeScript(scriptPath, [releaseTag]);
        console.log(`Release signed successfully: ${output}`);
    } catch (error: unknown) {
        if (error instanceof Error) {
            console.error(`Failed to sign release: ${error.message}`);
        } else {
            console.error('Failed to sign release: Unknown error');
        }
    }
} 