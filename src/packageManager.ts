import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import ignore from 'ignore'; // npm install ignore
import tar from 'tar-stream'; // npm install tar-stream
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getIgnoreFilter(packagePath: string) {
    const npmIgnoreFile = path.join(packagePath, ".npmignore");
    const gitIgnoreFile = path.join(packagePath, ".gitignore");
    let ignoreRules: string[] = [];

    if (fs.existsSync(npmIgnoreFile)) {
        ignoreRules = fs.readFileSync(npmIgnoreFile, "utf-8").split("\n").map(line => line.trim()).filter(Boolean);
    } else if (fs.existsSync(gitIgnoreFile)) {
        ignoreRules = fs.readFileSync(gitIgnoreFile, "utf-8").split("\n").map(line => line.trim()).filter(Boolean);
    }

    return ignore().add(ignoreRules);
}

/**
 * Collects all installed files while respecting .npmignore and .gitignore.
 * @param {string} packagePath - The package directory.
 * @returns {Set<string>} - Set of all included files.
 */
function getInstalledFiles(packagePath) {
  const ignoreFilter = getIgnoreFilter(packagePath);
  let installedFiles = new Set();

  function walkDir(dir) {
    fs.readdirSync(dir).forEach((file) => {
      const fullPath = path.join(dir, file);
      const relativePath = path.relative(packagePath, fullPath);

      if (relativePath === "" || ignoreFilter.ignores(relativePath)) return;

      if (fs.statSync(fullPath).isDirectory()) {
        walkDir(fullPath);
      } else {
        installedFiles.add(relativePath);
      }
    });
  }

  walkDir(packagePath);
  return installedFiles;
}

/**
 * Compares the computed bundle hash with the one stored in package.json.
 * @param {string} packagePath - The package directory.
 */
async function verifyBundleHash(packagePath) {
  const packageJsonPath = path.join(packagePath, "package.json");
  if (!fs.existsSync(packageJsonPath)) {
    console.error(`❌ package.json not found in ${packagePath}`);
    return;
  }

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
  if (!packageJson.bundleHash) {
    console.error(`⚠ No "bundleHash" found in ${packagePath}/package.json`);
    return;
  }

  console.log(`\n🔍 Verifying package integrity for ${packageJson.name}...`);

  const computedHash = await createBundleHash(packagePath);
  const expectedHash = packageJson.bundleHash;

  if (computedHash === expectedHash) {
    console.log(`✅ Integrity verified! Hash matches: ${computedHash}`);
  } else {
    console.error(`❌ Integrity check failed!`);
    console.error(`  Expected: ${expectedHash}`);
    console.error(`  Computed: ${computedHash}`);
    process.exit(1); // Exit process on failure
  }
}

/**
 * Creates a SHA-256 hash of the installed package files for DID derivation.
 * @param {string} packagePath - The package directory.
 * @returns {Promise<string>} - SHA-256 hash of the package.
 */
async function createBundleHash(packagePath: string): Promise<{ hash: string, files: string[] }> {
  const files: any[] = [...getInstalledFiles(packagePath)];
  const pack = tar.pack(); // Use tar-stream for in-memory tarball
  const hash = crypto.createHash("sha256");

  // Hash tarball content
  return new Promise<{ hash: string, files: string[] } >(async (resolve, reject) => {
    try {
      // Pipe tar pack to the hash stream
      const tarStream = pack.pipe(hash);

      // Add files to the tar pack
      for (const file of files) {
        const fullPath = path.join(packagePath, file as string);
        
        const content = fs.readFileSync(fullPath); // Read as Buffer for both binary & text
        pack.entry(
            {
                name: file,
                mode: 0o644, // Set consistent file permissions
                mtime: new Date(0), // Normalize timestamps
                uid: 0,
                gid: 0,
            },
            content
        );
      }

      pack.finalize(); // Finalize the tar stream

      // Wait for the tar stream to finish hashing
      tarStream.on("finish", () => resolve({ hash: hash.digest("hex"), files: files }));
      tarStream.on("error", reject);
    } catch (error) {
      reject(error);
    }
  });
}

function getPrivateKeyFromBundleHash(bundleHash: string): Uint8Array {
    const hashBuffer = crypto.createHash('sha256').update(bundleHash).digest();
    return new Uint8Array(hashBuffer.subarray(0, 32));
} 

async function getPrivateKeyFromBundle(packagePath: string): Promise<Uint8Array> {
    const bundleHash = await createBundleHash(packagePath);
    return getPrivateKeyFromBundleHash(bundleHash.hash);
}

async function getSelfBundleHash(): Promise<{ hash: string, files: string[] }> {
    const packagePath = path.resolve(__dirname, '..');
    const bundleHash = await createBundleHash(`${packagePath}`);
    return bundleHash;
}

async function getSelfBundlePrivateKey(): Promise<{ key: Uint8Array, hash: string, files: string[] }> {
    const bundleHash = await getSelfBundleHash();
    return { key: getPrivateKeyFromBundleHash(bundleHash.hash), hash: bundleHash.hash, files: bundleHash.files };
}

async function getPackageDIDFromPackageJson(): Promise<string> {
    const packageJsonPath = path.join(__dirname, '..', 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    return packageJson.did;
}

async function getParentBundleHash(): Promise<{ hash: string, files: string[] }> {
    const packagePath = path.resolve(__dirname, '../../../');
    const bundleHash = await createBundleHash(`${packagePath}`);
    return bundleHash;
}

async function getParentBundlePrivateKey(): Promise<{ key: Uint8Array, hash: string, files: string[] }> {
    const bundleHash = await getParentBundleHash();
    return { key: getPrivateKeyFromBundleHash(bundleHash.hash), hash: bundleHash.hash, files: bundleHash.files };
}

async function getParentDIDFromPackageJson(): Promise<string> {
    const packageJsonPath = path.join(__dirname, '../../../', 'package.json');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    return packageJson.parentDid;
}

export { 
  verifyBundleHash, 
  getPrivateKeyFromBundleHash, 
  getPrivateKeyFromBundle, 
  getSelfBundleHash, 
  getSelfBundlePrivateKey, 
  getPackageDIDFromPackageJson,
  getParentDIDFromPackageJson,
  getParentBundleHash,
  getParentBundlePrivateKey
};
