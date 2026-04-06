/**
 * OSS supply-chain risks — single training file covering four categories.
 *
 * SCA tools (e.g. ShiftLeft / Qwiet) resolve dependencies from the repo root
 * package.json and lockfile, not from JavaScript literals below. Use
 * ../package.json for scans that report package counts and OSS risks.
 *
 * Do not copy these patterns into production. This file is for education
 * and security review demos only.
 *
 * ---------------------------------------------------------------------------
 * 1. MALICIOUS PACKAGE — arbitrary code on install / runtime
 *    Attackers publish (or compromise) a package that runs scripts or
 *    exfiltrates data. npm lifecycle hooks (postinstall, preinstall) are
 *    a common vector.
 * ---------------------------------------------------------------------------
 * 2. ABANDONED PACKAGE — no patches, unfixed CVEs, bitrot
 *    Deprecated or unmaintained dependencies stay in your graph forever
 *    unless you replace them.
 * ---------------------------------------------------------------------------
 * 3. HIJACKABLE REPOSITORY — weak custody or unsafe resolution
 *    Examples: git over HTTP (MITM), unscoped widely-owned names, forks
 *    without pinning to immutable commits, compromised maintainer accounts.
 * ---------------------------------------------------------------------------
 * 4. TYPOSQUATTING — names look like popular packages
 *    Users mistype imports; malicious similarly-named packages run instead.
 * ---------------------------------------------------------------------------
 */

/* -------------------------------------------------------------------------- */
/* 1. MALICIOUS PACKAGE — lifecycle script (illustrative only, harmless)      */
/* -------------------------------------------------------------------------- */
// Real malicious packages use the same mechanism with harmful commands.
// package.json pattern:
//   "scripts": { "postinstall": "node ./steal-secrets.js" }
// This file uses a no-op script shape for demos:
const maliciousPackageIllustration = {
  scripts: {
    postinstall:
      "node -e \"console.log('[DEMO] Malicious packages hook install lifecycle'); process.exit(0);\"",
  },
};

/* -------------------------------------------------------------------------- */
/* 2. ABANDONED PACKAGE — deprecated / unmaintained (still resolves on npm)   */
/* -------------------------------------------------------------------------- */
const abandonedPackageIllustration = {
  dependencies: {
    // `request` is deprecated and unmaintained; prefer `fetch`, `undici`, `axios`, etc.
    request: "^2.88.2",
  },
};

/* -------------------------------------------------------------------------- */
/* 3. HIJACKABLE REPOSITORY — git+http, floating ref (branch name, not hash) */
/* -------------------------------------------------------------------------- */
const hijackableRepositoryIllustration = {
  dependencies: {
    // git+http allows MITM; #main can change without your lockfile knowing the commit
    "demo-from-insecure-vcs": "git+http://example.com/unsafe/repo.git#main",
  },
};

/* -------------------------------------------------------------------------- */
/* 4. TYPOSQUATTING — name similar to a popular package (FAKE NAME BELOW)     */
/* -------------------------------------------------------------------------- */
const typosquattingIllustration = {
  dependencies: {
    // Intentionally fake name mimicking "lodash" — do not publish a real typosquat.
    lodahs: "^9.9.9-typo-demo-only",
    // Real-world typos often target: react, express, cross-env, lodash, etc.
  },
};

/**
 * Combined package.json-shaped object for tooling demos (SBOM, policy gates).
 * Merge or split per risk in your scanner documentation.
 */
const combinedTrainingManifest = {
  name: "oss-risks-training-bundle",
  version: "0.0.0",
  private: true,
  description:
    "Training artifact: malicious lifecycle, abandoned dep, insecure git URL, typosquat-style name.",
  ...maliciousPackageIllustration,
  dependencies: {
    ...abandonedPackageIllustration.dependencies,
    ...hijackableRepositoryIllustration.dependencies,
    ...typosquattingIllustration.dependencies,
  },
};

module.exports = {
  maliciousPackageIllustration,
  abandonedPackageIllustration,
  hijackableRepositoryIllustration,
  typosquattingIllustration,
  combinedTrainingManifest,
};
