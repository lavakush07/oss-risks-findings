/**
 * OSS supply-chain risks — single training file covering four categories.
 *
 * SCA tools (e.g. ShiftLeft / Qwiet) resolve dependencies from manifests (repo root
 * package.json, ecosystems/golang, etc.), not from JavaScript literals below.
 *
 * VulnCheck: four OSS risk labels and supported ecosystems (see vulncheck_purl_catalog.json
 * and https://docs.vulncheck.com/products/exploit-and-vulnerability-intelligence/package-url-detections ).
 * Exported as OSS_RISK_SUPPORTED_ECOSYSTEMS below.
 *
 * If SCA shows zero findings: ensure the scan uses root package.json + package-lock.json
 * (tiny graphs like lodash+expres alone often have no CVEs). request + lockfile restores
 * a typical vulnerable transitive set for OSS vulnerability findings.
 *
 * ShiftLeft / Qwiet UI (Findings):
 * - The count on the Findings tab often reflects OSS CVEs / other finding types,
 *   not necessarily rows labeled with every OSS Risk sub-type (Abandoned,
 *   Malicious, Squatted, Hijackable repository).
 * - If you select several OSS Risk checkboxes and see "0 results", try: clear
 *   OSS Risk filters and use one category at a time (some UIs combine filters
 *   as AND). Click the Findings tab title to reset filters (per Qwiet docs).
 * - Also check Finding Type (e.g. OSS Vulnerabilities vs OSS Risk) so it is
 *   not excluding the rows you expect.
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

/** @type {Record<string, readonly string[]>} UI / policy labels → package ecosystems VulnCheck documents for that risk. */
const OSS_RISK_SUPPORTED_ECOSYSTEMS = Object.freeze({
  Abandoned: Object.freeze(["golang"]),
  Malicious: Object.freeze(["gem", "npm", "nuget", "pypi"]),
  Squatted: Object.freeze(["gem", "golang", "npm", "nuget", "pypi"]),
  "Hijackable Repository": Object.freeze(["golang"]),
});

/** Maps catalog keys to the same labels (for JSON `oss_risks[].label`). */
const OSS_RISK_LABEL_BY_ATTRIBUTE = Object.freeze({
  abandoned: "Abandoned",
  is_malicious: "Malicious",
  squatted_package: "Squatted",
  repo_hijackable: "Hijackable Repository",
});

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
/*    VulnCheck attribute: abandoned (golang only)                            */
/*    Example PURL: pkg:golang/github.com/paysuper/paysuper-reporter@v1.4.2   */
/*    See: ecosystems/golang/go.mod                                           */
/* -------------------------------------------------------------------------- */
const abandonedPackageIllustration = {
  dependencies: {
    // `request` is deprecated and unmaintained; prefer `fetch`, `undici`, `axios`, etc.
    request: "^2.88.2",
  },
  // golang: github.com/paysuper/paysuper-reporter v1.4.2 (in ecosystems/golang/go.mod)
};

/* -------------------------------------------------------------------------- */
/* 3. HIJACKABLE REPOSITORY — weak custody or unsafe resolution               */
/*    VulnCheck attribute: repo_hijackable (golang only)                      */
/*    Example PURL: pkg:golang/github.com/zerobounty/tile38-client@v0.10.2    */
/*    See: ecosystems/golang/go.mod                                           */
/* -------------------------------------------------------------------------- */
const hijackableRepositoryIllustration = {
  dependencies: {
    // git+http allows MITM; #main can change without your lockfile knowing the commit
    "demo-from-insecure-vcs": "git+http://example.com/unsafe/repo.git#main",
  },
  // golang: github.com/zerobounty/tile38-client v0.10.2 (in ecosystems/golang/go.mod)
};

/* -------------------------------------------------------------------------- */
/* 4. TYPOSQUATTING — names look like popular packages                        */
/*    VulnCheck attribute: squatted_package                                   */
/*    Supported: gem, golang, npm, nuget, pypi                                */
/*    Examples:                                                               */
/*      - npm: expres → express (root package.json)                           */
/*      - gem: activmodel → activemodel, raills → rails (ecosystems/ruby)     */
/*      - nuget: Newtonsoftjson → Newtonsoft.Json (ecosystems/dotnet)         */
/*      - pypi: numpyy → numpy, reqeusts → requests (ecosystems/python)       */
/* -------------------------------------------------------------------------- */
const typosquattingIllustration = {
  dependencies: {
    // Intentionally fake name mimicking "lodash" — do not publish a real typosquat.
    lodahs: "^9.9.9-typo-demo-only",
    // npm: expres → express (root package.json)
    expres: "^4.17.1",
    // gem: activmodel → activemodel, raills → rails (ecosystems/ruby)
    activmodel: "^6.1.3",
    raills: "^6.1.3",
    // nuget: Newtonsoftjson → Newtonsoft.Json (ecosystems/dotnet)
    Newtonsoftjson: "^13.0.1",
    // pypi: numpyy → numpy, reqeusts → requests (ecosystems/python)
    numpyy: "^1.20.0",
    reqeusts: "^2.25.1",
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
  OSS_RISK_SUPPORTED_ECOSYSTEMS,
  OSS_RISK_LABEL_BY_ATTRIBUTE,
  maliciousPackageIllustration,
  abandonedPackageIllustration,
  hijackableRepositoryIllustration,
  typosquattingIllustration,
  combinedTrainingManifest,
};
