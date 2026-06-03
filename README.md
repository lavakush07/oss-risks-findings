# OSS Risks Findings Test Repository

A multi-language test application with all four OSS supply-chain risks injected for SCA scanner validation.

**Reference:** Based on [shiftleft-js-demo commit 85c2e1d](https://github.com/ShiftLeftSecurity/shiftleft-js-demo/commit/85c2e1dc2a8c8d5cb899b719a71dfdaa55504578)

## OSS Risk Coverage Matrix

| Risk | VulnCheck Attribute | Supported Ecosystems | Covered In This Repo |
|------|---------------------|----------------------|----------------------|
| **Malicious** | `is_malicious` | gem, npm, nuget, pypi | ✅ npm, nuget, ruby |
| **Abandoned** | `abandoned` | golang | ✅ golang |
| **Hijackable Repository** | `repo_hijackable` | golang | ✅ golang |
| **Squatted** | `squatted_package` | gem, golang, npm, nuget, pypi | ✅ All five |
| **End of Life** | EOL risk score ≥ 60 | npm, maven, pypi | ✅ npm, maven, pypi |

## Injected Packages by Risk Type

### 1. Malicious (`is_malicious`)

| Ecosystem | Package | File |
|-----------|---------|------|
| npm | `aliyundrive@6.0.4` | `package.json` |
| npm | `local-malicious-lifecycle` (postinstall hook) | `package.json` |
| nuget | `Colorful.Console.Helper@1.0.0` | `ecosystems/dotnet/OssRiskDemo.csproj` |
| ruby | `malicious_lifecycle` (local gem) | `ecosystems/ruby/Gemfile` |

### 2. Abandoned (`abandoned`)

| Ecosystem | Package | File |
|-----------|---------|------|
| golang | `github.com/paysuper/paysuper-reporter@v1.4.2` | `go.mod` |
| npm | `request@^2.88.2` (deprecated) | `package.json` |

### 3. Hijackable Repository (`repo_hijackable`)

| Ecosystem | Package | File |
|-----------|---------|------|
| golang | `github.com/zerobounty/tile38-client@v0.10.2` | `go.mod` |
| npm | `inherits-insecure-git-demo` (git+http) | `package.json` |
| pypi | `sampleproject @ git+http://...` | `ecosystems/python/requirements.txt` |

### 4. Squatted / Typosquatting (`squatted_package`)

| Ecosystem | Typosquat | Target | File |
|-----------|-----------|--------|------|
| npm | `expres@0.0.5` | express | `package.json` |
| gem | `activmodel@5.2.1` | activemodel | `ecosystems/ruby/Gemfile` |
| gem | `raills@0.0.1` | rails | `ecosystems/ruby/Gemfile` |
| nuget | `Newtonsoftjson@13.0.1` | Newtonsoft.Json | `ecosystems/dotnet/OssRiskDemo.csproj` |
| pypi | `numpyy@0.1.0` | numpy | `ecosystems/python/requirements.txt` |
| pypi | `reqeusts` | requests | `ecosystems/python/requirements.txt` |
| golang | `github.com/aboringcompany/boringssl` | boringssl | `go.mod` |

### 5. End of Life (EOL)

| Ecosystem | Package | File |
|-----------|---------|------|
| npm | `express-eol` → `express@3.21.2` | `package.json` |
| npm | `connect@2.30.2` | `package.json` |
| npm | `node-uuid@1.4.8` | `package.json` |
| npm | `gulp@3.9.1` | `package.json` |
| pypi | `Django==1.11.29` | `ecosystems/python/requirements.txt` |
| pypi | `Flask==0.12.5` | `ecosystems/python/requirements.txt` |
| pypi | `cryptography==2.3.1` | `ecosystems/python/requirements.txt` |
| maven | `log4j:log4j:1.2.17` | `ecosystems/java/pom.xml` |
| maven | `spring-core:3.2.18.RELEASE` | `ecosystems/java/pom.xml` |
| maven | `struts-core:1.3.10` | `ecosystems/java/pom.xml` |

## Directory Structure

```
oss-risks-findings/
├── package.json              # npm: malicious, abandoned, hijackable, squatted
├── go.mod                    # golang: abandoned, hijackable, squatted
├── ecosystems/
│   ├── dotnet/
│   │   └── OssRiskDemo.csproj  # nuget: malicious, squatted
│   ├── java/
│   │   └── pom.xml             # maven: end of life
│   ├── golang/
│   │   └── go.mod              # golang risks (duplicate of root)
│   ├── npm/
│   │   └── local-malicious-lifecycle/  # npm: malicious (postinstall)
│   ├── python/
│   │   └── requirements.txt    # pypi: hijackable, squatted
│   └── ruby/
│       └── Gemfile             # gem: malicious, squatted
├── vulncheck_purl_catalog.json  # PURL examples for VulnCheck API
└── oss_risks_all_four.js        # Documentation and training module
```

## ShiftLeft / Qwiet Scan Info

- **Org ID:** `eba14690-d605-4f85-b5e3-b2992e9174b0`
- **Project:** `oss-risks-demo`
- **Findings:** https://app.shiftleft.io/apps/oss-risks-demo/scans/2/findings?status=unset&type=oss_risk

## Notes

- **Do not `npm install` or `go get`** — some packages are genuinely malicious
- VulnCheck only tracks **Hijackable Repository** for golang (npm/pypi git+http examples are illustrative)
- VulnCheck only tracks **Abandoned** for golang
- See `vulncheck_purl_catalog.json` for PURL query examples
