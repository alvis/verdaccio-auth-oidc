<div align="center">

<img src="./assets/icon.svg" alt="verdaccio-auth-oidc logo" width="220" />

# verdaccio-auth-oidc

[![npm](https://img.shields.io/npm/dm/verdaccio-auth-oidc?style=flat-square)](https://www.npmjs.com/package/verdaccio-auth-oidc)
[![build](https://img.shields.io/github/actions/workflow/status/alvis/verdaccio-auth-oidc/main.yaml?style=flat-square)](https://github.com/alvis/verdaccio-auth-oidc/actions)
[![dependencies](https://img.shields.io/librariesio/release/npm/verdaccio-auth-oidc?style=flat-square)](https://libraries.io/npm/verdaccio-auth-oidc)
[![license](https://img.shields.io/github/license/alvis/verdaccio-auth-oidc.svg?style=flat-square)](https://github.com/alvis/verdaccio-auth-oidc/blob/main/LICENSE)

**Keyless CI publishing for Verdaccio** — authenticate CI/CD runners with their platform's short-lived OIDC ID token instead of a shared static password.

_Verifies tokens against each issuer's public JWKS and maps verified claims to per-repository or organization-wide Verdaccio identities._

</div>

> 🚧 **Under construction.** This package is scaffolded but not implemented yet. The configuration and behavior below describe the planned design and may change before the first release.

---

## ⚡ Quick Start

```bash
# npm
npm install verdaccio-auth-oidc
# pnpm
pnpm add verdaccio-auth-oidc
# yarn
yarn add verdaccio-auth-oidc
```

Register the plugin under `auth:` in Verdaccio's `config.yaml`, beside the auth plugin you already use:

```yaml
auth:
  htpasswd:
    file: ./htpasswd
  auth-oidc: # loads the verdaccio-auth-oidc package
    issuers:
      - id: github-actions
        issuer: https://token.actions.githubusercontent.com
        audience: https://registry.example.com
        usernameTemplate: 'gha:{repository}'
        groupTemplates:
          - 'gha:{repository}'
          - 'gha-org:{repository_owner}'
        matchClaim: repository
        allow:
          - repository: your-org/*
            sub: 'repo:your-org/*:environment:npmjs'

packages:
  '@your-org/your-package':
    access: $all
    publish: gha:your-org/your-repo # only this repository's CI
  '@your-org/*':
    access: $all
    publish: gha-org:your-org # any repository in the organization
```

Every verified token carries both its repository identity and its organization group, so each `packages:` entry chooses its own scope.

Then publish from CI with the runner's ID token as the bearer token:

```yaml
# .github/workflows/release.yaml
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: npmjs
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v6
      - name: request an OIDC token for the registry
        run: |
          token=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://registry.example.com" | jq -r .value)
          echo "::add-mask::$token"
          npm config set //registry.example.com/:_authToken "$token"
      - run: npm publish --registry https://registry.example.com
```

---

## ✨ Why verdaccio-auth-oidc?

### 😩 The Problem

Publishing to a private Verdaccio registry from CI usually means a long-lived secret:

- **Shared passwords**: One `htpasswd` account is reused by every pipeline, so any repository can publish any package
- **Long-lived tokens**: Static tokens sit in CI secrets for months and leak through logs, forks and compromised dependencies
- **Coarse identities**: Every pipeline looks like the same user, so ACLs can't tell repositories or organizations apart
- **Manual rotation**: Rotating a shared credential means touching every repository that uses it

### 💡 The Solution

verdaccio-auth-oidc lets the CI platform vouch for the job instead:

- **🔑 No shared secret**: Tokens are verified against each issuer's public JWKS — there is nothing to store or rotate
- **⏱️ Short-lived credentials**: OIDC ID tokens expire in minutes, so a leaked token is useless almost immediately
- **🏷️ Repository or organization scope**: Claims render into identities like `gha:your-org/your-repo` and groups like `gha-org:your-org`, so an ACL can trust one repository or a whole organization
- **🎯 Job-level pinning**: Allow entries can pin extra claims (for example `sub`) so only the publish job's token is accepted
- **🌐 Issuer-agnostic**: Issuers, audiences, claims and templates are pure configuration — no platform-specific code
- **🛡️ Fails closed**: A token from a trusted issuer that doesn't verify gets a `401` with `{"error":"unauthorized","reason":"oidc token verification failed"}`, never anonymous access

---

## 🚀 Key Features

| Feature                         | verdaccio-auth-oidc | htpasswd + static token | Verdaccio npm tokens |
| ------------------------------- | ------------------- | ----------------------- | -------------------- |
| **No stored secret**            | ✅                  | ❌                      | ❌                   |
| **Short-lived credentials**     | ✅                  | ❌                      | ❌                   |
| **Per-repository identity**     | ✅                  | ❌                      | Partial              |
| **Organization-wide identity**  | ✅                  | ❌                      | ❌                   |
| **Job-level pinning**           | ✅                  | ❌                      | ❌                   |
| **Works with any OIDC CI**      | ✅                  | ✅                      | ✅                   |
| **Layers on top of other auth** | ✅                  | N/A                     | N/A                  |

**Core Benefits:**

- **🔒 Smaller blast radius**: A compromised pipeline can only publish what its own repository is allowed to
- **🧹 Zero credential hygiene**: No secrets to rotate, revoke or audit across repositories
- **🔌 Drop-in**: Runs beside `htpasswd` or any other auth plugin — password logins and Verdaccio's own tokens are handed to Verdaccio's built-in handling unchanged
- **⚡ Fast**: Verified identities are cached until the token expires, so a publish's many requests verify once

---

## 📖 Usage Examples

### GitHub Actions — Selected Repositories

```yaml
auth:
  auth-oidc:
    issuers:
      - id: github-actions
        issuer: https://token.actions.githubusercontent.com
        audience: https://registry.example.com
        usernameTemplate: 'gha:{repository}'
        groupTemplates:
          - 'gha-org:{repository_owner}'
        matchClaim: repository
        allow:
          - repository: your-org/app
            sub: 'repo:your-org/app:environment:npmjs'
          - repository: your-org/service-*
            sub: 'repo:your-org/service-*:environment:npmjs'
```

### GitHub Actions — Organization-wide

Trust every repository in an organization without listing them. Scope the issuer by the owner claim, and pin the immutable owner ID so a renamed or re-registered organization can't inherit the trust:

```yaml
auth:
  auth-oidc:
    issuers:
      - id: github-actions
        issuer: https://token.actions.githubusercontent.com
        audience: https://registry.example.com
        usernameTemplate: 'gha:{repository}'
        groupTemplates:
          - 'gha-org:{repository_owner}'
        matchClaim: repository_owner
        allow:
          - repository_owner: your-org
            repository_owner_id: '1234567'
            sub: 'repo:your-org/*:environment:npmjs'

packages:
  '@your-org/*':
    access: $authenticated
    publish: gha-org:your-org
```

### Bitbucket Pipelines — Workspace-wide

```yaml
auth:
  auth-oidc:
    issuers:
      - id: bitbucket-pipelines
        issuer: https://api.bitbucket.org/2.0/workspaces/your-workspace/pipelines-config/identity/oidc
        audience: 'ari:cloud:bitbucket::workspace/<workspace-uuid>'
        usernameTemplate: 'bb:{repositoryUuid}'
        groupTemplates:
          - 'bb-workspace:{workspaceUuid}'
        matchClaim: workspaceUuid
        allow:
          - workspaceUuid: '<workspace-uuid>'
```

### GitLab CI — Group-wide

```yaml
auth:
  auth-oidc:
    issuers:
      - id: gitlab
        issuer: https://gitlab.com
        audience: https://registry.example.com
        usernameTemplate: 'gl:{project_path}'
        groupTemplates:
          - 'gl-ns:{namespace_path}'
        matchClaim: namespace_path
        allow:
          - namespace_path: your-group
            namespace_id: '7654321'
            ref_protected: 'true'
```

### Multiple Issuers

```yaml
auth:
  auth-oidc:
    issuers:
      - id: github-actions
        issuer: https://token.actions.githubusercontent.com
        # ...
      - id: gitlab
        issuer: https://gitlab.com
        # ...
```

Each `issuers[]` entry is independent. A token is routed to the issuer whose `issuer` URL equals its `iss` claim.

---

## 🔧 Configuration Reference

### Plugin Options

```ts
interface PluginConfig {
  /** issuers whose tokens are trusted */
  issuers: IssuerConfig[];
  /** allowed clock drift, in seconds, when checking exp and nbf */
  clockToleranceSeconds?: number;
  /** minimum interval, in seconds, between re-discoveries of one issuer */
  discoveryCooldownSeconds?: number;
  /** how long, in seconds, a verified identity stays cached */
  jwtCacheTtlSeconds?: number;
  /** the maximum number of cached identities */
  jwtCacheMaxEntries?: number;
}
```

| Option                     | Type             | Default  | Description                                        |
| -------------------------- | ---------------- | -------- | -------------------------------------------------- |
| `issuers`                  | `IssuerConfig[]` | required | Trusted issuers                                    |
| `clockToleranceSeconds`    | `number`         | `30`     | Allowed clock drift on `exp` / `nbf`               |
| `discoveryCooldownSeconds` | `number`         | `30`     | Minimum interval between re-discoveries per issuer |
| `jwtCacheTtlSeconds`       | `number`         | `300`    | Result-cache lifetime; `0` disables the cache      |
| `jwtCacheMaxEntries`       | `number`         | `1000`   | Result-cache size; `0` disables the cache          |

### Issuer Options

```ts
interface IssuerConfig {
  /** free-form label used in logs and errors */
  id: string;
  /** issuer URL, which must equal the token's iss claim */
  issuer: string;
  /** audience(s) the token's aud claim must match */
  audience: string | string[];
  /** accepted signature algorithms, capped to a safe asymmetric set */
  algorithms?: string[];
  /** explicit JWKS endpoint that skips discovery */
  jwksUri?: string;
  /** whether http (not https) issuer and JWKS URLs are accepted; for loopback and tests only */
  allowInsecureHttp?: boolean;
  /** template for the Verdaccio user name, e.g. 'gha:{repository}' */
  usernameTemplate: string;
  /** templates for the Verdaccio groups */
  groupTemplates: string[];
  /** the claim that sets the trust scope (e.g. repository or repository_owner); every allow entry must name it */
  matchClaim: string;
  /** whether claim matching ignores case */
  matchCaseInsensitive?: boolean;
  /** allow entries; a token is accepted when any entry matches */
  allow: Array<Record<string, string | string[]>>;
}
```

| Option                 | Type                                        | Default    | Description                                          |
| ---------------------- | ------------------------------------------- | ---------- | ---------------------------------------------------- |
| `id`                   | `string`                                    | required   | Label used in logs and errors                        |
| `issuer`               | `string`                                    | required   | Absolute `https` URL equal to the token's `iss`      |
| `audience`             | `string \| string[]`                        | required   | Expected `aud`; never optional                       |
| `algorithms`           | `string[]`                                  | discovered | Accepted algorithms, capped to the safe set          |
| `jwksUri`              | `string`                                    | discovered | `https` JWKS URL that skips discovery for key lookup |
| `allowInsecureHttp`    | `boolean`                                   | `false`    | Accept `http` issuer and JWKS URLs (loopback, tests) |
| `usernameTemplate`     | `string`                                    | required   | `{claim}` placeholders rendered from verified claims |
| `groupTemplates`       | `string[]`                                  | required   | Group templates, rendered the same way               |
| `matchClaim`           | `string`                                    | required   | Trust-scope claim every `allow` entry must name      |
| `matchCaseInsensitive` | `boolean`                                   | `true`     | Case-insensitive matching and lower-case identities  |
| `allow`                | `Array<Record<string, string \| string[]>>` | required   | Claim patterns; any matching entry admits the token  |

### Allow Patterns

Each `allow` entry matches when **every** key matches the claim of the same name. A list value matches when **any** of its patterns does.

| Pattern | Matches                                  | Example                                     |
| ------- | ---------------------------------------- | ------------------------------------------- |
| `*`     | Any run of characters except `/` and `:` | `your-org/service-*` → `your-org/service-a` |
| `**`    | Anything, crossing `/` and `:`           | `your-org/**` → `your-org/a/b`              |
| literal | Every other character matches itself     | `repo:your-org/app:environment:npmjs`       |

### Startup Checks

The plugin refuses to load, naming the issuer and the problem, when an issuer is missing an `id`, `audience`, `matchClaim` or templates, uses a malformed template or a non-absolute `issuer` URL, has an empty `allow` list or an entry without its `matchClaim` key, lists an unsafe algorithm, shares its `issuer` URL with another entry, or uses an `http` `issuer` or `jwksUri` without `allowInsecureHttp: true`. The plugin's key under `auth:` must be `auth-oidc`, which Verdaccio resolves to the `verdaccio-auth-oidc` package.

A failed startup logs `verdaccio-auth-oidc failed to start, stopping verdaccio: …` and exits Verdaccio with code `1` — including when the plugin sits in Verdaccio's `plugins` folder, where Verdaccio would otherwise skip a broken plugin and keep serving without it.

A `usernameTemplate` or `groupTemplates` entry that starts with a `{claim}` placeholder loads, but logs a warning: the token's claims alone then choose the name, so a job could render a name that collides with a human user or group. Give every template a literal prefix such as `gha:` or `ci:`.

---

## 🌐 Compatibility & Size

| Requirement       | Value                                                                                    |
| ----------------- | ---------------------------------------------------------------------------------------- |
| **Node.js**       | >= 22.12 (`require()` of ESM)                                                            |
| **Verdaccio**     | 6.1.0 – 7.x (7.x needs Node.js >= 24)                                                    |
| **TypeScript**    | 5.x+                                                                                     |
| **Module format** | ESM only                                                                                 |
| **Plugin type**   | Verdaccio `auth` plugin (`apiJWTmiddleware`)                                             |
| **Dependencies**  | [`jose`](https://github.com/panva/jose), [`xception`](https://github.com/alvis/xception) |

**Why an `auth` plugin?** Verdaccio's core API middleware runs before every `middlewares` plugin, and from Verdaccio 7 it answers `401` to any bearer token it didn't issue itself — so a CI token never reaches a later middleware. As an `auth` plugin providing `apiJWTmiddleware`, this plugin sees the request first: it verifies tokens whose `iss` names a configured issuer and hands every other request — password logins, Verdaccio-issued tokens, anonymous access — to Verdaccio's own core handling over your remaining auth plugins.

To do that, the plugin builds a second copy of Verdaccio's core auth from the running Verdaccio install, set up the way that Verdaccio version sets up its own. Two consequences follow:

- **Other auth plugins load twice** — once for Verdaccio's core and once for the hand-off — so their "loaded" log lines and any start-up side effects appear twice. API requests use the hand-off copy; `npm login` and token creation use core's.
- **Verdaccio must be started through its own executable** (the `verdaccio` bin or the official Docker image), because the plugin finds the install from the running script. Launching through a wrapper such as PM2's script mode stops Verdaccio at startup with `OIDC_FALLBACK_UNAVAILABLE`.

Verdaccio 6.0.x is not supported: its core auth is an internal implementation the plugin can't reproduce exactly, while from 6.1.0 core uses the shared `@verdaccio/auth` package.

---

## ⚔️ Alternatives

| Feature                     | verdaccio-auth-oidc | [verdaccio-htpasswd](https://www.npmjs.com/package/verdaccio-htpasswd) | [verdaccio-github-oauth-ui](https://www.npmjs.com/package/verdaccio-github-oauth-ui) | npmjs.com trusted publishing |
| --------------------------- | ------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ---------------------------- |
| **Self-hosted registry**    | ✅                  | ✅                                                                     | ✅                                                                                   | ❌                           |
| **No stored CI secret**     | ✅                  | ❌                                                                     | ❌                                                                                   | ✅                           |
| **Per-repository identity** | ✅                  | ❌                                                                     | ❌                                                                                   | ✅                           |
| **Org-wide CI identity**    | ✅                  | ❌                                                                     | ❌                                                                                   | ❌                           |
| **Any OIDC CI platform**    | ✅                  | N/A                                                                    | ❌                                                                                   | Partial                      |
| **Human SSO login**         | ❌                  | ❌                                                                     | ✅                                                                                   | N/A                          |

**When to choose what:**

- **verdaccio-auth-oidc** — When CI pipelines publish to a self-hosted Verdaccio and you want no stored credentials
- **verdaccio-htpasswd** — When a handful of humans or one trusted pipeline need simple password auth
- **verdaccio-github-oauth-ui** — When humans should sign in to the registry with their GitHub account
- **npmjs.com trusted publishing** — When you publish to the public npm registry rather than your own

---

## 🏗️ Advanced Features

### Telling the Publish Job Apart

Every job in a GitHub Actions run gets a token with the same `repository` claim — including an install job whose dependencies run arbitrary scripts. Pin `sub` to the publish job's environment so only that job's token is accepted:

```yaml
allow:
  - repository: your-org/your-repo
    sub: 'repo:your-org/your-repo:environment:npmjs'
```

Give the `npmjs` environment a deployment rule for release tags so only a release run can enter it.

### Choosing a Trust Scope

`matchClaim` decides how wide an issuer's trust reaches, and the templates decide which identities a verified token receives:

| Scope        | GitHub `matchClaim` | Bitbucket `matchClaim` | GitLab `matchClaim` | ACL target example       |
| ------------ | ------------------- | ---------------------- | ------------------- | ------------------------ |
| Repository   | `repository`        | `repositoryUuid`       | `project_path`      | `gha:your-org/your-repo` |
| Organization | `repository_owner`  | `workspaceUuid`        | `namespace_path`    | `gha-org:your-org`       |

Both scopes can coexist: an organization-wide issuer still renders the repository identity, so one `packages:` entry can grant the whole organization while another narrows a sensitive package to a single repository. For organization-wide trust, pin the platform's immutable ID claim (`repository_owner_id`, `namespace_id`) next to the name — names can be renamed and re-registered, IDs can't.

### Discovery and Key Rotation

Each issuer's `jwks_uri` and signing algorithms are discovered from `{issuer}/.well-known/openid-configuration` on first use. When verification fails because a key can't be resolved, the plugin re-discovers once — rate-limited by `discoveryCooldownSeconds` — so a provider moving its JWKS heals without a restart. A failed re-discovery keeps the working key source, so tokens signed with known keys still verify while its cached keys are fresh; once the JWKS endpoint itself has been unreachable past that cache (about 10 minutes), tokens are rejected until it recovers. Failures caused by the token itself are never retried.

Issuer, `jwksUri` and discovered `jwks_uri` URLs must use `https`; set `allowInsecureHttp: true` only for a loopback or test issuer.

### Algorithm Safety

Only asymmetric algorithms (`RS*`, `PS*`, `ES*`, `EdDSA`) are ever accepted, whatever the configuration or discovery document says. The algorithm is never taken from the token header, which rules out `none` and `HS*` confusion attacks.

### Result Cache

Verified identities are cached by a hash of the token — never the token itself — until `min(now + jwtCacheTtlSeconds, exp)`, with least-recently-used eviction at `jwtCacheMaxEntries`. Editing `allow:` takes effect for cached tokens on expiry or restart.

---

## 🤝 Contributing

1. **Fork & Clone**: `git clone https://github.com/alvis/verdaccio-auth-oidc.git`
2. **Install**: `pnpm install`
3. **Develop**: `pnpm test:watch` for development mode
4. **Test**: `pnpm test && pnpm lint`
5. **Submit**: Create a pull request

**Code Style:**

- [Conventional Commits](https://conventionalcommits.org/)
- ESLint + Prettier enforced
- 100% test coverage required

---

## 🛡️ Security

Found a vulnerability? Please report it privately through [GitHub Security Advisories](https://github.com/alvis/verdaccio-auth-oidc/security/advisories/new) rather than a public issue.
We aim to respond within 48 hours and patch as quickly as possible.

**Known limitations:** OIDC ID tokens are not single-use, so a leaked token remains valid until its `exp`. The plugin never logs a token or a full claim set.

---

## 🛠️ Troubleshooting

| Issue                                              | Solution                                                                                                                      |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **CI token rejected as a Verdaccio token**         | Verdaccio uses only the first auth plugin providing `apiJWTmiddleware` — remove or reorder any other plugin that provides one |
| **Every publish answers 401**                      | Check that `audience` matches the audience the CI job requested, and that an `allow` entry matches its claims                 |
| **Plugin fails to load (`ERR_REQUIRE_ESM`)**       | Upgrade to Node.js >= 22.12, which can `require()` ES modules                                                                 |
| **ACL doesn't match a mixed-case repo**            | With `matchCaseInsensitive: true` identities render in lower case — write ACL entries in lower case                           |
| **Plugin refuses to start**                        | Read the startup error — it names the issuer and the invalid field                                                            |
| **Startup fails with `OIDC_FALLBACK_UNAVAILABLE`** | Start Verdaccio through its own `verdaccio` executable (or the official image), and use Verdaccio 6.1.0 or later              |
| **Warning: template has no literal prefix**        | Prefix the template, e.g. `ci:{repository}`, so OIDC names can't collide with human users or groups                           |

### ❓ FAQ

**Does this replace my existing auth plugin?**
No. It only claims bearer tokens from configured issuers; password logins and Verdaccio-issued tokens are handed to Verdaccio's own authentication over the other auth plugins you configure.

**Which CI platforms are supported?**
Any platform that issues OIDC ID tokens with a discoverable JWKS — GitHub Actions, GitLab CI, Bitbucket Pipelines, CircleCI, Azure DevOps and more. Support is configuration, not code.

**Can I trust a whole organization instead of listing every repository?**
Yes. Set `matchClaim` to the organization claim (for example `repository_owner`) and grant the rendered organization group in `packages:` — see [Choosing a Trust Scope](#choosing-a-trust-scope).

**Can humans log in with this?**
No. This plugin verifies machine-issued ID tokens; interactive SSO is out of scope.

More help: [GitHub Issues](https://github.com/alvis/verdaccio-auth-oidc/issues) · [Discussions](https://github.com/alvis/verdaccio-auth-oidc/discussions)

---

## 📄 License

**MIT** © 2026 [Alvis HT Tang](https://github.com/alvis)

Free for personal and commercial use. See [LICENSE](LICENSE) for details.

---

<div align="center">

**[⭐ Star on GitHub](https://github.com/alvis/verdaccio-auth-oidc)** · **[📦 View on npm](https://www.npmjs.com/package/verdaccio-auth-oidc)** · **[📖 Documentation](https://github.com/alvis/verdaccio-auth-oidc#readme)**

_Built for teams who'd rather their pipelines carry no secrets at all._

</div>
