import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { describe, expect, inject, it } from 'vitest';

import { AUDIENCE, HTPASSWD_USER } from './setup';

import type { JWTPayload } from 'jose';

const issuerUrl = inject('issuerUrl');
const targets = inject('verdaccioTargets').map((target) => ({
  ...target,
  title: target.skipReason
    ? `verdaccio ${target.version} (skipped: ${target.skipReason})`
    : `verdaccio ${target.version}`,
}));

const allowedClaims = {
  aud: AUDIENCE,
  repository: 'acme/app',
  repository_owner: 'acme',
  sub: 'repo:acme/app:environment:release',
};

/**
 * asks the fake issuer for a signed ID token, as a CI runner would
 * @param claims the claims the issuer signs
 * @returns the signed token
 */
async function requestIdToken(claims: JWTPayload): Promise<string> {
  const response = await fetch(`${issuerUrl}/token`, {
    method: 'POST',
    body: JSON.stringify(claims),
  });
  const { value } = (await response.json()) as { value: string };

  return value;
}

/**
 * publishes a minimal package with the npm CLI and a bearer token
 * @param params the registry, package name and token
 * @param params.registry the registry URL
 * @param params.name the package name
 * @param params.token the bearer token npm sends
 * @returns npm's exit code
 */
async function publishWithNpm(params: {
  registry: string;
  name: string;
  token: string;
}): Promise<number> {
  const { registry, name, token } = params;
  const directory = mkdtempSync(join(tmpdir(), 'verdaccio-auth-oidc-pkg-'));
  const npmrc = join(directory, '.npmrc');

  writeFileSync(
    join(directory, 'package.json'),
    JSON.stringify({ name, version: '1.0.0' }),
  );
  writeFileSync(
    npmrc,
    `${registry.replace(/^https?:/, '')}/:_authToken=${token}\n`,
  );

  try {
    await promisify(execFile)('npm', ['publish', '--registry', registry], {
      cwd: directory,
      env: {
        ...process.env,
        npm_config_userconfig: npmrc,
        npm_config_update_notifier: 'false',
      },
    });

    return 0;
  } catch (exception) {
    return (exception as { code?: number }).code ?? 1;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe.each(targets)('$title', (target) => {
  const registry = target.url ?? '';

  describe.skipIf(target.skipReason !== undefined)(
    'with htpasswd and auth-oidc',
    () => {
      it('should start with the plugin loaded', () => {
        expect(target.startupError).toBeUndefined();
      });

      it('should publish a package with an allowed CI token', async () => {
        const token = await requestIdToken(allowedClaims);

        const exitCode = await publishWithNpm({
          registry,
          name: '@acme/ci-package',
          token,
        });
        const manifest = await fetch(`${registry}/@acme%2fci-package`).then(
          async (response) => response.json() as Promise<{ versions: object }>,
        );

        expect(exitCode).toBe(0);
        expect(Object.keys(manifest.versions)).toEqual(['1.0.0']);
      });

      it('should answer 401 to a token no allow entry matches', async () => {
        const token = await requestIdToken({
          ...allowedClaims,
          repository: 'evil/app',
          sub: 'repo:evil/app:environment:release',
        });

        const response = await fetch(`${registry}/-/whoami`, {
          headers: { authorization: `Bearer ${token}` },
        });

        expect({
          status: response.status,
          body: await response.json(),
        }).toEqual({
          status: 401,
          body: {
            error: 'unauthorized',
            reason: 'oidc token verification failed',
          },
        });
      });

      it('should serve a package to an anonymous reader', async () => {
        const token = await requestIdToken(allowedClaims);
        await publishWithNpm({ registry, name: '@acme/public-read', token });

        const response = await fetch(`${registry}/@acme%2fpublic-read`);

        expect(response.status).toBe(200);
      });

      it('should leave a token from an unconfigured issuer anonymous', async () => {
        const token = await requestIdToken({
          ...allowedClaims,
          iss: 'https://unconfigured.example.com',
        });

        const exitCode = await publishWithNpm({
          registry,
          name: '@acme/unconfigured-issuer',
          token,
        });
        const manifest = await fetch(`${registry}/@acme%2funconfigured-issuer`);

        expect({ exitCode, status: manifest.status }).toEqual({
          exitCode: 1,
          status: 404,
        });
      });

      it('should not let an OIDC identity mint a Verdaccio token', async () => {
        const token = await requestIdToken(allowedClaims);

        const response = await fetch(`${registry}/-/npm/v1/tokens`, {
          method: 'POST',
          headers: {
            'authorization': `Bearer ${token}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            password: 'any-password',
            readonly: false,
            cidr_whitelist: [],
          }),
        });

        expect(response.ok).toBe(false);
      });

      it('should keep htpasswd login and Verdaccio-issued tokens working through the fallback', async () => {
        const credentials = Buffer.from(
          `${HTPASSWD_USER.name}:${HTPASSWD_USER.password}`,
        ).toString('base64');

        const login = await fetch(
          `${registry}/-/user/org.couchdb.user:${HTPASSWD_USER.name}`,
          {
            method: 'PUT',
            // npm's legacy login sends the credentials as basic auth too
            headers: {
              'authorization': `Basic ${credentials}`,
              'content-type': 'application/json',
            },
            body: JSON.stringify(HTPASSWD_USER),
          },
        );
        const { token } = (await login.json()) as { token: string };

        const whoami = await fetch(`${registry}/-/whoami`, {
          headers: { authorization: `Bearer ${token}` },
        }).then(async (response) => response.json());
        const exitCode = await publishWithNpm({
          registry,
          name: '@humans/hand-made',
          token,
        });

        expect(whoami).toEqual({ username: HTPASSWD_USER.name });
        expect(exitCode).toBe(0);
      });
    },
  );
});
