import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { startFakeIssuer } from '../fixtures/issuer';

import type { ChildProcess } from 'node:child_process';
import type { AddressInfo } from 'node:net';

import type { TestProject } from 'vitest/node';

/** a Verdaccio install the e2e suite boots, with its outcome */
export interface VerdaccioTarget {
  /** the aliased package name under node_modules */
  alias: string;
  /** the installed Verdaccio version */
  version: string;
  /** the registry URL */
  url: string;
  /** Verdaccio's output when it failed to start */
  startupError?: string;
}

declare module 'vitest' {
  export interface ProvidedContext {
    issuerUrl: string;
    verdaccioTargets: VerdaccioTarget[];
  }
}

/** the audience every e2e token is issued for */
export const AUDIENCE = 'https://registry.e2e.test';

/** the htpasswd user the fallback must keep serving */
export const HTPASSWD_USER = { name: 'alice', password: 'wonderland' };

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const STARTUP_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 250;
const NODE_MAJOR = Number(process.versions.node.split('.', 1)[0]);

const installs = [
  { alias: 'verdaccio-6.1.0', minimumNodeMajor: 18 },
  { alias: 'verdaccio-6', minimumNodeMajor: 22 },
  { alias: 'verdaccio-7.0.0', minimumNodeMajor: 24 },
  { alias: 'verdaccio', minimumNodeMajor: 24 },
];

/**
 * boots the fake issuer and every Verdaccio install
 * @param project the vitest project receiving the provided context
 * @returns the teardown that stops every process and removes the work directory
 * @throws {Error} when this Node.js is too old to host every Verdaccio install
 */
export default async function setup(
  project: TestProject,
): Promise<() => Promise<void>> {
  assertNodeHostsEveryInstall();

  const issuer = await startFakeIssuer();
  const workDirectory = mkdtempSync(join(tmpdir(), 'verdaccio-auth-oidc-e2e-'));
  const pluginsDirectory = preparePluginsDirectory(workDirectory);
  const processes: ChildProcess[] = [];

  const targets = await Promise.all(
    installs.map(async ({ alias }): Promise<VerdaccioTarget> => {
      const packagePath = join(ROOT, 'node_modules', alias, 'package.json');
      const { version } = JSON.parse(readFileSync(packagePath, 'utf8')) as {
        version: string;
      };
      const directory = join(workDirectory, alias);
      const configPath = writeVerdaccioConfig({
        directory,
        pluginsDirectory,
        issuerUrl: issuer.url,
      });
      const port = await findFreePort();
      const { child, startupError } = await bootVerdaccio({
        bin: realpathSync(
          join(ROOT, 'node_modules', alias, 'bin', 'verdaccio'),
        ),
        configPath,
        port,
      });
      processes.push(child);

      return {
        alias,
        version,
        url: `http://127.0.0.1:${port}`,
        startupError,
      };
    }),
  );

  project.provide('issuerUrl', issuer.url);
  project.provide('verdaccioTargets', targets);

  return async () => {
    for (const child of processes) {
      child.kill();
    }
    await issuer[Symbol.asyncDispose]();
    rmSync(workDirectory, { recursive: true, force: true });
  };
}

/**
 * refuses to run the suite on a Node.js that cannot host every Verdaccio install, so no target goes untested
 * @throws {Error} naming each install this Node.js cannot host and the Node.js version it needs
 */
function assertNodeHostsEveryInstall(): void {
  const unhostable = installs.filter(
    ({ minimumNodeMajor }) => NODE_MAJOR < minimumNodeMajor,
  );

  if (unhostable.length === 0) {
    return;
  }

  const requiredMajor = Math.max(
    ...unhostable.map(({ minimumNodeMajor }) => minimumNodeMajor),
  );
  const needs = unhostable
    .map(
      ({ alias, minimumNodeMajor }) =>
        `${alias} needs Node.js >= ${minimumNodeMajor}`,
    )
    .join(', ');

  throw new Error(
    `the e2e suite requires Node.js >= ${requiredMajor} to boot every Verdaccio target, but runs on ${process.versions.node}: ${needs}`,
  );
}

/**
 * lays the built plugin out as Verdaccio expects under its `plugins` directory
 * @param workDirectory the e2e work directory
 * @returns the path Verdaccio's `plugins` setting points at
 */
function preparePluginsDirectory(workDirectory: string): string {
  const pluginsDirectory = join(workDirectory, 'plugins');
  const pluginDirectory = join(pluginsDirectory, 'verdaccio-auth-oidc');
  const { name, version } = JSON.parse(
    readFileSync(join(ROOT, 'package.json'), 'utf8'),
  ) as { name: string; version: string };

  mkdirSync(pluginDirectory, { recursive: true });
  cpSync(join(ROOT, 'lib'), join(pluginDirectory, 'lib'), { recursive: true });
  // mirror the published manifest, whose subpath imports point at lib
  writeFileSync(
    join(pluginDirectory, 'package.json'),
    JSON.stringify({
      name,
      version,
      type: 'module',
      main: 'lib/index.js',
      exports: { '.': './lib/index.js' },
      imports: { '#*': './lib/*.js' },
    }),
  );
  // resolve jose and xception from this repository's install
  symlinkSync(
    join(ROOT, 'node_modules'),
    join(pluginDirectory, 'node_modules'),
  );

  return pluginsDirectory;
}

/**
 * writes a Verdaccio config with htpasswd beside this plugin
 * @param params where to write and what to trust
 * @param params.directory the per-install directory
 * @param params.pluginsDirectory the directory holding the built plugin
 * @param params.issuerUrl the fake issuer's URL
 * @returns the config path
 */
function writeVerdaccioConfig(params: {
  directory: string;
  pluginsDirectory: string;
  issuerUrl: string;
}): string {
  const { directory, pluginsDirectory, issuerUrl } = params;
  const configPath = join(directory, 'config.yaml');
  // htpasswd's {SHA} scheme dictates the hash; it guards a throwaway fixture user
  // eslint-disable-next-line sonarjs/hashing -- {SHA} is the fixture file format, not a security control
  const passwordHash = createHash('sha1')
    .update(HTPASSWD_USER.password)
    .digest('base64');

  mkdirSync(join(directory, 'storage'), { recursive: true });
  writeFileSync(
    join(directory, 'htpasswd'),
    `${HTPASSWD_USER.name}:{SHA}${passwordHash}:autocreated\n`,
  );
  // JSON is valid YAML, so the config needs no YAML serializer
  writeFileSync(
    configPath,
    JSON.stringify({
      storage: join(directory, 'storage'),
      plugins: pluginsDirectory,
      auth: {
        'htpasswd': { file: join(directory, 'htpasswd') },
        'auth-oidc': {
          issuers: [
            {
              id: 'fake',
              issuer: issuerUrl,
              // the fake issuer serves plain http on loopback
              allowInsecureHttp: true,
              audience: AUDIENCE,
              usernameTemplate: 'ci:{repository}',
              groupTemplates: ['ci-org:{repository_owner}'],
              matchClaim: 'repository',
              allow: [
                {
                  repository: 'acme/*',
                  sub: 'repo:acme/*:environment:release',
                },
              ],
            },
          ],
        },
      },
      uplinks: {},
      packages: {
        '@acme/*': { access: '$all', publish: 'ci:acme/app' },
        '@humans/*': { access: '$all', publish: HTPASSWD_USER.name },
        '**': { access: '$all', publish: '$authenticated' },
      },
      log: { type: 'stdout', format: 'json', level: 'warn' },
    }),
  );

  return configPath;
}

/**
 * finds a free local TCP port
 * @returns a port nothing listens on
 */
async function findFreePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));

  return port;
}

/**
 * starts Verdaccio and waits until it answers its ping endpoint or exits
 * @param params the bin, config and port
 * @param params.bin the real path of Verdaccio's bin
 * @param params.configPath the Verdaccio config file to boot with
 * @param params.port the local port Verdaccio binds
 * @returns the process and, when it did not come up, its output
 */
async function bootVerdaccio(params: {
  bin: string;
  configPath: string;
  port: number;
}): Promise<{ child: ChildProcess; startupError?: string }> {
  const { bin, configPath, port } = params;
  const output: string[] = [];
  const child = spawn(
    process.execPath,
    [bin, '--config', configPath, '--listen', `127.0.0.1:${port}`],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const collectOutput = (chunk: Buffer): void => {
    output.push(chunk.toString());
  };
  child.stdout.on('data', collectOutput);
  child.stderr.on('data', collectOutput);

  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline && child.exitCode === null) {
    const isUp = await fetch(`http://127.0.0.1:${port}/-/ping`)
      .then((response) => response.ok)
      .catch(() => false);
    if (isUp) {
      return { child };
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  return {
    child,
    startupError: `exit code ${String(child.exitCode)}\n${output.join('')}`,
  };
}
