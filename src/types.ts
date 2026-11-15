import type { NextFunction, Request, Response } from 'express';
import type { JWTPayload } from 'jose';

/** an allow entry as written in config: claim name to one or more patterns */
export type AllowEntryConfig = Record<string, string | string[]>;

/** issuer options as written under `issuers[]` in Verdaccio's config */
export interface IssuerConfig {
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
  /** whether the issuer, jwksUri and discovered jwks_uri may use plain http, e.g. for a loopback test issuer; defaults to false */
  allowInsecureHttp?: boolean;
  /** template for the Verdaccio user name, e.g. 'gha:{repository}' */
  usernameTemplate: string;
  /** templates for the Verdaccio groups */
  groupTemplates: string[];
  /** the claim that sets the trust scope; every allow entry must name it */
  matchClaim: string;
  /** whether claim matching ignores case and identities render in lower case */
  matchCaseInsensitive?: boolean;
  /** allow entries; a token is accepted when any entry matches */
  allow: AllowEntryConfig[];
}

/** plugin options as written under `auth:` in Verdaccio's config */
export interface PluginConfig {
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

/** one literal or placeholder segment of a parsed template */
export type TemplateSegment =
  { kind: 'literal'; text: string } | { kind: 'claim'; claim: string };

/** a template parsed at startup, rendered per token */
export interface Template {
  /** the template as written in config */
  source: string;
  /** literal and placeholder segments in order */
  segments: TemplateSegment[];
}

/** one claim condition of an allow entry, compiled at startup */
export interface ClaimCondition {
  /** the claim name the condition reads */
  claim: string;
  /** compiled patterns; any match satisfies the condition */
  patterns: RegExp[];
}

/** a compiled allow entry; every condition must match */
export type AllowEntry = ClaimCondition[];

/** a validated issuer with defaults applied and templates/patterns compiled */
export interface ResolvedIssuer {
  /** label used in logs and errors */
  id: string;
  /** issuer URL the token's iss claim must equal */
  issuer: string;
  /** accepted audiences, at least one */
  audience: string[];
  /** configured algorithms, or undefined to use discovery */
  algorithms?: string[];
  /** explicit JWKS endpoint that skips discovery */
  jwksUri?: string;
  /** whether plain http is accepted for the issuer, jwksUri and discovered jwks_uri */
  allowInsecureHttp: boolean;
  /** parsed user name template */
  usernameTemplate: Template;
  /** parsed group templates */
  groupTemplates: Template[];
  /** the trust-scope claim every allow entry names */
  matchClaim: string;
  /** whether matching ignores case and identities render in lower case */
  isCaseInsensitive: boolean;
  /** compiled allow entries */
  allow: AllowEntry[];
}

/** a validated plugin configuration with defaults applied */
export interface ResolvedPluginConfig {
  /** trusted issuers */
  issuers: ResolvedIssuer[];
  /** allowed clock drift, in seconds, on exp and nbf */
  clockToleranceSeconds: number;
  /** minimum interval, in seconds, between re-discoveries of one issuer */
  discoveryCooldownSeconds: number;
  /** result-cache lifetime in seconds; 0 disables the cache */
  jwtCacheTtlSeconds: number;
  /** result-cache size; 0 disables the cache */
  jwtCacheMaxEntries: number;
}

/** verified token claims */
export type Claims = JWTPayload;

/** the Verdaccio identity a verified token maps to */
export interface Identity {
  /** the configured issuer id that verified the token */
  issuerId: string;
  /** the rendered Verdaccio user name */
  name: string;
  /** the rendered Verdaccio groups */
  groups: string[];
}

/** the part of the user Verdaccio attaches to a request that this plugin reads; Verdaccio's helpers add more */
export interface RemoteUser {
  /** the user name, undefined for an anonymous user */
  name: string | undefined;
  /** the groups ACLs match against, including Verdaccio's built-in ones */
  groups: string[];
}

/** helpers Verdaccio passes to an auth plugin's `apiJWTmiddleware` */
export interface AuthMiddlewareHelpers {
  /** builds the anonymous user */
  createAnonymousRemoteUser: () => RemoteUser;
  /** builds an authenticated user from a name and plugin groups */
  createRemoteUser: (name: string, pluginGroups: string[]) => RemoteUser;
}

/** an Express request carrying Verdaccio's `remote_user`, whose snake-case name Verdaccio fixes */
export type VerdaccioRequest = Request &
  Partial<Record<'remote_user', RemoteUser>>;

/** the Express middleware signature Verdaccio mounts */
export type RequestHandler = (
  request: VerdaccioRequest,
  response: Response,
  next: NextFunction,
) => void;

/** the subset of Verdaccio's pino-style logger this plugin uses */
export interface Logger {
  info: (context: Record<string, unknown>, template?: string) => void;
  warn: (context: Record<string, unknown>, template?: string) => void;
  error: (context: Record<string, unknown>, template?: string) => void;
}

/** the subset of Verdaccio's resolved config this plugin reads */
export interface VerdaccioConfig {
  /** auth plugin section, keyed by plugin id */
  auth?: Record<string, unknown> | null;
  /** secret signing Verdaccio's own tokens; required by its core auth */
  secret?: string;
}

/** options Verdaccio passes to every plugin constructor */
export interface VerdaccioPluginOptions {
  /** the full Verdaccio configuration */
  config: VerdaccioConfig;
  /** Verdaccio's logger */
  logger: Logger;
}
