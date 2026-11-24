import { isSafeAlgorithm } from '#algorithms';
import { OidcError } from '#errors';
import { rejectUnknownIssuerKeys } from '#keys';
import { compilePattern } from '#pattern';
import { parseTemplate } from '#template';

import type {
  AllowEntry,
  ResolvedIssuer,
  ResolvedPluginConfig,
  Template,
} from '#types';

/** what an allow list is compiled against */
interface AllowScope {
  /** the issuer named in errors */
  issuerId: string;
  /** the claim every entry must name */
  matchClaim: string;
  /** whether matching ignores case */
  isCaseInsensitive: boolean;
}

const DEFAULT_CLOCK_TOLERANCE_SECONDS = 30;
const DEFAULT_DISCOVERY_COOLDOWN_SECONDS = 30;
const DEFAULT_JWT_CACHE_TTL_SECONDS = 300;
const DEFAULT_JWT_CACHE_MAX_ENTRIES = 1000;

/**
 * validates the plugin's config block and compiles its templates and patterns, running every startup check
 * @param input the plugin config as Verdaccio hands it over, possibly merged with Verdaccio's own config
 * @returns the resolved config with defaults applied
 * @throws {OidcError} OIDC_CONFIG_INVALID naming the issuer and field when any check fails
 */
export function parseConfig(input: unknown): ResolvedPluginConfig {
  const record = readRecord(input, 'plugin config', {});
  const issuersInput = record.issuers;

  if (!Array.isArray(issuersInput) || issuersInput.length === 0) {
    throw invalid('issuers must be a non-empty list', { field: 'issuers' });
  }

  const issuers = issuersInput.map((issuerInput: unknown, index) =>
    parseIssuer(issuerInput, index),
  );

  const urls = issuers.map(({ issuer }) => issuer);
  const duplicate = urls.find((url, index) => urls.indexOf(url) !== index);
  if (duplicate !== undefined) {
    throw invalid(`issuer URL ${duplicate} is configured more than once`, {
      field: 'issuer',
    });
  }

  return {
    issuers,
    clockToleranceSeconds: readNonNegativeInteger(
      record,
      'clockToleranceSeconds',
      DEFAULT_CLOCK_TOLERANCE_SECONDS,
    ),
    discoveryCooldownSeconds: readNonNegativeInteger(
      record,
      'discoveryCooldownSeconds',
      DEFAULT_DISCOVERY_COOLDOWN_SECONDS,
    ),
    jwtCacheTtlSeconds: readNonNegativeInteger(
      record,
      'jwtCacheTtlSeconds',
      DEFAULT_JWT_CACHE_TTL_SECONDS,
    ),
    jwtCacheMaxEntries: readNonNegativeInteger(
      record,
      'jwtCacheMaxEntries',
      DEFAULT_JWT_CACHE_MAX_ENTRIES,
    ),
  };
}

/**
 * validates one `issuers[]` entry
 * @param input the raw entry
 * @param index the entry's position, used when it has no id
 * @returns the resolved issuer
 * @throws {OidcError} OIDC_CONFIG_INVALID naming the issuer and field, including an unknown key
 */
function parseIssuer(input: unknown, index: number): ResolvedIssuer {
  const record = readRecord(input, `issuers[${index}]`, {});
  const id = record.id;

  if (typeof id !== 'string' || id === '') {
    throw invalid(`issuers[${index}] is missing an id`, { field: 'id' });
  }

  rejectUnknownIssuerKeys(record, id);

  const isCaseInsensitive = readOptionalBoolean(record, {
    field: 'matchCaseInsensitive',
    issuerId: id,
    fallback: true,
  });
  const allowInsecureHttp = readOptionalBoolean(record, {
    field: 'allowInsecureHttp',
    issuerId: id,
    fallback: false,
  });
  const matchClaim = readString(record, 'matchClaim', id);
  const readIssuerUrl = (field: string): string =>
    readUrl(record, { field, issuerId: id, allowInsecureHttp });

  return {
    id,
    issuer: readIssuerUrl('issuer'),
    audience: readAudience(record, id),
    algorithms: readAlgorithms(record, id),
    jwksUri:
      record.jwksUri === undefined ? undefined : readIssuerUrl('jwksUri'),
    allowInsecureHttp,
    usernameTemplate: readTemplate(
      record.usernameTemplate,
      'usernameTemplate',
      id,
    ),
    groupTemplates: readTemplates(record, id),
    matchClaim,
    isCaseInsensitive,
    allow: readAllow(record, { issuerId: id, matchClaim, isCaseInsensitive }),
  };
}

/**
 * reads an object-shaped value
 * @param input the raw value
 * @param label what the value is, for the error message
 * @param meta the issuer id and field the error names, when known
 * @returns the value as a record
 * @throws {OidcError} OIDC_CONFIG_INVALID when the value is not an object
 */
function readRecord(
  input: unknown,
  label: string,
  meta: Record<string, unknown>,
): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw invalid(`${label} must be an object`, meta);
  }

  return input as Record<string, unknown>;
}

/**
 * reads a required non-empty string field
 * @param record the issuer record
 * @param field the field name
 * @param issuerId the issuer named in errors
 * @returns the field value
 * @throws {OidcError} OIDC_CONFIG_INVALID when the field is missing or empty
 */
function readString(
  record: Record<string, unknown>,
  field: string,
  issuerId: string,
): string {
  const value = record[field];
  if (typeof value !== 'string' || value === '') {
    throw invalid(`issuer "${issuerId}" is missing ${field}`, {
      issuerId,
      field,
    });
  }

  return value;
}

/**
 * reads a required absolute https URL field, or http when the issuer opts in
 * @param record the issuer record
 * @param scope the field, the issuer named in errors and the issuer's http opt-in
 * @param scope.field the field name
 * @param scope.issuerId the issuer named in errors
 * @param scope.allowInsecureHttp whether plain http is accepted
 * @returns the URL as written
 * @throws {OidcError} OIDC_CONFIG_INVALID when the field is not an absolute https URL, or http without the opt-in
 */
function readUrl(
  record: Record<string, unknown>,
  scope: { field: string; issuerId: string; allowInsecureHttp: boolean },
): string {
  const { field, issuerId, allowInsecureHttp } = scope;
  const value = readString(record, field, issuerId);
  const protocol = URL.parse(value)?.protocol;

  if (protocol === 'http:' && !allowInsecureHttp) {
    throw invalid(
      `issuer "${issuerId}" has a plain http ${field}; use https, or set allowInsecureHttp: true for a loopback or test issuer`,
      { issuerId, field },
    );
  }

  if (protocol !== 'https:' && protocol !== 'http:') {
    throw invalid(
      `issuer "${issuerId}" has a ${field} that is not an absolute https URL`,
      { issuerId, field },
    );
  }

  return value;
}

/**
 * reads the required audience as a non-empty list
 * @param record the issuer record
 * @param issuerId the issuer named in errors
 * @returns the accepted audiences
 * @throws {OidcError} OIDC_CONFIG_INVALID when the audience is missing or empty
 */
function readAudience(
  record: Record<string, unknown>,
  issuerId: string,
): string[] {
  const value = record.audience;
  const audiences = typeof value === 'string' ? [value] : value;

  if (
    !Array.isArray(audiences) ||
    audiences.length === 0 ||
    audiences.some(
      (audience) => !(typeof audience === 'string' && audience !== ''),
    )
  ) {
    throw invalid(`issuer "${issuerId}" is missing audience`, {
      issuerId,
      field: 'audience',
    });
  }

  return audiences as string[];
}

/**
 * reads the optional algorithm list, refusing any algorithm outside the safe set
 * @param record the issuer record
 * @param issuerId the issuer named in errors
 * @returns the configured algorithms, or undefined to use discovery
 * @throws {OidcError} OIDC_CONFIG_INVALID when the list is empty or lists an unsafe algorithm
 */
function readAlgorithms(
  record: Record<string, unknown>,
  issuerId: string,
): string[] | undefined {
  const value = record.algorithms;
  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value) || value.length === 0) {
    throw invalid(
      `issuer "${issuerId}" has an empty or malformed algorithms list`,
      { issuerId, field: 'algorithms' },
    );
  }

  const unsafe = value.filter(
    (algorithm) => typeof algorithm !== 'string' || !isSafeAlgorithm(algorithm),
  );
  if (unsafe.length > 0) {
    throw invalid(
      `issuer "${issuerId}" lists unsafe algorithms: ${unsafe.map(String).join(', ')}`,
      { issuerId, field: 'algorithms' },
    );
  }

  return value as string[];
}

/**
 * parses a template field
 * @param value the raw template
 * @param field the field name, for error context
 * @param issuerId the issuer named in errors
 * @returns the parsed template
 * @throws {OidcError} OIDC_CONFIG_INVALID when the template is missing or malformed
 */
function readTemplate(
  value: unknown,
  field: string,
  issuerId: string,
): Template {
  if (typeof value !== 'string') {
    throw invalid(`issuer "${issuerId}" is missing ${field}`, {
      issuerId,
      field,
    });
  }

  try {
    return parseTemplate(value);
  } catch (exception) {
    throw new OidcError(
      'OIDC_CONFIG_INVALID',
      `issuer "${issuerId}" has a malformed ${field}: ${(exception as Error).message}`,
      { cause: exception, meta: { issuerId, field } },
    );
  }
}

/**
 * parses the required group templates
 * @param record the issuer record
 * @param issuerId the issuer named in errors
 * @returns the parsed templates
 * @throws {OidcError} OIDC_CONFIG_INVALID when the list is missing or any template is malformed
 */
function readTemplates(
  record: Record<string, unknown>,
  issuerId: string,
): Template[] {
  const value = record.groupTemplates;
  if (!Array.isArray(value)) {
    throw invalid(`issuer "${issuerId}" is missing groupTemplates`, {
      issuerId,
      field: 'groupTemplates',
    });
  }

  return value.map((template: unknown) =>
    readTemplate(template, 'groupTemplates', issuerId),
  );
}

/**
 * reads an optional boolean
 * @param record the issuer record
 * @param scope the field, the issuer named in errors and the default
 * @param scope.field the field name
 * @param scope.issuerId the issuer named in errors
 * @param scope.fallback the value when the field is absent
 * @returns the flag
 * @throws {OidcError} OIDC_CONFIG_INVALID when the value is not a boolean
 */
function readOptionalBoolean(
  record: Record<string, unknown>,
  scope: { field: string; issuerId: string; fallback: boolean },
): boolean {
  const { field, issuerId, fallback } = scope;
  const value = record[field] ?? fallback;
  if (typeof value !== 'boolean') {
    throw invalid(`issuer "${issuerId}" has a non-boolean ${field}`, {
      issuerId,
      field,
    });
  }

  return value;
}

/**
 * compiles the allow list, requiring every entry to name the match claim
 * @param record the issuer record
 * @param scope the issuer's id, trust-scope claim and case sensitivity
 * @returns the compiled allow entries
 * @throws {OidcError} OIDC_CONFIG_INVALID when the list is empty, or an entry is malformed or lacks the match claim
 */
function readAllow(
  record: Record<string, unknown>,
  scope: AllowScope,
): AllowEntry[] {
  const { issuerId, matchClaim, isCaseInsensitive } = scope;
  const value = record.allow;
  if (!Array.isArray(value) || value.length === 0) {
    throw invalid(`issuer "${issuerId}" has an empty allow list`, {
      issuerId,
      field: 'allow',
    });
  }

  return value.map((entryInput: unknown, index) => {
    const label = `issuer "${issuerId}" allow[${index}]`;
    const entry = readRecord(entryInput, label, { issuerId, field: 'allow' });

    if (!Object.hasOwn(entry, matchClaim)) {
      throw invalid(
        `issuer "${issuerId}" allow[${index}] does not name its matchClaim "${matchClaim}"`,
        { issuerId, field: 'allow' },
      );
    }

    return Object.entries(entry).map(([claim, patternInput]) => {
      const patterns: unknown[] = Array.isArray(patternInput)
        ? patternInput
        : [patternInput];

      if (
        patterns.length === 0 ||
        patterns.some(
          (pattern) => !(typeof pattern === 'string' && pattern !== ''),
        )
      ) {
        throw invalid(
          `issuer "${issuerId}" allow[${index}].${claim} must be a non-empty pattern or list of patterns`,
          { issuerId, field: 'allow' },
        );
      }

      return {
        claim,
        patterns: (patterns as string[]).map((pattern) =>
          compilePattern(pattern, { isCaseInsensitive }),
        ),
        sources: patterns as string[],
      };
    });
  });
}

/**
 * reads an optional non-negative integer option
 * @param record the plugin config record
 * @param field the option name
 * @param fallback the default
 * @returns the value
 * @throws {OidcError} OIDC_CONFIG_INVALID when the value is not a non-negative integer
 */
function readNonNegativeInteger(
  record: Record<string, unknown>,
  field: string,
  fallback: number,
): number {
  const value = record[field] ?? fallback;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw invalid(`${field} must be a non-negative integer`, { field });
  }

  return value;
}

/**
 * creates a startup configuration error
 * @param message what is wrong
 * @param meta the issuer id and field involved
 * @returns the error to throw
 */
function invalid(message: string, meta: Record<string, unknown>): OidcError {
  return new OidcError('OIDC_CONFIG_INVALID', message, { meta });
}
