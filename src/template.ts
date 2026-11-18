import { OidcError } from '#errors';

import type {
  Claims,
  ResolvedPluginConfig,
  Template,
  TemplateSegment,
} from '#types';

/** a template that renders claim text with no fixed prefix, reported at startup */
export interface PrefixlessTemplate {
  /** the issuer the template belongs to */
  issuerId: string;
  /** the config field holding the template */
  field: 'usernameTemplate' | 'groupTemplates';
  /** the template as written in config */
  source: string;
}

/** options for {@link renderTemplate} */
export interface RenderTemplateOptions {
  /** whether to lower-case the rendered result */
  isLowerCase?: boolean;
}

// a template is literal text with `{claim}` placeholders and no stray braces
const templateRegex = /^(?:[^{}]|\{[\w.-]+\})*$/;
const segmentRegex = /\{([\w.-]+)\}|[^{}]+/g;

/**
 * parses a `{claim}` template once, at startup
 * @param source the template as written in config
 * @returns the parsed template
 * @throws {OidcError} OIDC_CONFIG_INVALID when the template is empty or has an unbalanced or empty placeholder
 */
export function parseTemplate(source: string): Template {
  if (!source || !templateRegex.test(source)) {
    throw new OidcError(
      'OIDC_CONFIG_INVALID',
      `malformed template "${source}": use literal text with {claim} placeholders`,
      { meta: { template: source } },
    );
  }

  const segments = [...source.matchAll(segmentRegex)].map(
    ([text, claim]): TemplateSegment =>
      claim === undefined
        ? { kind: 'literal', text }
        : { kind: 'claim', claim },
  );

  return { source, segments };
}

/**
 * checks whether a template fixes some literal text before its first claim placeholder
 * @param template the parsed template
 * @returns false when the template starts with a placeholder
 */
export function hasLiteralPrefix(template: Template): boolean {
  return template.segments[0]?.kind !== 'claim';
}

/**
 * lists the templates that start with a claim, whose rendered names an issuer's claims fully control
 * @param config the resolved plugin config
 * @returns every user name or group template with no literal text before its first placeholder
 */
export function listPrefixlessTemplates(
  config: ResolvedPluginConfig,
): PrefixlessTemplate[] {
  return config.issuers.flatMap(
    ({ id: issuerId, usernameTemplate, groupTemplates }) =>
      [
        { field: 'usernameTemplate' as const, template: usernameTemplate },
        ...groupTemplates.map((template) => ({
          field: 'groupTemplates' as const,
          template,
        })),
      ]
        .filter(({ template }) => !hasLiteralPrefix(template))
        .map(({ field, template }) => ({
          issuerId,
          field,
          source: template.source,
        })),
  );
}

/**
 * renders a parsed template from verified claims
 * @param template the parsed template
 * @param claims verified token claims
 * @param options rendering options
 * @returns the rendered text
 * @throws {OidcError} OIDC_TEMPLATE_CLAIM_MISSING when a placeholder's claim is absent, empty or not a scalar
 */
export function renderTemplate(
  template: Template,
  claims: Claims,
  options?: RenderTemplateOptions,
): string {
  const rendered = template.segments
    .map((segment) =>
      segment.kind === 'literal'
        ? segment.text
        : readScalarClaim(claims, segment.claim, template),
    )
    .join('');

  return options?.isLowerCase ? rendered.toLowerCase() : rendered;
}

/**
 * reads a claim that a template placeholder renders
 * @param claims verified token claims
 * @param claim the claim name
 * @param template the template being rendered, for error context
 * @returns the claim as text
 * @throws {OidcError} OIDC_TEMPLATE_CLAIM_MISSING when the claim is absent, empty or not a scalar
 */
function readScalarClaim(
  claims: Claims,
  claim: string,
  template: Template,
): string {
  const value = claims[claim];

  if (
    typeof value === 'number' ||
    typeof value === 'boolean' ||
    (typeof value === 'string' && value !== '')
  ) {
    return String(value);
  }

  throw new OidcError(
    'OIDC_TEMPLATE_CLAIM_MISSING',
    `claim "${claim}" required by template "${template.source}" is missing or not a scalar`,
    { meta: { claim, template: template.source } },
  );
}
