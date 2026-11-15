import { OidcError } from '#errors';
import { matchesAllowEntries } from '#pattern';
import { renderTemplate } from '#template';

import type { Claims, Identity, ResolvedIssuer } from '#types';

/**
 * maps verified claims to a Verdaccio identity when an allow entry admits them
 * @param issuer the issuer that verified the claims
 * @param claims verified token claims
 * @returns the rendered user name and groups
 * @throws {OidcError} OIDC_NOT_ALLOWED when no allow entry matches the claims
 */
export function resolveIdentity(
  issuer: ResolvedIssuer,
  claims: Claims,
): Identity {
  if (!matchesAllowEntries(issuer.allow, claims)) {
    throw new OidcError(
      'OIDC_NOT_ALLOWED',
      `no allow entry of issuer "${issuer.id}" matches the token`,
      { meta: { issuerId: issuer.id } },
    );
  }

  const renderOptions = { isLowerCase: issuer.isCaseInsensitive };
  const groups = issuer.groupTemplates.map((template) =>
    renderTemplate(template, claims, renderOptions),
  );

  return {
    issuerId: issuer.id,
    name: renderTemplate(issuer.usernameTemplate, claims, renderOptions),
    groups: [...new Set(groups)],
  };
}
