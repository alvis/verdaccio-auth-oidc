import { describe, expect, it } from 'vitest';

import { OidcError } from '#errors';

describe('cl:OidcError', () => {
  it('should carry its code and context', () => {
    const error = new OidcError('OIDC_NOT_ALLOWED', 'not allowed', {
      meta: { issuerId: 'gha' },
    });

    expect({
      code: error.code,
      meta: error.meta,
      message: error.message,
    }).toEqual({
      code: 'OIDC_NOT_ALLOWED',
      meta: { issuerId: 'gha' },
      message: 'not allowed',
    });
  });

  it('should keep the cause of a wrapped failure', () => {
    const cause = new TypeError('fetch failed');

    const error = new OidcError('OIDC_DISCOVERY_FAILED', 'discovery failed', {
      cause,
    });

    expect(error.cause).toBe(cause);
  });
});
