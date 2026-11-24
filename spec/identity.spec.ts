import { describe, expect, it } from 'vitest';

import { parseConfig } from '#config';
import { resolveIdentity } from '#identity';

const githubIssuer = {
  id: 'gha',
  issuer: 'https://token.actions.githubusercontent.com',
  audience: 'https://registry.example.com',
  usernameTemplate: 'gha:{repository}',
  groupTemplates: ['gha-org:{repository_owner}'],
  matchClaim: 'repository_owner',
  allow: [{ repository_owner: 'acme' }],
};

const [issuer] = parseConfig({ issuers: [githubIssuer] }).issuers;

describe('fn:resolveIdentity', () => {
  it('should map allowed claims to a lower-cased repository identity with an organization group', () => {
    const result = resolveIdentity(issuer!, {
      repository: 'Acme/App',
      repository_owner: 'Acme',
    });

    expect(result).toEqual({
      issuerId: 'gha',
      name: 'gha:acme/app',
      groups: ['gha-org:acme'],
    });
  });

  it('should reject claims no allow entry matches with OIDC_NOT_ALLOWED', () => {
    const result = () =>
      resolveIdentity(issuer!, {
        repository: 'evil/app',
        repository_owner: 'evil',
      });

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_NOT_ALLOWED',
        meta: { issuerId: 'gha' },
      }),
    );
  });

  it('should keep case when matchCaseInsensitive is false', () => {
    const [caseSensitiveIssuer] = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          matchCaseInsensitive: false,
          allow: [{ repository_owner: 'Acme' }],
        },
      ],
    }).issuers;

    const result = resolveIdentity(caseSensitiveIssuer!, {
      repository: 'Acme/App',
      repository_owner: 'Acme',
    });

    expect(result).toEqual({
      issuerId: 'gha',
      name: 'gha:Acme/App',
      groups: ['gha-org:Acme'],
    });
  });

  it('should list a group rendered twice only once', () => {
    const [overlappingIssuer] = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          groupTemplates: ['ci:{repository_owner}', 'ci:{organization}'],
        },
      ],
    }).issuers;

    const result = resolveIdentity(overlappingIssuer!, {
      repository: 'acme/app',
      repository_owner: 'acme',
      organization: 'acme',
    });

    expect(result).toEqual({
      issuerId: 'gha',
      name: 'gha:acme/app',
      groups: ['ci:acme'],
    });
  });
});
