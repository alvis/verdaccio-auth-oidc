import { describe, expect, it } from 'vitest';

import { parseConfig } from '#config';
import { listPrefixlessTemplates } from '#template';

const githubIssuer = {
  id: 'gha',
  issuer: 'https://token.actions.githubusercontent.com',
  audience: 'https://registry.example.com',
  usernameTemplate: 'gha:{repository}',
  groupTemplates: ['gha-org:{repository_owner}'],
  matchClaim: 'repository',
  allow: [{ repository: 'acme/*' }],
};

/**
 * copies the GitHub issuer config without one field
 * @param field the field to leave out
 * @returns the issuer config missing that field
 */
function omitField(field: keyof typeof githubIssuer): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(githubIssuer).filter(([key]) => key !== field),
  );
}

describe('fn:parseConfig', () => {
  it('should apply defaults and compile templates and allow patterns', () => {
    const result = parseConfig({
      issuers: [
        {
          id: 'gha',
          issuer: 'https://token.actions.githubusercontent.com',
          audience: 'https://registry.example.com',
          usernameTemplate: 'gha:{repository}',
          groupTemplates: ['gha-org:{repository_owner}'],
          matchClaim: 'repository',
          allow: [{ repository: 'acme/*' }],
        },
      ],
    });

    expect(result).toEqual({
      issuers: [
        {
          id: 'gha',
          issuer: 'https://token.actions.githubusercontent.com',
          audience: ['https://registry.example.com'],
          algorithms: undefined,
          jwksUri: undefined,
          allowInsecureHttp: false,
          usernameTemplate: {
            source: 'gha:{repository}',
            segments: [
              { kind: 'literal', text: 'gha:' },
              { kind: 'claim', claim: 'repository' },
            ],
          },
          groupTemplates: [
            {
              source: 'gha-org:{repository_owner}',
              segments: [
                { kind: 'literal', text: 'gha-org:' },
                { kind: 'claim', claim: 'repository_owner' },
              ],
            },
          ],
          matchClaim: 'repository',
          isCaseInsensitive: true,
          allow: [
            [
              {
                claim: 'repository',
                patterns: [new RegExp('^acme/[^/:]*$', 'iu')],
                sources: ['acme/*'],
              },
            ],
          ],
        },
      ],
      clockToleranceSeconds: 30,
      discoveryCooldownSeconds: 30,
      jwtCacheTtlSeconds: 300,
      jwtCacheMaxEntries: 1000,
    });
  });

  it('should reject a plain http issuer or jwksUri without allowInsecureHttp', () => {
    const httpIssuer = () =>
      parseConfig({
        issuers: [{ ...githubIssuer, issuer: 'http://issuer.example.com' }],
      });
    const httpJwksUri = () =>
      parseConfig({
        issuers: [
          { ...githubIssuer, jwksUri: 'http://issuer.example.com/jwks' },
        ],
      });

    expect(httpIssuer).toThrow(
      expect.objectContaining({
        code: 'OIDC_CONFIG_INVALID',
        meta: { issuerId: 'gha', field: 'issuer' },
      }),
    );
    expect(httpJwksUri).toThrow(
      expect.objectContaining({
        code: 'OIDC_CONFIG_INVALID',
        meta: { issuerId: 'gha', field: 'jwksUri' },
      }),
    );
  });

  it('should accept a plain http issuer and jwksUri with allowInsecureHttp: true', () => {
    const result = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          issuer: 'http://127.0.0.1:8080',
          jwksUri: 'http://127.0.0.1:8080/jwks',
          allowInsecureHttp: true,
        },
      ],
    });

    expect(result.issuers).toEqual([
      expect.objectContaining({
        issuer: 'http://127.0.0.1:8080',
        jwksUri: 'http://127.0.0.1:8080/jwks',
        allowInsecureHttp: true,
      }),
    ]);
  });

  it('should accept explicit options, audience and algorithm lists and case-sensitive patterns', () => {
    const result = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          audience: ['https://registry.example.com', 'npm'],
          algorithms: ['RS256', 'ES256'],
          matchCaseInsensitive: false,
          allow: [
            { repository: ['acme/app', 'acme/lib'], ref: 'refs/heads/*' },
          ],
        },
      ],
      clockToleranceSeconds: 0,
      discoveryCooldownSeconds: 60,
      jwtCacheTtlSeconds: 0,
      jwtCacheMaxEntries: 5,
    });

    expect(result).toEqual({
      issuers: [
        expect.objectContaining({
          audience: ['https://registry.example.com', 'npm'],
          algorithms: ['RS256', 'ES256'],
          isCaseInsensitive: false,
          allow: [
            [
              {
                claim: 'repository',
                patterns: [
                  new RegExp('^acme/app$', 'u'),
                  new RegExp('^acme/lib$', 'u'),
                ],
                sources: ['acme/app', 'acme/lib'],
              },
              {
                claim: 'ref',
                patterns: [new RegExp('^refs/heads/[^/:]*$', 'u')],
                sources: ['refs/heads/*'],
              },
            ],
          ],
        }),
      ],
      clockToleranceSeconds: 0,
      discoveryCooldownSeconds: 60,
      jwtCacheTtlSeconds: 0,
      jwtCacheMaxEntries: 5,
    });
  });

  it.each([
    { case: 'a missing config', input: undefined, meta: {} },
    { case: 'a list as config', input: [], meta: {} },
    { case: 'a missing issuers list', input: {}, meta: { field: 'issuers' } },
    {
      case: 'an empty issuers list',
      input: { issuers: [] },
      meta: { field: 'issuers' },
    },
    {
      case: 'an issuer that is not an object',
      input: { issuers: ['gha'] },
      meta: {},
    },
    {
      case: 'an issuer without an id',
      input: { issuers: [{ ...githubIssuer, id: '' }] },
      meta: { field: 'id' },
    },
    ...[
      { field: 'clockToleranceSeconds', value: -1 },
      { field: 'discoveryCooldownSeconds', value: 1.5 },
      { field: 'jwtCacheTtlSeconds', value: '300' },
      { field: 'jwtCacheMaxEntries', value: -10 },
    ].map(({ field, value }) => ({
      case: `${field} set to ${JSON.stringify(value)}`,
      input: { issuers: [githubIssuer], [field]: value },
      meta: { field },
    })),
  ])('should reject $case with OIDC_CONFIG_INVALID', ({ input, meta }) => {
    const result = () => parseConfig(input);

    expect(result).toThrow(
      expect.objectContaining({ code: 'OIDC_CONFIG_INVALID', meta }),
    );
  });

  it.each([
    ...(['issuer', 'audience', 'usernameTemplate', 'allow'] as const).map(
      (field) => ({ field, case: 'missing', issuer: omitField(field) }),
    ),
    ...[
      { field: 'matchCaseInsensitive', value: 'yes' },
      { field: 'allowInsecureHttp', value: 1 },
      { field: 'matchClaim', value: '' },
      { field: 'issuer', value: 'not a url' },
      { field: 'issuer', value: 'ftp://issuer.example.com' },
      { field: 'jwksUri', value: 'file:///etc/jwks.json' },
      { field: 'audience', value: [] },
      { field: 'audience', value: ['npm', ''] },
      { field: 'algorithms', value: [] },
      { field: 'algorithms', value: 'RS256' },
      { field: 'algorithms', value: ['RS256', 'HS256'] },
      { field: 'algorithms', value: ['none'] },
      { field: 'algorithms', value: [256] },
      { field: 'usernameTemplate', value: 'gha:{' },
      { field: 'groupTemplates', value: 'gha:{owner}' },
      { field: 'groupTemplates', value: ['gha:{}'] },
      { field: 'groupTemplates', value: [42] },
      { field: 'allow', value: [] },
      { field: 'allow', value: [{ repository: [] }] },
      { field: 'allow', value: [{ repository: '' }] },
      { field: 'allow', value: [{ repository: ['acme/*', 7] }] },
    ].map(({ field, value }) => ({
      field,
      case: JSON.stringify(value),
      issuer: { ...githubIssuer, [field]: value },
    })),
  ])(
    'should reject $field set to $case naming the issuer and field',
    ({ field, issuer }) => {
      const result = () => parseConfig({ issuers: [issuer] });

      expect(result).toThrow(
        expect.objectContaining({
          code: 'OIDC_CONFIG_INVALID',
          meta: { issuerId: 'gha', field },
        }),
      );
    },
  );

  it('should reject an allow entry that is not an object naming the issuer and field', () => {
    const result = () =>
      parseConfig({ issuers: [{ ...githubIssuer, allow: ['acme/*'] }] });

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_CONFIG_INVALID',
        meta: { issuerId: 'gha', field: 'allow' },
      }),
    );
  });

  it.each([
    { key: 'algorithm', value: ['ES256'], suggestion: 'algorithms' },
    {
      key: 'jwks_uri',
      value: 'https://keys.example.com/jwks',
      suggestion: 'jwksUri',
    },
    {
      key: 'matchCaseInsensitve',
      value: false,
      suggestion: 'matchCaseInsensitive',
    },
  ])(
    'should reject the misspelled key $key naming the issuer and key and suggesting $suggestion',
    ({ key, value, suggestion }) => {
      const result = () =>
        parseConfig({ issuers: [{ ...githubIssuer, [key]: value }] });

      expect(result).toThrow(
        expect.objectContaining({
          code: 'OIDC_CONFIG_INVALID',
          message: `issuer "gha" has an unknown key "${key}"; did you mean "${suggestion}"?`,
          meta: { issuerId: 'gha', field: key },
        }),
      );
    },
  );

  it('should reject an unknown key that resembles no issuer key without a suggestion', () => {
    const result = () =>
      parseConfig({ issuers: [{ ...githubIssuer, environment: 'npmjs' }] });

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_CONFIG_INVALID',
        message: 'issuer "gha" has an unknown key "environment"',
        meta: { issuerId: 'gha', field: 'environment' },
      }),
    );
  });

  it('should accept unknown keys at the plugin level', () => {
    const result = parseConfig({
      issuers: [githubIssuer],
      max_users: -1,
      secret: 'verdaccio-secret',
    });

    expect(result.issuers).toEqual([expect.objectContaining({ id: 'gha' })]);
  });

  it('should reject duplicate issuer URLs', () => {
    const result = () =>
      parseConfig({
        issuers: [githubIssuer, { ...githubIssuer, id: 'gha-again' }],
      });

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_CONFIG_INVALID',
        meta: { field: 'issuer' },
      }),
    );
  });

  it.each([
    { case: 'a matchClaim it does not list', matchClaim: 'repository_owner' },
    { case: 'a matchClaim it only inherits', matchClaim: 'toString' },
  ])('should reject an allow entry that names $case', ({ matchClaim }) => {
    const result = () =>
      parseConfig({ issuers: [{ ...githubIssuer, matchClaim }] });

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_CONFIG_INVALID',
        meta: { issuerId: 'gha', field: 'allow' },
      }),
    );
  });
});

describe('fn:listPrefixlessTemplates', () => {
  it('should list the user name and group templates that start with a claim', () => {
    const config = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          usernameTemplate: '{repository}',
          groupTemplates: ['gha-org:{repository_owner}', '{repository_owner}'],
        },
      ],
    });

    const result = listPrefixlessTemplates(config);

    expect(result).toEqual([
      { issuerId: 'gha', field: 'usernameTemplate', source: '{repository}' },
      {
        issuerId: 'gha',
        field: 'groupTemplates',
        source: '{repository_owner}',
      },
    ]);
  });
});
