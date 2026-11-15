import { describe, expect, it } from 'vitest';

import { parseConfig } from '#config';
import { listInsecureHttpUrls } from '#insecure';

const githubIssuer = {
  id: 'gha',
  issuer: 'https://token.actions.githubusercontent.com',
  audience: 'https://registry.example.com',
  usernameTemplate: 'gha:{repository}',
  groupTemplates: ['gha-org:{repository_owner}'],
  matchClaim: 'repository',
  allow: [{ repository: 'acme/*' }],
};

describe('fn:listInsecureHttpUrls', () => {
  it('should list the issuer and jwksUri of an allowInsecureHttp issuer on a non-loopback host, whatever their protocol', () => {
    const config = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          id: 'remote',
          issuer: 'http://issuer.example.com',
          jwksUri: 'https://keys.example.com/jwks',
          allowInsecureHttp: true,
        },
        {
          ...githubIssuer,
          id: 'https-only-url',
          issuer: 'https://token.actions.githubusercontent.com',
          allowInsecureHttp: true,
        },
      ],
    });

    const result = listInsecureHttpUrls(config);

    expect(result).toEqual([
      {
        issuerId: 'remote',
        field: 'issuer',
        url: 'http://issuer.example.com',
      },
      {
        issuerId: 'remote',
        field: 'jwksUri',
        url: 'https://keys.example.com/jwks',
      },
      {
        issuerId: 'https-only-url',
        field: 'issuer',
        url: 'https://token.actions.githubusercontent.com',
      },
    ]);
  });

  it('should list a localhost subdomain, which may resolve through DNS', () => {
    const config = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          id: 'subdomain',
          issuer: 'http://localhost:8080',
          jwksUri: 'http://keys.test.localhost:8080/jwks',
          allowInsecureHttp: true,
        },
      ],
    });

    const result = listInsecureHttpUrls(config);

    expect(result).toEqual([
      {
        issuerId: 'subdomain',
        field: 'jwksUri',
        url: 'http://keys.test.localhost:8080/jwks',
      },
    ]);
  });

  it('should list nothing for loopback hosts or issuers without allowInsecureHttp', () => {
    const config = parseConfig({
      issuers: [
        {
          ...githubIssuer,
          id: 'localhost',
          issuer: 'http://localhost:8080',
          jwksUri: 'http://localhost:8080/jwks',
          allowInsecureHttp: true,
        },
        {
          ...githubIssuer,
          id: 'ipv4',
          issuer: 'http://127.10.0.1:8080',
          allowInsecureHttp: true,
        },
        {
          ...githubIssuer,
          id: 'ipv6',
          issuer: 'http://[::1]:8080',
          allowInsecureHttp: true,
        },
        { ...githubIssuer, id: 'secure', issuer: 'https://gitlab.com' },
      ],
    });

    const result = listInsecureHttpUrls(config);

    expect(result).toEqual([]);
  });
});
