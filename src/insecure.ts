import type { ResolvedPluginConfig } from '#types';

/** a configured URL that allowInsecureHttp leaves open to plain http although it names a host off the local machine, reported at startup */
export interface InsecureHttpUrl {
  /** the issuer that sets allowInsecureHttp */
  issuerId: string;
  /** the config field holding the URL */
  field: 'issuer' | 'jwksUri';
  /** the URL as written in config */
  url: string;
}

// hosts that never leave the machine: localhost, 127.0.0.0/8 and ::1; a *.localhost name may resolve through DNS, so it is not one of them
const loopbackHostRegex = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])$/i;

/**
 * lists the configured URLs of issuers that allow plain http but point at a host other than loopback
 *
 * allowInsecureHttp exists for loopback and test issuers; on any other host it lets a network attacker serve discovery or keys
 * @param config the resolved plugin config
 * @returns every issuer or jwksUri URL of an allowInsecureHttp issuer whose host is not loopback
 */
export function listInsecureHttpUrls(
  config: ResolvedPluginConfig,
): InsecureHttpUrl[] {
  return config.issuers
    .filter(({ allowInsecureHttp }) => allowInsecureHttp)
    .flatMap(({ id: issuerId, issuer, jwksUri }) =>
      [
        { field: 'issuer' as const, url: issuer },
        ...(jwksUri === undefined
          ? []
          : [{ field: 'jwksUri' as const, url: jwksUri }]),
      ]
        .filter(({ url }) => !isLoopbackUrl(url))
        .map(({ field, url }) => ({ issuerId, field, url })),
    );
}

/**
 * checks whether a URL names a host on the local machine
 * @param url an absolute URL already validated by the config parser
 * @returns true for localhost, a 127.0.0.0/8 address or ::1
 */
function isLoopbackUrl(url: string): boolean {
  return loopbackHostRegex.test(new URL(url).hostname);
}
