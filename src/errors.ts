import { Xception } from 'xception';

/** machine-readable codes for every failure this plugin raises */
export type OidcErrorCode =
  | 'OIDC_CONFIG_INVALID'
  | 'OIDC_DISCOVERY_FAILED'
  | 'OIDC_FALLBACK_UNAVAILABLE'
  | 'OIDC_NOT_ALLOWED'
  | 'OIDC_TEMPLATE_CLAIM_MISSING'
  | 'OIDC_TOKEN_INVALID';

/** options for {@link OidcError} */
export interface OidcErrorOptions {
  /** upstream error */
  cause?: unknown;
  /** non-sensitive context, never a token or a full claim set */
  meta?: Record<string, unknown>;
}

const NAMESPACE = 'verdaccio-auth-oidc';

/** an error raised by this plugin, discriminated by its code */
export class OidcError extends Xception {
  /**
   * creates an error with a machine-readable code
   * @param code the failure code
   * @param message a human-readable explanation
   * @param options upstream cause and context
   */
  constructor(
    code: OidcErrorCode,
    message: string,
    options?: OidcErrorOptions,
  ) {
    super(message, {
      namespace: NAMESPACE,
      code,
      cause: options?.cause,
      meta: options?.meta,
    });
    this.name = 'OidcError';
  }
}
