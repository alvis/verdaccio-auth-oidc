import { describe, expect, it } from 'vitest';

import { parseTemplate, renderTemplate } from '#template';

describe('fn:renderTemplate', () => {
  it('should render claims into a lower-cased identity', () => {
    const template = parseTemplate('gha:{repository}');

    const result = renderTemplate(
      template,
      { repository: 'Acme/App' },
      { isLowerCase: true },
    );

    expect(result).toBe('gha:acme/app');
  });

  it('should render number and boolean claims and keep case by default', () => {
    const template = parseTemplate('Run:{run_number}:{is_main}');

    const result = renderTemplate(template, { run_number: 42, is_main: true });

    expect(result).toBe('Run:42:true');
  });

  it.each([
    { case: 'a missing claim', claims: {} },
    { case: 'an empty claim', claims: { repository: '' } },
    { case: 'an object claim', claims: { repository: { name: 'app' } } },
    { case: 'a list claim', claims: { repository: ['acme/app'] } },
  ])('should fail with OIDC_TEMPLATE_CLAIM_MISSING on $case', ({ claims }) => {
    const template = parseTemplate('gha:{repository}');

    const result = () => renderTemplate(template, claims);

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_TEMPLATE_CLAIM_MISSING',
        meta: { claim: 'repository', template: 'gha:{repository}' },
      }),
    );
  });
});

describe('fn:parseTemplate', () => {
  it.each([
    { case: 'an empty template', source: '' },
    { case: 'an unclosed placeholder', source: 'gha:{repository' },
    { case: 'an empty placeholder', source: 'gha:{}' },
    { case: 'a stray closing brace', source: 'gha:repository}' },
    { case: 'a placeholder with a space', source: 'gha:{repo name}' },
  ])('should reject $case with OIDC_CONFIG_INVALID', ({ source }) => {
    const result = () => parseTemplate(source);

    expect(result).toThrow(
      expect.objectContaining({
        code: 'OIDC_CONFIG_INVALID',
        meta: { template: source },
      }),
    );
  });
});
