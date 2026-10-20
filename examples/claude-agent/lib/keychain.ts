import { execFileSync } from 'node:child_process';

// The Anthropic API key is read from the macOS Keychain at run time and handed
// only to the agent subprocess's environment. It is never exported in a shell,
// never written to disk, and never logged.
export function anthropicApiKey(service = process.env.ANTHROPIC_KEYCHAIN_SERVICE ?? 'aegis-anthropic-api'): string {
  let key: string;
  try {
    key = execFileSync('security', ['find-generic-password', '-s', service, '-w'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    throw new Error(`no Keychain item with service "${service}"`);
  }
  // An OAuth token (sk-ant-oat...) would bill a subscription, not the API
  // credit. Refuse anything that is not an API key.
  if (!key.startsWith('sk-ant-api')) {
    throw new Error(`Keychain item "${service}" is not an Anthropic API key (sk-ant-api...)`);
  }
  return key;
}
