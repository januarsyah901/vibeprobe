import { describe, expect, it } from 'vitest';
import { isInternalAddress, isLocalHost, isLoopbackAddress, Scope, ScopeError } from '../src';

describe('isLocalHost', () => {
  it.each(['localhost', 'LOCALHOST', 'localhost.', 'app.localhost', '127.0.0.1', '127.8.9.10', '[::1]', '::1', '::ffff:127.0.0.1'])(
    'treats %s as local',
    (host) => expect(isLocalHost(host)).toBe(true),
  );

  it.each(['localhost.evil.com', 'evillocalhost', 'example.com', '10.0.0.1', '0.0.0.0', '::', '::ffff:10.0.0.1', '192.168.1.1'])(
    'treats %s as not local',
    (host) => expect(isLocalHost(host)).toBe(false),
  );
});

describe('address classes', () => {
  it('detects loopback', () => {
    expect(isLoopbackAddress('127.0.0.1')).toBe(true);
    expect(isLoopbackAddress('::1')).toBe(true);
    expect(isLoopbackAddress('8.8.8.8')).toBe(false);
  });

  it.each(['10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', 'fd00::1', 'fe80::1', '::ffff:192.168.0.1'])(
    '%s is internal',
    (ip) => expect(isInternalAddress(ip)).toBe(true),
  );

  it.each(['8.8.8.8', '172.32.0.1', '2606:4700::1111'])('%s is public', (ip) =>
    expect(isInternalAddress(ip)).toBe(false),
  );
});

describe('Scope.assertUrl', () => {
  const scope = new Scope({ verifiedHosts: ['myapp.example'] });

  it.each(['http://localhost:3000/', 'https://127.0.0.1/', 'http://[::1]:8080/x', 'http://api.localhost/', 'https://myapp.example/'])(
    'allows %s',
    (u) => expect(() => scope.assertUrl(new URL(u))).not.toThrow(),
  );

  it.each([
    'http://example.com/',
    'http://localhost.evil.com/',
    'http://10.0.0.1/',
    'http://169.254.169.254/latest/meta-data/',
    'http://0.0.0.0:3000/',
    'file:///etc/passwd',
    'ftp://localhost/',
    'http://user:pass@localhost/',
    'http://sub.myapp.example/',
  ])('rejects %s', (u) => expect(() => scope.assertUrl(new URL(u))).toThrow(ScopeError));

  it('allows nothing public by default', () => {
    expect(() => new Scope().assertUrl(new URL('https://myapp.example/'))).toThrow(ScopeError);
  });
});

describe('Scope.assertResolvedAddress', () => {
  const scope = new Scope({ verifiedHosts: ['myapp.example'] });

  it('keeps local names on loopback', () => {
    expect(() => scope.assertResolvedAddress('app.localhost', '127.0.0.1')).not.toThrow();
    expect(() => scope.assertResolvedAddress('app.localhost', '93.184.216.34')).toThrow(ScopeError);
  });

  it('keeps verified names off internal ranges', () => {
    expect(() => scope.assertResolvedAddress('myapp.example', '93.184.216.34')).not.toThrow();
    expect(() => scope.assertResolvedAddress('myapp.example', '10.0.0.5')).toThrow(ScopeError);
    expect(() => scope.assertResolvedAddress('myapp.example', '127.0.0.1')).toThrow(ScopeError);
  });

  it('rejects unverified names whatever they resolve to', () => {
    expect(() => scope.assertResolvedAddress('other.example', '93.184.216.34')).toThrow(ScopeError);
  });
});
