import { describe, expect, it } from 'vitest';
import { findPiiKeys, parseSetCookie } from '../src';

describe('parseSetCookie', () => {
  it('reads flags case-insensitively', () => {
    expect(parseSetCookie('sid=abc; Path=/; HttpOnly; SameSite=Lax; Secure')).toMatchObject({
      name: 'sid',
      value: 'abc',
      httpOnly: true,
      sameSite: true,
      secure: true,
    });
    expect(parseSetCookie('session=x; path=/')).toMatchObject({ httpOnly: false, sameSite: false, secure: false });
  });

  it('keeps "=" characters inside the value', () => {
    expect(parseSetCookie('t=a=b==; HttpOnly').value).toBe('a=b==');
  });
});

describe('findPiiKeys', () => {
  it('finds personal-data keys in arrays and nested objects', () => {
    expect([...findPiiKeys([{ id: 1, user: { Email: 'a@b.c' } }])]).toEqual(['Email']);
  });

  it('ignores harmless data', () => {
    expect(findPiiKeys([{ id: 1, name: 'Mug', price: 3 }]).size).toBe(0);
  });

  it('does not loop forever on deep data', () => {
    let deep: unknown = { email: 'x' };
    for (let i = 0; i < 50; i++) deep = { a: deep };
    expect(findPiiKeys(deep).size).toBe(0);
  });
});
