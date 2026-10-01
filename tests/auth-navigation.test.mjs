import assert from 'node:assert/strict'
import { test } from 'node:test'
import { isTrustedAuthNavigation } from '../src/main/utils/auth-navigation.ts'

const connection = {
  url: 'https://chat.example.com/subpath',
  authOrigins: ['https://portal.example.com', 'https://accounts.example.com/']
}

test('keeps the full federated login and callback chain in one session', () => {
  for (const [from, to] of [
    ['https://chat.example.com', 'https://portal.example.com'],
    ['https://portal.example.com', 'https://accounts.example.com'],
    ['https://accounts.example.com', 'https://portal.example.com'],
    ['https://portal.example.com', 'https://chat.example.com']
  ]) {
    assert.equal(isTrustedAuthNavigation(from, to, connection), true)
  }
})

test('requires opt-in for each connection', () => {
  for (const config of [
    undefined,
    { url: connection.url },
    { url: connection.url, authOrigins: [] }
  ]) {
    assert.equal(
      isTrustedAuthNavigation('https://chat.example.com', 'https://portal.example.com', config),
      false
    )
  }
})

test('keeps unrelated origins, lookalike hosts and different schemes external', () => {
  for (const origin of [
    'https://other.example.com',
    'https://portal.example.com.evil.test',
    'http://portal.example.com',
    'https://portal.example.com:8443'
  ]) {
    assert.equal(isTrustedAuthNavigation('https://chat.example.com', origin, connection), false)
    assert.equal(isTrustedAuthNavigation(origin, 'https://chat.example.com', connection), false)
  }
})

test('ignores malformed and non-origin configuration entries', () => {
  for (const origin of [
    '*',
    'not a URL',
    'http://portal.example.com',
    'https://portal.example.com/path',
    'https://portal.example.com?query',
    'https://portal.example.com#fragment',
    'https://user:pass@portal.example.com',
    null,
    42
  ]) {
    assert.equal(
      isTrustedAuthNavigation('https://chat.example.com', 'https://portal.example.com', {
        url: connection.url,
        authOrigins: [origin]
      }),
      false
    )
  }
})

test('fails closed for invalid connection configuration', () => {
  assert.equal(
    isTrustedAuthNavigation('https://chat.example.com', 'https://portal.example.com', {
      url: 'invalid',
      authOrigins: connection.authOrigins
    }),
    false
  )
  assert.equal(
    isTrustedAuthNavigation('https://chat.example.com', 'https://portal.example.com', {
      url: connection.url,
      authOrigins: 'https://portal.example.com'
    }),
    false
  )
})

test('does not share authentication origins between connections', () => {
  assert.equal(
    isTrustedAuthNavigation('https://portal.example.com', 'https://chat.example.com', {
      url: 'https://another-chat.example.com',
      authOrigins: ['https://another-login.example.com']
    }),
    false
  )
})
