# Digest Auth

```
Authorization: Digest <parameters>
```

Password is never sent, only a hash of it

## Flow

1. Client requests resource without credentials
2. Server responds `401` with `WWW-Authenticate: Digest realm, nonce, algorithm, qop`
3. Client calculates `response` and sends it with `username`, `realm`, `nonce`, `nc`, `cnonce`, `qop`
4. Server calculates the same hash and compares

## Response

```
HA1      = SHA-256(username:realm:password)
HA2      = SHA-256(method:uri)
response = SHA-256(HA1:nonce:nc:cnonce:qop:HA2)
```

- `nonce` random value from server, new for each challenge
- `cnonce` random value from client
- `nc` request counter

## Trade-offs

- ✅ Password not sent in plain text
- ✅ Nonce makes every response different
- ⚠️ Server needs the password (or HA1) to verify, no bcrypt/argon2 possible
- ⚠️ Leaked HA1 is enough to log in
- ⚠️ Fast hash, easy to brute force offline
- ⚠️ Extra round trip for every new nonce
- ⚠️ Server has to track nonces and `nc` (stateful)
- ⚠️ Only credentials are protected, body is plain text, so still use HTTPS
- ⚠️ Bad client support, no logout, no custom login form
- ⚠️ This example doesn't check the nonce, so replay is possible
