# Bearer Token (opaque)

```
Authorization: Bearer <token>
```

Random token issued once, sent instead of a password

## Flow

1. Client calls `POST /register`
2. Server generates a random token, stores its hash with username and issue time, returns the plaintext once
3. Client sends `Authorization: Bearer <token>` on every request
4. Server hashes the token, looks it up, checks expiry
5. `POST /revoke` deletes the record, token is dead immediately

```
curl -s -X POST localhost:8888/register -d '{"username":"alice"}'
curl -H "Authorization: Bearer <token>" localhost:8888/private
curl -X POST -H "Authorization: Bearer <token>" localhost:8888/revoke
```

## Token

- `wsec_` prefix + 32 random bytes (hex), from `crypto/rand`
- Prefix makes leaked tokens easy to spot for secret scanners
- No meaning on its own, all state lives on the server
- Only the SHA-256 hash is stored, a fast hash is fine because the token is high entropy (unlike passwords)

## Trade-offs

- ✅ Instant revocation
- ✅ Expiry and scopes can be added per token
- ✅ Not sent automatically by browsers, so no CSRF
- ⚠️ Lookup on every request (DB or cache)
- ⚠️ Whoever holds the token is the user (bearer), so HTTPS is required
- ⚠️ Client has to store it, `localStorage` is exposed to XSS
- ⚠️ This example keeps tokens in memory, they are lost on restart
- ⚠️ `/register` has no password, anyone can get a token for any name
- ⚠️ No refresh token, no rate limiting
