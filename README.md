# Web Security 101

**Goal:** Learn web security concepts practically. 

- Authentication **methods** and trade-offs
- Authentication **frameworks** (OAuth2)
- SSO

## Authentication

Security process of verifying the identity of a
(i) user,
(ii) device,
(iii) or system
to prove they are who they claim to be.

### Types

- Basic
- Digest
- API Keys
- Session
- Bearer & JWT Tokens
- Access & Refresh Tokens
- OAuth2 
- OpenID Connect
- OSS (SAML,  OIDC, OAuth2)

### Flow
```mermaid
flowchart TD

login([Login Request])
who{Who is User?}


subgraph ValidIdentity
    confirmed[Identity Confirmed]
    access([Grand Access])
end

subgraph InvalidIdentity
    notconfirmed[Identity Not Confirmed]
    reject([Reject with 401 Unauthorized])
end

gateway[API Gateway]

login-->who
who-- Valid -->confirmed
who-- Invalid -->notconfirmed


access -- Enter System --> gateway

confirmed-->access
notconfirmed-->reject
```

