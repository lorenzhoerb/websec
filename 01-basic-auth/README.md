# Basic Auth

```
Authorization: Basic <credentials>
```

Credentials is `base64` encoded string `<username>:<password>`

## Trade-offs

- ✅ Simple
- ⚠️ Only secure over HTTPS
- ⚠️ Always sends username and password

