# OAuth2: Authorization Code Flow

This is a standard OAuth2 authorization code flow.

The `ClientApplication` initiates the flow by redirecting the the browser to the `/authorize` endpoint.
It also provides 
(i) the `redirect_uri`, 
(ii) the `client_id`, and
(iii) the `state`.
The `redirect_uri` is usually a handler endpoints of the `ClientApplication` so it can obtain the `authorization_token`.
The `AuthServer` has client registered by client_id and with their allowed return_uri's.
The `AuthServer` validates the client_id and the redirect uri properties  of the /authorize request to its registered ones. 
If valid it checks if the user is already authenticated.
This is done by looking up the cookie session. 

IF session is valid it creates, registers and returns the `authorization code`, by redirecting the browser to the original provided redirect_uri. 

IF the session is NOT VALID, the user has to authenticate.
The auth server redirects the users to /login pages.
The user enters their credentials and the server checks them.

If valid a session is created and the user is redirected to the /authorize endpoint with `SET-Cookie=session_id`.

The same /authorize checks are down as before, but now the user obtains a valid session.

The auth server create the authorization token and redirects the user to the original provided redirect_uri with the code and state properties (e.g. /redirect_uri?code=...&state=...)

The `ClientApplication` receives the callback and checks its validity.
If valid, it can exchange it for the access token by POST /token.

Now the ClientApplication has token to request the resource.

**Error Handling.** For the /authorize endpoint errors are handled in two ways. 

1. When the client_id or redirect_uri is invalid, the user should not be redirected to the redirect_uri, because it could not be validated that this uri is "save". The RFC doesn't specify the way how handling this. 
Usually, BAD REQUEST is returned. 
2. For subsequent errors, the user can be redirected to the redirect_uri with the property error_code=... (e.g. /redirect_uri?error_code=invalid_request)

Typical error codes include:
- invalid_request: missing or invalid request parameters
- unauthorized_client: client is not authorized to use this grant type
- access_denied: User or authorization server denied request
- unsupported_response_type: unsupported response type

```mermaid
sequenceDiagram

participant b as Browser
participant c as ClientApplication
participant a as AuthorizationServer
actor u as User

b->>c: Access Application
c->>b: Redirect to /authorize
b->>a: GET /authorize?client_id=...&redirect_uri=...state=...

a->>a: validate client_id and return_uri
a->>a: check login session


alt no valid session

    %% login user
    a->>b: redirect to /login?return_to=...
    b->>a: GET /login
    a->>b: display login page
    u->>b: enter credentials
    b->>a: POST /login
    a->>a: validate credentials
    a->>a: create session
    a->>b: Set-Cookie: session_id=...
    a->>b: redirect to original /authorize URL
    a->>a: GET /authorize
else valid session
    a->>a: validate authentication request
    a->>a: check user consent
    a->>a: generate authorization code
    a->>b: Redirect to redirect_uri?code=...&state=...
    b->>c: redirect with authorization code
    c->>a: POST /token (code + client authentication)
    a->>a: validate authorization code
    a->>a: consume code
    a->>c: return access_token
end
