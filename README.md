# Jwt

A PowerShell module for creating, parsing, validating, and inspecting JSON Web Tokens (JWT), and for converting keys to and from the JSON Web Key (JWK) format.

The module implements the JOSE family of specs — [RFC 7519 (JWT)](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 7515 (JWS)](https://datatracker.ietf.org/doc/html/rfc7515), [RFC 7517 (JWK)](https://datatracker.ietf.org/doc/html/rfc7517), and [RFC 7518 (JWA)](https://datatracker.ietf.org/doc/html/rfc7518) — using only the .NET BCL (`System.Security.Cryptography`); no third-party dependencies.

## Prerequisites

- [PowerShell 7.6+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell). Windows PowerShell 5.1 is not supported.
- The [PSModule framework](https://github.com/PSModule/Process-PSModule) for building, testing and publishing the module.

## Installation

```powershell
Install-PSResource -Name Jwt
Import-Module -Name Jwt
```

## Public functions

| Function | Purpose |
| -------- | ------- |
| `New-Jwt` | Create a JWT from header values and a claims hashtable. Signs with a local key by default; `-Unsigned` produces `header.payload.` for external signing. |
| `ConvertFrom-Jwt` | Parse a compact JWT string into a typed `[Jwt]` object (no validation). |
| `Test-Jwt` | Verify the signature and validate registered claims (`exp`, `nbf`, `iat`, `iss`, `aud`). |
| `Get-JwtHeader` | Return the parsed `[JwtHeader]` from a JWT string or `[Jwt]`. |
| `Get-JwtPayload` | Return the parsed `[JwtPayload]` from a JWT string or `[Jwt]`. |
| `Get-JwtClaim` | Return one or more named claim values (single name → value, array → ordered hashtable). |
| `ConvertTo-JwtKey` | Convert a .NET `RSA`, `ECDsa`, or `byte[]` into a `[JwtKey]` (JWK). |
| `ConvertFrom-JwtKey` | Convert a `[JwtKey]` into a usable .NET `RSA`, `ECDsa`, or `byte[]`. |

Supported algorithms: `RS256`, `HS256`, `ES256`. Additional algorithms are tracked in follow-up issues.

## Usage

### Create a signed JWT (RS256)

```powershell
$pem = Get-Content ./private.pem -Raw
$jwt = New-Jwt -Payload @{
    iss = 'my-app'
    sub = 'service-account'
    aud = 'https://api.example.com'
    exp = [DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
} -Key $pem -Algorithm RS256

$jwt.ToString()   # the compact wire form: header.payload.signature
```

### Create an unsigned JWT and attach an external signature

For scenarios where the private key lives in [Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys), an HSM, or another remote signer, build the unsigned token, send `SigningInput()` to the signer, and assign the resulting Base64URL signature back onto the object.

```powershell
$jwt = New-Jwt -Payload @{ iss = 'my-app' } -Unsigned -Algorithm RS256
$jwt.ToString()                # ends with a trailing dot
$signingInput = $jwt.SigningInput()   # "header.payload"
# ... compute $base64UrlSignature externally against $signingInput ...
$jwt.Signature = $base64UrlSignature
$jwt.ToString()                # full header.payload.signature
```

### Parse a JWT (no validation)

```powershell
$parsed = $tokenString | ConvertFrom-Jwt
$parsed.Header
$parsed.Payload
```

### Inspect a token

```powershell
$tokenString | Get-JwtHeader
$tokenString | Get-JwtPayload

# Single name returns the value (or $null if absent)
$tokenString | Get-JwtClaim -Name iss

# Multiple names return an ordered hashtable
$tokenString | Get-JwtClaim -Name iss, sub, scope
```

### Validate a JWT

```powershell
$tokenString | Test-Jwt -Key $publicPem -Issuer 'my-app' -Audience 'https://api.example.com'

# Detailed per-check output
$tokenString | Test-Jwt -Key $publicPem -Detailed
```

`Test-Jwt` enforces algorithm-key compatibility *before* any signature work to block algorithm-confusion attacks (for example, presenting an `HS256` token to a verifier holding an RSA public key throws a terminating error).

### Work with JWKs

```powershell
# RSA → JWK
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$jwk = ConvertTo-JwtKey -Key $rsa -Use sig -Alg RS256 -Kid key-1 -IncludePrivate

# JWK → RSA
$rsaFromJwk = ConvertFrom-JwtKey -JwtKey $jwk
```

## Documentation

For per-command help:

```powershell
Get-Command -Module Jwt
Get-Help New-Jwt -Full
Get-Help Test-Jwt -Full
```

## Contributing

Coder or not, you can contribute to the project! We welcome all contributions.

### For Users

If you don't code, you still sit on valuable information that can make this project even better. If you experience that the
product does unexpected things, throw errors or is missing functionality, you can help by submitting bugs and feature requests.
Please see the issues tab on this project and submit a new issue that matches your needs.

### For Developers

If you do code, we'd love to have your contributions. Please read the [Contribution guidelines](CONTRIBUTING.md) for more information.
You can either help by picking up an existing issue or submit a new one if you have an idea for a new feature or improvement.

## Acknowledgements

Here is a list of people and projects that helped this project in some way.
