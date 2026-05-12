# Jwt

`Jwt` is a PowerShell module for creating, parsing, validating, and inspecting [JSON Web Tokens (RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519) and the JOSE specs it builds on ([RFC 7515 — JWS](https://datatracker.ietf.org/doc/html/rfc7515), [RFC 7517 — JWK](https://datatracker.ietf.org/doc/html/rfc7517), [RFC 7518 — JWA](https://datatracker.ietf.org/doc/html/rfc7518), [RFC 7638 — JWK Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)). All cryptography uses the .NET BCL — no third-party dependencies.

> **Breaking change in v2.** The v1 surface (`New-Jwt -PayloadJson`, `Test-Jwt -Cert`, etc.) has been replaced with a typed object model. See [Migration from v1](#migration-from-v1).

## Installation

```powershell
Install-PSResource -Name Jwt
Import-Module -Name Jwt
```

Requires PowerShell 7.6 or newer. Windows PowerShell 5.1 is not supported.

## Algorithms

| Family | Algorithms                          | Key shapes                                      |
| ------ | ----------------------------------- | ----------------------------------------------- |
| HMAC   | `HS256`, `HS384`, `HS512`           | `byte[]`, raw secret string, `SecureString`, `JwtKey` (kty=oct) |
| RSA    | `RS256`, `RS384`, `RS512`           | `RSA`, RSA PEM string, `JwtKey` (kty=RSA)       |
| RSA-PSS | `PS256`, `PS384`, `PS512`          | `RSA`, RSA PEM string, `JwtKey` (kty=RSA)       |
| ECDSA  | `ES256` (P-256), `ES384` (P-384), `ES512` (P-521) | `ECDsa`, EC PEM string, `JwtKey` (kty=EC) |
| None   | `none`                              | No key. Rejected by `Test-Jwt` unless `-AllowUnsigned` is supplied. |

The curve attached to an ECDSA key is checked against the algorithm's required curve before any signature work, and HMAC keys are rejected when supplied for an asymmetric algorithm — both block the classic [algorithm-confusion attack](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/).

## Public surface

| Function                | Purpose                                                                            |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `New-Jwt`               | Create a JWT from header overrides and a claims hashtable; sign locally or `-Unsigned` |
| `ConvertFrom-Jwt`       | Parse a compact JWT string into a typed `[Jwt]` (no validation)                    |
| `Test-Jwt`              | Verify the signature and registered claims (`exp`, `nbf`, `iss`, `aud`)            |
| `Get-JwtHeader`         | Return the parsed `[JwtHeader]` of a token                                         |
| `Get-JwtPayload`        | Return the parsed `[JwtPayload]` of a token                                        |
| `Get-JwtClaim`          | Return one or more named claims (registered or private)                            |
| `ConvertTo-JwtKey`      | Convert an `RSA` / `ECDsa` / `byte[]` into a `[JwtKey]` (JWK)                      |
| `ConvertFrom-JwtKey`    | Convert a `[JwtKey]` (JWK) back into a .NET key                                    |
| `ConvertTo-JwtKeySet`   | Wrap one or more `[JwtKey]` in a `[JwtKeySet]` (JWKS)                              |
| `ConvertFrom-JwtKeySet` | Parse a JWKS JSON document into a `[JwtKeySet]`                                    |
| `Get-JwtKeyFromSet`     | Look up a `[JwtKey]` in a `[JwtKeySet]` by `kid`                                   |
| `Get-JwtKeyThumbprint`  | Compute the RFC 7638 JWK thumbprint of a key (`SHA-256` / `SHA-384` / `SHA-512`)   |
| `ConvertTo-Base64UrlString` / `ConvertFrom-Base64UrlString` | Base64url codec helpers (RFC 4648 §5)          |

Public types: `[Jwt]`, `[JwtHeader]`, `[JwtPayload]`, `[JwtKey]`, `[JwtKeySet]`, `[JwtBase64Url]`.

## Create

### HS256 with a shared secret

```powershell
$jwt = New-Jwt -Payload @{
    sub   = '1234567890'
    name  = 'John Doe'
    admin = $true
    iat   = 1516239022
} -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'

$jwt.ToString()
```

### RS256 / PS256 with a local RSA key

```powershell
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
New-Jwt -Payload @{ sub = 'app'; iss = 'https://issuer'; exp = 1900000000 } `
    -Header @{ kid = 'key-1' } -Algorithm RS256 -Key $rsa

# RSA-PSS variant
New-Jwt -Payload @{ sub = 'app' } -Algorithm PS256 -Key $rsa
```

### ES256 / ES384 / ES512 with an EC key

```powershell
$ec = [System.Security.Cryptography.ECDsa]::Create(
    [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))   # P-256
New-Jwt -Payload @{ sub = 'app' } -Algorithm ES256 -Key $ec
```

### Unsigned token, sign externally (HSM / Azure Key Vault)

```powershell
$jwt = New-Jwt -Payload @{ sub = 'app' } -Algorithm RS256 -Unsigned
$jwt.SigningInput()              # 'header.payload' — feed this to your external signer
$jwt.Signature = $externalSig    # base64url signature returned by Key Vault / HSM
$jwt.ToString()
```

## Parse

```powershell
$parsed = ConvertFrom-Jwt -Token $compactString
$parsed.Header.alg
$parsed.Payload.sub
$parsed.Payload.AdditionalFields['groups']
```

## Inspect

```powershell
Get-JwtHeader  -Token $compactString
Get-JwtPayload -Token $compactString
Get-JwtClaim   -Token $compactString -Name 'sub'
Get-JwtClaim   -Token $compactString -Name @('sub', 'role', 'missing')   # ordered hashtable, $null for missing
```

`Get-JwtClaim` silently returns `$null` for a missing single claim; pass `-ErrorIfMissing` to escalate to non-terminating errors.

## Validate

```powershell
Test-Jwt -Token $compactString -Key $rsaPublic `
    -Issuer 'https://issuer' -Audience 'api' -ClockSkew ([timespan]::FromMinutes(2))

# Structured report
Test-Jwt -Token $compactString -Key $rsaPublic -Detailed
```

`-Detailed` returns:

```text
Valid              : True
SignatureValidated : True
Algorithm          : RS256
Checks             : @(
    @{ Name = 'Algorithm';   Passed = $true;  Reason = $null }
    @{ Name = 'Signature';   Passed = $true;  Reason = $null }
    @{ Name = 'Expiration';  Passed = $true;  Reason = $null }
    @{ Name = 'NotBefore';   Passed = $true;  Reason = $null }
    @{ Name = 'Issuer';      Passed = $true;  Reason = $null }
    @{ Name = 'Audience';    Passed = $true;  Reason = $null }
)
```

## Keys (JWK + JWKS + thumbprints)

```powershell
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$jwk = ConvertTo-JwtKey -Key $rsa -KeyId 'key-1' -Algorithm 'RS256'
$jwk.ToJson()

$rsa2 = ConvertFrom-JwtKey -Key $jwk

# RFC 7638 thumbprint, suitable as a stable kid
Get-JwtKeyThumbprint -Key $jwk                       # SHA-256 (default)
Get-JwtKeyThumbprint -Key $jwk -HashAlgorithm SHA384

# JWK Set — publish or consume a JWKS endpoint
$set  = $jwk1, $jwk2 | ConvertTo-JwtKeySet
$json = $set.ToJson()                                 # publish

$set2 = ConvertFrom-JwtKeySet -Json (Invoke-RestMethod 'https://issuer/.well-known/jwks.json' | ConvertTo-Json -Depth 100)
$key  = Get-JwtKeyFromSet -KeySet $set2 -KeyId (Get-JwtHeader $token).kid
Test-Jwt -Token $token -Key $key
```

Supported `kty`: `RSA`, `EC` (P-256 / P-384 / P-521), `oct` (HMAC).

## Roadmap

The v2 release covers the JWS half of JOSE end to end (RFC 7515 / 7517 / 7518 §3 / 7519 / 7638). The following are tracked as follow-ups:

- **JWE — RFC 7516 + RFC 7518 §4–§5.** `Protect-Jwt` / `Unprotect-Jwt` plus the full key-management and content-encryption matrix (`RSA-OAEP-256`, `A128/192/256KW`, `A128/192/256GCMKW`, `dir`, `ECDH-ES` family, `PBES2-*`, content algorithms `A128/192/256GCM`, `A128CBC-HS256` family). Not in scope for v2 because the surface is large and the AES-CBC-HMAC mode in particular requires careful constant-time MAC-then-decrypt to avoid padding-oracle bugs.
- **EdDSA — RFC 8037.** `Ed25519` and `Ed448` over the `OKP` key type. Blocked on first-party Ed25519 support landing in `System.Security.Cryptography`; the project's "no third-party dependencies" rule rules out a BouncyCastle workaround.
- **`RSA1_5` key wrap.** Spec-listed but Bleichenbacher-vulnerable. Will not be implemented; modern profiles use `RSA-OAEP-256`.

## Migration from v1

| v1                                                      | v2                                                                       |
| ------------------------------------------------------- | ------------------------------------------------------------------------ |
| `New-Jwt -Header '{...}' -PayloadJson '{...}' -Secret`  | `New-Jwt -Payload @{...} -Algorithm HS256 -Key $secret`                  |
| `New-Jwt -Cert $cert ...`                               | `$rsa = $cert.GetRSAPrivateKey(); New-Jwt -Key $rsa`                     |
| `Test-Jwt -Cert $cert ...`                              | `Test-Jwt -Key $rsa ...` (or `-Key $jwk`)                                |
| `Get-JwtHeader` / `Get-JwtPayload` returned strings     | Now return typed `[JwtHeader]` / `[JwtPayload]` objects                  |
| `Verify-JwtSignature` alias                             | Removed — use `Test-Jwt`                                                 |

## Contributing

Coder or not, you can contribute to the project! We welcome all contributions.

### For Users

If you don't code, you still sit on valuable information that can make this project even better. If you experience that the
product does unexpected things, throws errors, or is missing functionality, you can help by submitting bugs and feature requests.
Please see the issues tab on this project and submit a new issue that matches your needs.

### For Developers

If you do code, we'd love to have your contributions. Please read the [Contribution guidelines](CONTRIBUTING.md) for more information.
You can either help by picking up an existing issue or submit a new one if you have an idea for a new feature or improvement.
