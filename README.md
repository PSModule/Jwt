# Jwt

`Jwt` is a PowerShell module for creating, parsing, validating, and inspecting [JSON Web Tokens (RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519) and the JOSE specs it builds on ([RFC 7515 — JWS](https://datatracker.ietf.org/doc/html/rfc7515), [RFC 7517 — JWK](https://datatracker.ietf.org/doc/html/rfc7517), [RFC 7518 — JWA](https://datatracker.ietf.org/doc/html/rfc7518)). All cryptography uses the .NET BCL — no third-party dependencies.

> **Breaking change in v2.** The v1 surface (`New-Jwt -PayloadJson`, `Test-Jwt -Cert`, public `ConvertTo-Base64UrlString`, etc.) has been replaced with a typed object model. See [Migration from v1](#migration-from-v1).

## Installation

```powershell
Install-PSResource -Name Jwt
Import-Module -Name Jwt
```

Requires PowerShell 7.6 or newer. Windows PowerShell 5.1 is not supported.

## Public surface

| Function             | Purpose                                                                            |
| -------------------- | ---------------------------------------------------------------------------------- |
| `New-Jwt`            | Create a JWT from header overrides and a claims hashtable; sign locally or `-Unsigned` |
| `ConvertFrom-Jwt`    | Parse a compact JWT string into a typed `[Jwt]` (no validation)                    |
| `Test-Jwt`           | Verify the signature and registered claims (`exp`, `nbf`, `iss`, `aud`)            |
| `Get-JwtHeader`      | Return the parsed `[JwtHeader]` of a token                                         |
| `Get-JwtPayload`     | Return the parsed `[JwtPayload]` of a token                                        |
| `Get-JwtClaim`       | Return one or more named claims (registered or private)                            |
| `ConvertTo-JwtKey`   | Convert an `RSA` / `ECDsa` / `byte[]` into a `[JwtKey]` (JWK)                      |
| `ConvertFrom-JwtKey` | Convert a `[JwtKey]` (JWK) back into a .NET key                                    |

Public types: `[Jwt]`, `[JwtHeader]`, `[JwtPayload]`, `[JwtKey]`. Algorithms: `RS256`, `HS256`, `ES256`, plus `none` (rejected unless `-AllowUnsigned` is supplied to `Test-Jwt`).

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

### RS256 with a local RSA key

```powershell
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$jwt = New-Jwt -Payload @{ sub = 'app'; iss = 'https://issuer'; exp = 1900000000 } `
    -Header @{ kid = 'key-1' } -Algorithm RS256 -Key $rsa
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

`Test-Jwt` enforces an algorithm-key compatibility check **before** any signature work, blocking the [HS256-with-RSA-public-key algorithm-confusion attack](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/). Unknown / missing `alg` values are rejected. `alg=none` is rejected unless `-AllowUnsigned` is passed.

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

## Keys (JWK)

```powershell
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$jwk = ConvertTo-JwtKey -Key $rsa -KeyId 'key-1' -Algorithm 'RS256'
$jwk.ToJson()

$rsa2 = ConvertFrom-JwtKey -Key $jwk
```

Supported `kty`: `RSA`, `EC` (P-256 / P-384 / P-521), `oct` (HMAC).

## Migration from v1

| v1                                                      | v2                                                                       |
| ------------------------------------------------------- | ------------------------------------------------------------------------ |
| `New-Jwt -Header '{...}' -PayloadJson '{...}' -Secret`  | `New-Jwt -Payload @{...} -Algorithm HS256 -Key $secret`                  |
| `New-Jwt -Cert $cert ...`                               | Extract the RSA: `$rsa = $cert.GetRSAPrivateKey(); New-Jwt -Key $rsa`    |
| `Test-Jwt -Cert $cert ...`                              | `Test-Jwt -Key $rsa ...` (or `-Key $jwk`)                                |
| Public `ConvertTo-Base64UrlString` / `ConvertFrom-...`  | Now private. Internal helpers, not part of the supported surface.        |
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
