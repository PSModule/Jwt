# Jwt

Jwt is a PowerShell module for creating, decoding, and verifying JSON Web Tokens (JWTs). It supports HS256
shared-secret tokens, RS256 certificate-signed tokens, and the `none` algorithm.

> [!WARNING]
> The `none` algorithm produces an unsigned token whose integrity cannot be verified. Avoid it for
> authentication or authorization; use HS256 or RS256 for any token that must be trusted.

## Installation

Install the module from the PowerShell Gallery:

```powershell
Install-PSResource -Name Jwt
Import-Module -Name Jwt
```

## Usage

### Example: Create and validate an HMAC-signed token

```powershell
$payload = '{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}'
$secret = 'a-string-secret-at-least-256-bits-long'

$jwt = New-Jwt -Header '{"alg":"HS256","typ":"JWT"}' -PayloadJson $payload -Secret $secret
$jwt | Test-Jwt -Secret $secret
```

### Example: Decode the payload of an existing token

```powershell
$jwt | Get-JwtPayload
```

## Documentation

Documentation is published at [psmodule.io/Jwt](https://psmodule.io/Jwt/).

Use PowerShell help and command discovery for module details:

```powershell
Get-Command -Module Jwt
Get-Help -Name New-Jwt -Examples
```
