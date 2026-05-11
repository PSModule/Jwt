# Jwt

`Jwt` is a PowerShell module for creating and verifying JSON Web Tokens. This repository maintains the current `Jwt` module command surface under PSModule maintenance so existing users can continue to install and use the package from PowerShell Gallery.

## Installation

```powershell
Install-PSResource -Name Jwt
Import-Module -Name Jwt
```

## Commands

The maintained module exports the same JWT commands and alias used by the current package:

```powershell
ConvertFrom-Base64UrlString
ConvertTo-Base64UrlString
Get-JwtHeader
Get-JwtPayload
New-Jwt
Test-Jwt
Verify-JwtSignature
```

## Usage

Create and validate an HMAC-signed JWT:

```powershell
$header = '{"alg":"HS256","typ":"JWT"}'
$payload = '{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}'
$secret = 'a-string-secret-at-least-256-bits-long'

$jwt = New-Jwt -Header $header -PayloadJson $payload -Secret $secret
Test-Jwt -jwt $jwt -Secret $secret
```

Read the header and payload from an existing token:

```powershell
Get-JwtHeader -jwt $jwt
Get-JwtPayload -jwt $jwt
```

For more information about each command, use PowerShell help:

```powershell
Get-Command -Module Jwt
Get-Help New-Jwt -Full
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
