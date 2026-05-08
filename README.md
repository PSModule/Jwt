# Jwt

A PowerShell module for creating and managing JSON Web Tokens (JWT).

## Prerequisites

- [PowerShell 7+](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell)
- The [PSModule framework](https://github.com/PSModule/Process-PSModule) for building, testing and publishing the module.

## Installation

```powershell
Install-PSResource -Name Jwt
Import-Module -Name Jwt
```

## Usage

`New-Jwt` builds a signed JWT from a payload (and optional header overrides) and returns a typed
`[Jwt]` object. Call `ToString()` for the compact `header.payload.signature` form used on the wire.

Only `RS256` is supported in this release. Two signing methods are available:

### Sign with a local RSA private key

```powershell
$now = [System.DateTimeOffset]::UtcNow
$jwt = New-Jwt `
    -Header  @{ kid = 'my-key-id' } `
    -Payload @{
        iss = 'my-app'
        iat = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } `
    -PrivateKey (Get-Content ./private-key.pem -Raw)

$jwt.ToString()  # header.payload.signature
```

The `-PrivateKey` parameter accepts either a PEM-encoded `[string]` or a `[securestring]`.

### Sign with Azure Key Vault

```powershell
$jwt = New-Jwt `
    -Payload @{ iss = 'my-app'; iat = $iat; exp = $exp } `
    -KeyVaultKeyReference 'https://myvault.vault.azure.net/keys/my-key'
```

Key Vault signing calls the [Sign REST API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign)
(`api-version=7.4`) and obtains a bearer token from the [Azure CLI](https://learn.microsoft.com/cli/azure/)
or [Az PowerShell](https://learn.microsoft.com/powershell/azure/), whichever is available. Neither
is declared as a module dependency — install and sign in with one of them before calling.

### Public surface

| Member | Kind     | Purpose                                                       |
|--------|----------|---------------------------------------------------------------|
| `New-Jwt`     | Function | Create and sign a JWT (RS256 via local key or Key Vault) |
| `Jwt`         | Class    | Token object; `ToString()` returns `header.payload.signature` |
| `JwtHeader`   | Class    | Typed JOSE header (`alg`, `typ`, `kid`, plus extension fields) |
| `JwtPayload`  | Class    | Typed payload (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, plus private claims) |
| `JwtBase64Url`| Class    | Base64URL encoding utilities ([RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5)) |

## Documentation

For more information about the module's functions and features, use:

```powershell
Get-Command -Module Jwt
Get-Help New-Jwt
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
