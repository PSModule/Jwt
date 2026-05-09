@{
    RootModule        = 'JWT.psm1'
    ModuleVersion     = '1.9.2'
    GUID              = 'd4592298-b1a3-4a7d-b6fc-2ac16cc0e722'
    Author            = 'Svyatoslav Pidgorny'
    CompanyName       = 'PSModule'
    Copyright         = '(c) 2025 PSModule'
    Description       = 'PowerShell module to create and verify JWTs, the JSON Web Tokens'
    FunctionsToExport = @(
        'ConvertFrom-Base64UrlString'
        'ConvertTo-Base64UrlString'
        'Get-JwtHeader'
        'Get-JwtPayload'
        'New-Jwt'
        'Test-Jwt'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @('Verify-JwtSignature')
    PrivateData       = @{
        PSData = @{
            Tags         = @('JWT', 'JSONWebToken', 'JWS', 'PowerShell')
            LicenseUri   = 'https://github.com/PSModule/Jwt/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/PSModule/Jwt'
            IconUri      = 'https://raw.githubusercontent.com/PSModule/Jwt/main/icon/icon.png'
            ReleaseNotes = 'Continuation release under PSModule maintenance preserving the public command surface and behavior of Jwt 1.9.1.'
        }
    }
}