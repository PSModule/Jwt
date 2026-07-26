#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'ConvertFrom-JwtKey' {
    It 'converts a JWK back into a .NET key' {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $jwk = ConvertTo-JwtKey -Key $rsa
            (ConvertFrom-JwtKey -Key $jwk) | Should -BeOfType [System.Security.Cryptography.RSA]
        } finally {
            $rsa.Dispose()
        }
    }
}

