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

    It 'returns raw bytes for oct keys by default' {
        $secret = [System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long')
        $jwk = ConvertTo-JwtKey -Key $secret
        $resolved = ConvertFrom-JwtKey -Key $jwk
        $resolved | Should -BeOfType [byte]
        [System.Convert]::ToBase64String($resolved) | Should -Be ([System.Convert]::ToBase64String($secret))
    }

    It 'returns HMAC when -AsHmac is requested for oct keys' {
        $secret = [System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long')
        $jwk = ConvertTo-JwtKey -Key $secret
        $resolved = ConvertFrom-JwtKey -Key $jwk -AsHmac -Algorithm HS512
        try {
            $resolved | Should -BeOfType [System.Security.Cryptography.HMACSHA512]
        } finally {
            $resolved.Dispose()
        }
    }
}
