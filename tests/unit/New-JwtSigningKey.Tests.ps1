#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'New-JwtSigningKey' {
    It 'generates RSA key material for RS256' {
        $key = New-JwtSigningKey -Algorithm RS256 -RsaKeySize 2048
        try {
            $key | Should -BeOfType [System.Security.Cryptography.RSA]
            $key.KeySize | Should -Be 2048
        } finally {
            $key.Dispose()
        }
    }

    It 'generates ECDsa key material for ES256' {
        $key = New-JwtSigningKey -Algorithm ES256
        try {
            $key | Should -BeOfType [System.Security.Cryptography.ECDsa]
            $params = $key.ExportParameters($false)
            $params.Curve.Oid.Value | Should -Be '1.2.840.10045.3.1.7'
        } finally {
            $key.Dispose()
        }
    }

    It 'generates an HMAC secret for HS512 with expected length' {
        $key = New-JwtSigningKey -Algorithm HS512
        $key | Should -BeOfType [byte]
        $key.Length | Should -Be 64
    }

    It 'can return a JWK with private material' {
        $jwk = New-JwtSigningKey -Algorithm RS256 -AsJwk -KeyId 'rsa-1'
        $jwk | Should -BeOfType [JwtKey]
        $jwk.kty | Should -Be 'RSA'
        $jwk.kid | Should -Be 'rsa-1'
        $jwk.d | Should -Not -BeNullOrEmpty
    }
}

