#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Keys segment' {
    Context 'ConvertFrom-JwtKey' {
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

    Context 'ConvertFrom-JwtKeySet' {
        It 'parses a valid JWKS JSON document' {
            $jwk = ConvertTo-JwtKey -Key ([System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long'))
            $set = $jwk | ConvertTo-JwtKeySet
            (ConvertFrom-JwtKeySet -Json $set.ToJson()).keys.Count | Should -Be 1
        }
    }

    Context 'ConvertTo-JwtKey' {
        It 'converts a byte array into an oct JWK' {
            $jwk = ConvertTo-JwtKey -Key ([System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long'))
            $jwk.kty | Should -Be 'oct'
            $jwk.k | Should -Not -BeNullOrEmpty
        }
    }

    Context 'ConvertTo-JwtKeySet' {
        It 'wraps one or more JwtKey objects in a JwtKeySet' {
            $jwk = ConvertTo-JwtKey -Key ([System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long'))
            ($jwk | ConvertTo-JwtKeySet).GetType().Name | Should -Be 'JwtKeySet'
        }
    }

    Context 'Get-JwtKeyFromSet' {
        It 'returns the key matching the requested kid' {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            try {
                $jwk = ConvertTo-JwtKey -Key $rsa -KeyId 'rsa-1' -Algorithm RS256
                $set = $jwk | ConvertTo-JwtKeySet
                (Get-JwtKeyFromSet -KeySet $set -KeyId 'rsa-1').kid | Should -Be 'rsa-1'
            } finally {
                $rsa.Dispose()
            }
        }
    }

    Context 'Get-JwtKeyThumbprint' {
        It 'returns a base64url thumbprint for a valid key' {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            try {
                $jwk = ConvertTo-JwtKey -Key $rsa
                Get-JwtKeyThumbprint -Key $jwk | Should -Match '^[A-Za-z0-9_-]{43}$'
            } finally {
                $rsa.Dispose()
            }
        }
    }

    Context 'New-JwtSigningKey' {
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
}

