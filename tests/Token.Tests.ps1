#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Token segment' {
    Context 'ConvertFrom-Jwt' {
        It 'parses a compact JWT into a Jwt object' {
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
            (ConvertFrom-Jwt -Token $token.ToString()).GetType().Name | Should -Be 'Jwt'
        }
    }

    Context 'Get-JwtClaim' {
        It 'returns a single named claim' {
            $token = New-Jwt -Payload @{ sub = 'joe'; role = 'admin' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
            Get-JwtClaim -Token $token -Name 'role' | Should -Be 'admin'
        }
    }

    Context 'Get-JwtHeader' {
        It 'returns a header with alg set' {
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
            (Get-JwtHeader -Token $token).alg | Should -Be 'HS256'
        }
    }

    Context 'Get-JwtPayload' {
        It 'returns payload claims' {
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
            (Get-JwtPayload -Token $token).sub | Should -Be 'joe'
        }
    }

    Context 'New-Jwt' {
        It 'creates a compact token with 3 segments' {
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
            $token.ToString().Split('.').Count | Should -Be 3
        }

        It 'can generate a signing key internally and still produce a valid token' {
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm ES256 -GenerateKey
            $token | Should -BeOfType [Jwt]
            $token.ToString().Split('.').Count | Should -Be 3
            $token.Header.alg | Should -Be 'ES256'
        }

        It 'applies -GeneratedKeyId to header kid in generated-key mode' {
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm RS256 -GenerateKey -GeneratedKeyId 'rsa-1'
            $token.Header.kid | Should -Be 'rsa-1'
        }
    }

    Context 'Test-Jwt' {
        It 'returns true for a valid HS256 token' {
            $secret = 'a-string-secret-at-least-256-bits-long'
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret
            Test-Jwt -Token $token -Key $secret -RequireExpiration $false | Should -BeTrue
        }

        It 'requires -AllowUnsigned for alg=none tokens' {
            $h = ConvertTo-Base64UrlString '{"alg":"none","typ":"JWT"}'
            $p = ConvertTo-Base64UrlString '{"sub":"joe"}'
            { Test-Jwt -Token "$h.$p." -Key 'super-secret' } | Should -Throw
            Test-Jwt -Token "$h.$p." -AllowUnsigned -RequireExpiration $false | Should -BeTrue
        }

        It 'rejects crit headers unless explicitly allow-listed' {
            $secret = 'a-string-secret-at-least-256-bits-long'
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret -Header @{ kid = 'key-1'; crit = @('kid') }
            { Test-Jwt -Token $token -Key $secret -RequireExpiration $false } | Should -Throw '*Unsupported critical header parameters*'
            Test-Jwt -Token $token -Key $secret -RequireExpiration $false -AllowedCriticalHeader 'kid' | Should -BeTrue
        }

        It 'rejects crit entries that do not exist in the header' {
            $secret = 'a-string-secret-at-least-256-bits-long'
            $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret -Header @{ crit = @('kid') }
            { Test-Jwt -Token $token -Key $secret -RequireExpiration $false -AllowedCriticalHeader 'kid' } | Should -Throw '*not present in header*'
        }
    }
}

