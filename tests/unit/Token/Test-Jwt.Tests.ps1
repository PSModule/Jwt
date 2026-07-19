#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Test-Jwt' {
    It 'returns true for a valid HS256 token' {
        $secret = 'a-string-secret-at-least-256-bits-long'
        $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret
        Test-Jwt -Token $token -Key $secret -RequireExpiration $false | Should -BeTrue
    }

    It "requires -AllowUnsigned for alg=none tokens" {
        $h = ConvertTo-Base64UrlString '{"alg":"none","typ":"JWT"}'
        $p = ConvertTo-Base64UrlString '{"sub":"joe"}'
        { Test-Jwt -Token "$h.$p." -Key 'super-secret' } | Should -Throw
        Test-Jwt -Token "$h.$p." -AllowUnsigned -RequireExpiration $false | Should -BeTrue
    }

    It "rejects crit headers unless explicitly allow-listed" {
        $secret = 'a-string-secret-at-least-256-bits-long'
        $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret -Header @{ kid = 'key-1'; crit = @('kid') }
        { Test-Jwt -Token $token -Key $secret -RequireExpiration $false } | Should -Throw '*Unsupported critical header parameters*'
        Test-Jwt -Token $token -Key $secret -RequireExpiration $false -AllowedCriticalHeader 'kid' | Should -BeTrue
    }

    It "rejects crit entries that do not exist in the header" {
        $secret = 'a-string-secret-at-least-256-bits-long'
        $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key $secret -Header @{ crit = @('kid') }
        { Test-Jwt -Token $token -Key $secret -RequireExpiration $false -AllowedCriticalHeader 'kid' } | Should -Throw '*not present in header*'
    }
}
