#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Get-JwtClaim' {
    It 'returns a single named claim' {
        $token = New-Jwt -Payload @{ sub = 'joe'; role = 'admin' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
        Get-JwtClaim -Token $token -Name 'role' | Should -Be 'admin'
    }
}

