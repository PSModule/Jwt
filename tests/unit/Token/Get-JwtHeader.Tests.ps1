#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Get-JwtHeader' {
    It 'returns a header with alg set' {
        $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
        (Get-JwtHeader -Token $token).alg | Should -Be 'HS256'
    }
}

