#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Get-JwtPayload' {
    It 'returns payload claims' {
        $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
        (Get-JwtPayload -Token $token).sub | Should -Be 'joe'
    }
}

