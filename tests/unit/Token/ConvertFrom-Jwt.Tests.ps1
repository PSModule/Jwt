#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'ConvertFrom-Jwt' {
    It 'parses a compact JWT into a Jwt object' {
        $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
        (ConvertFrom-Jwt -Token $token.ToString()).GetType().Name | Should -Be 'Jwt'
    }
}

