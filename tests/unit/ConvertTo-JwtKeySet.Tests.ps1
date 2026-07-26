#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'ConvertTo-JwtKeySet' {
    It 'wraps one or more JwtKey objects in a JwtKeySet' {
        $jwk = ConvertTo-JwtKey -Key ([System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long'))
        ($jwk | ConvertTo-JwtKeySet).GetType().Name | Should -Be 'JwtKeySet'
    }
}

