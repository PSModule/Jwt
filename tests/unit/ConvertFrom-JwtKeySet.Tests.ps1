#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'ConvertFrom-JwtKeySet' {
    It 'parses a valid JWKS JSON document' {
        $jwk = ConvertTo-JwtKey -Key ([System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long'))
        $set = $jwk | ConvertTo-JwtKeySet
        (ConvertFrom-JwtKeySet -Json $set.ToJson()).keys.Count | Should -Be 1
    }
}

