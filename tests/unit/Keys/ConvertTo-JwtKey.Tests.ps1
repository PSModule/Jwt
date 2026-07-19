#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'ConvertTo-JwtKey' {
    It 'converts a byte array into an oct JWK' {
        $jwk = ConvertTo-JwtKey -Key ([System.Text.Encoding]::UTF8.GetBytes('a-string-secret-at-least-256-bits-long'))
        $jwk.kty | Should -Be 'oct'
        $jwk.k | Should -Not -BeNullOrEmpty
    }
}

