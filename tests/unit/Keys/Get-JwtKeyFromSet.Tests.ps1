#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Get-JwtKeyFromSet' {
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

