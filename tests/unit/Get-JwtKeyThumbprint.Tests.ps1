#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'Get-JwtKeyThumbprint' {
    It 'returns a base64url thumbprint for a valid key' {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $jwk = ConvertTo-JwtKey -Key $rsa
            Get-JwtKeyThumbprint -Key $jwk | Should -Match '^[A-Za-z0-9_-]{43}$'
        } finally {
            $rsa.Dispose()
        }
    }
}

