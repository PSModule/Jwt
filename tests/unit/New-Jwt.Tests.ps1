#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0'; MaximumVersion = '6.*' }
[CmdletBinding()]
param()

Describe 'New-Jwt' {
    It 'creates a compact token with 3 segments' {
        $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm HS256 -Key 'a-string-secret-at-least-256-bits-long'
        $token.ToString().Split('.').Count | Should -Be 3
    }

    It 'can generate a signing key internally and still produce a valid token' {
        $token = New-Jwt -Payload @{ sub = 'joe' } -Algorithm ES256 -GenerateKey
        $token.ToString().Split('.').Count | Should -Be 3
        $token.Header.alg | Should -Be 'ES256'
    }

    It 'returns token+key+jwk bundle when include switches are used' {
        $bundle = New-Jwt -Payload @{ sub = 'joe' } -Algorithm RS256 `
            -GenerateKey -GeneratedKeyId 'rsa-1' -IncludeGeneratedKey -IncludeGeneratedJwk
        $bundle.Token | Should -BeOfType [Jwt]
        $bundle.Key | Should -BeOfType [System.Security.Cryptography.RSA]
        $bundle.Jwk | Should -BeOfType [JwtKey]
        $bundle.Jwk.kid | Should -Be 'rsa-1'
        $bundle.Token.Header.kid | Should -Be 'rsa-1'
    }
}
