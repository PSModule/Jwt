[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Required for Pester tests'
)]
[CmdletBinding()]
param()

Describe 'Jwt' {
    It 'New-Jwt should emit a warning that it is not yet implemented' {
        New-Jwt 3>&1 | Should -BeLike '*not yet implemented*'
    }
}
