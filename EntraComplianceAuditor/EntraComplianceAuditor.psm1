#Requires -Version 5.1
Set-StrictMode -Version Latest

# Dot-source private helper functions first
$Private = @(Get-ChildItem -Path "$PSScriptRoot/Private/*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $Private) {
    try {
        . $file.FullName
    } catch {
        Write-Error "Failed to import private function '$($file.FullName)': $_"
    }
}

# Dot-source public functions
$Public = @(Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $Public) {
    try {
        . $file.FullName
    } catch {
        Write-Error "Failed to import public function '$($file.FullName)': $_"
    }
}

Export-ModuleMember -Function $Public.BaseName
