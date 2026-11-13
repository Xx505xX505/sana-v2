$ErrorActionPreference = 'Stop'
$previousUri = $env:MONGODB_URI
$hadUri = -not [string]::IsNullOrWhiteSpace($previousUri)
$secureUri = $null
$uriPointer = [IntPtr]::Zero
$exitCode = 1

try {
  if (-not $hadUri) {
    $secureUri = Read-Host 'Atlas MONGODB_URI (hidden; entered only in this local terminal)' -AsSecureString
    if ($secureUri.Length -eq 0) { throw 'No URI was entered.' }
    $uriPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureUri)
    $env:MONGODB_URI = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($uriPointer)
  }

  Push-Location $PSScriptRoot\..
  try {
    npm.cmd run db:check
    $exitCode = $LASTEXITCODE
  } finally {
    Pop-Location
  }
} catch {
  Write-Error 'Atlas check could not run. The URI is never printed.'
  $exitCode = 1
} finally {
  if ($hadUri) { $env:MONGODB_URI = $previousUri }
  else { Remove-Item Env:\MONGODB_URI -ErrorAction SilentlyContinue }
  if ($uriPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($uriPointer) }
  if ($secureUri) { $secureUri.Dispose() }
}

exit $exitCode
