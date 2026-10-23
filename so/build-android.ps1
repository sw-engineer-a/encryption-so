$ErrorActionPreference = "Stop"

$ndk = $env:ANDROID_NDK_HOME
if (-not $ndk) {
    $sdk = $env:ANDROID_SDK_ROOT
    if (-not $sdk) { $sdk = $env:ANDROID_HOME }
    if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk" }
    $ndkRoot = Join-Path $sdk "ndk"
    if (Test-Path $ndkRoot) {
        $ndk = Get-ChildItem $ndkRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
}

if (-not $ndk -or -not (Test-Path $ndk)) {
    Write-Error "Android NDK not found. Install it and set ANDROID_NDK_HOME."
}

$ndkBuild = Join-Path $ndk "ndk-build.cmd"
if (-not (Test-Path $ndkBuild)) {
    Write-Error "ndk-build.cmd was not found in $ndk"
}

& $ndkBuild NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk NDK_APPLICATION_MK=Application.mk -j 8
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (Test-Path "dist\jniLibs") { Remove-Item -Recurse -Force "dist\jniLibs" }
Copy-Item -Recurse "libs" "dist\jniLibs"
Write-Host "Built libraries:"
Get-ChildItem -Recurse "dist\jniLibs\*.so" | ForEach-Object { Write-Host $_.FullName }
