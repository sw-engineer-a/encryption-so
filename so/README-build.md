# Build libmh1721crypto.so offline

This builds the Android shared library from the `so` folder. After `android-ndk-r30-windows.zip` is already on the PC, every step below works with no internet. Do not use `sdkmanager` for this install. That tool downloads the NDK and will fail offline.

The RSA calls are described in `README-api.md`.

The zip is Android NDK r30. The build uses `ndk-build` from that zip. It produces three copies of the same library:

```text
dist/jniLibs/armeabi-v7a/libmh1721crypto.so
dist/jniLibs/arm64-v8a/libmh1721crypto.so
dist/jniLibs/x86_64/libmh1721crypto.so
```

| File | Use it on |
|---|---|
| `arm64-v8a` | Current phones |
| `armeabi-v7a` | Older 32-bit phones |
| `x86_64` | The Android emulator on a PC |

The library runs on Android 5.0 and newer (API 21).

## What must already be on the PC

| Item | Where it is |
|---|---|
| NDK zip, about 711 MB (727,980,788 bytes) | `C:\Users\ASUS\Downloads\android-ndk-r30-windows.zip` |
| This project | `C:\Users\ASUS\Documents\company\encryption-so\so` |
| PowerShell | Already installed with Windows |
| `tar` | Already installed with Windows. It is used only to unzip. It does not download anything. |

## 1. Extract the zip

Open PowerShell. The prompt looks like `PS C:\...>`. These commands are PowerShell. They will not work if they are pasted into `cmd`, and `cmd` lines such as `set SDK=%LOCALAPPDATA%\...` will not work in PowerShell.

```powershell
$zip = "$env:USERPROFILE\Downloads\android-ndk-r30-windows.zip"
$dest = "$env:LOCALAPPDATA\Android\Sdk\ndk"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
tar -xf $zip -C $dest
```

Extraction reads only the local zip. It takes a few minutes and needs about 3 GB of free disk space. When it finishes, this folder exists:

```text
C:\Users\ASUS\AppData\Local\Android\Sdk\ndk\android-ndk-r30
```

`%LOCALAPPDATA%` on this PC is `C:\Users\ASUS\AppData\Local`. The zip's top folder is named `android-ndk-r30`. Inside it, the file that matters is `ndk-build.cmd`.

If that folder is already there from an earlier extract, skip `tar`. Run this instead and continue at step 2 when it prints `True`:

```powershell
Test-Path "$env:LOCALAPPDATA\Android\Sdk\ndk\android-ndk-r30\ndk-build.cmd"
```

## 2. Tell Windows where the NDK is

`ANDROID_NDK_HOME` must be the folder that contains `ndk-build.cmd`, not the zip and not the `ndk` parent folder.

Set it for the current PowerShell window and save it for later windows:

```powershell
$ndk = "$env:LOCALAPPDATA\Android\Sdk\ndk\android-ndk-r30"
$env:ANDROID_NDK_HOME = $ndk
setx ANDROID_NDK_HOME $ndk
```

`setx` writes the user environment variable. It does not change the window you are typing in. The line `$env:ANDROID_NDK_HOME = $ndk` does. A new PowerShell window sees only the `setx` value.

Check this window:

```powershell
Test-Path "$env:ANDROID_NDK_HOME\ndk-build.cmd"
```

`True` means this window can build. `False` means `ANDROID_NDK_HOME` is empty or points at the wrong folder. Set `$env:ANDROID_NDK_HOME` again with the two lines above. Do not point it at `C:\Users\ASUS\Downloads`.

## 3. Build

Stay in the same PowerShell window so `ANDROID_NDK_HOME` is still set.

```powershell
cd C:\Users\ASUS\Documents\company\encryption-so\so
.\build-android.ps1
```

If Windows blocks the script, run it once this way. This does not change the system policy:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-android.ps1
```

The script does four things, all local:

1. It reads `ANDROID_NDK_HOME`. If that variable is empty, it picks the only directory under `%LOCALAPPDATA%\Android\Sdk\ndk`, which is `android-ndk-r30`.
2. It runs `ndk-build.cmd` from that folder. No files are downloaded.
3. `Android.mk` compiles `src/bn.c`, `src/rsa.c`, `src/sha256.c`, `src/random.c`, and `src/mh1721_jni.c`.
4. `Application.mk` selects `armeabi-v7a`, `arm64-v8a`, and `x86_64`. The script copies `libs` to `dist\jniLibs`.

A successful build prints `Compile` lines, then lines like:

```text
[arm64-v8a] SharedLibrary  : libmh1721crypto.so
[armeabi-v7a] SharedLibrary  : libmh1721crypto.so
[x86_64] SharedLibrary  : libmh1721crypto.so
Built libraries:
C:\Users\ASUS\Documents\company\encryption-so\so\dist\jniLibs\arm64-v8a\libmh1721crypto.so
C:\Users\ASUS\Documents\company\encryption-so\so\dist\jniLibs\armeabi-v7a\libmh1721crypto.so
C:\Users\ASUS\Documents\company\encryption-so\so\dist\jniLibs\x86_64\libmh1721crypto.so
```

The first build can take about a minute. Later builds are faster. `libs` and `obj` are intermediate output. The files to keep are under `dist\jniLibs`.

To build only the 64-bit phone library:

```powershell
cd C:\Users\ASUS\Documents\company\encryption-so\so
& "$env:ANDROID_NDK_HOME\ndk-build.cmd" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk NDK_APPLICATION_MK=Application.mk APP_ABI=arm64-v8a
```

That writes `libs\arm64-v8a\libmh1721crypto.so` and does not refresh `dist\jniLibs`. Use `.\build-android.ps1` when you want all three ABIs copied into `dist`.

## 4. Use the result in the Android app

The project in `..\android` already compiles `java\com\mh1721\crypto\Mh1721Crypto.java` and packs `dist\jniLibs`. Rebuild with `.\build-android.ps1`, then run that app from Android Studio. The package folder must stay `com\mh1721\crypto`.

To drop the same files into a different app, copy them like this:

| Built file | Place in the other app |
|---|---|
| `dist\jniLibs\arm64-v8a\libmh1721crypto.so` | `app\src\main\jniLibs\arm64-v8a\` |
| `dist\jniLibs\armeabi-v7a\libmh1721crypto.so` | `app\src\main\jniLibs\armeabi-v7a\` |
| `dist\jniLibs\x86_64\libmh1721crypto.so` | `app\src\main\jniLibs\x86_64\` |
| `java\com\mh1721\crypto\Mh1721Crypto.java` | `app\src\main\java\com\mh1721\crypto\` |

Create the `jniLibs\<abi>` folders in the other app if they are not there. The file name must stay `libmh1721crypto.so`. How to call encrypt, decrypt, sign, and verify is in `README-api.md`.

## Build again later, still offline

The zip does not need to be extracted again. Open a new PowerShell window and run:

```powershell
cd C:\Users\ASUS\Documents\company\encryption-so\so
.\build-android.ps1
```

A new window already has `ANDROID_NDK_HOME` from `setx`. If `Test-Path "$env:ANDROID_NDK_HOME\ndk-build.cmd"` prints `False`, set the variable again with the commands in step 2.

## If the build stops

| What you see | What to do |
|---|---|
| `Android NDK not found` | This window does not have `ANDROID_NDK_HOME`. Repeat step 2, including `$env:ANDROID_NDK_HOME = $ndk`, then run the script again in that same window. |
| `ndk-build.cmd was not found` | `ANDROID_NDK_HOME` is not `...\ndk\android-ndk-r30`. Point it at the folder that contains `ndk-build.cmd`. |
| `tar` says the zip cannot be opened | Check the path `C:\Users\ASUS\Downloads\android-ndk-r30-windows.zip`. The file must be the full 727,980,788-byte zip. |
| PowerShell error on `--sdk_root` or `%SDK%` | Those belong to an online `sdkmanager` install. This offline install does not use them. |
| `Test-Path` is `False` in a new window | Open the window after `setx`, or set `$env:ANDROID_NDK_HOME` in the current window. |
