# encryption-so

Two projects:

| Folder | What it is |
|---|---|
| `so` | NDK project that builds `libmh1721crypto.so` |
| `android` | Android app that loads that library and calls encrypt, decrypt, sign, and verify |

Build the library first, from `so`:

```powershell
cd C:\Users\ASUS\Documents\company\encryption-so\so
.\build-android.ps1
```

That writes `so\dist\jniLibs\<abi>\libmh1721crypto.so`. The Android app compiles `so\java` and packs those `.so` files. It does not keep a second copy. Open the `android` folder in Android Studio and run the app.

NDK steps are in `so\README-build.md`. The RSA calls are in `so\README-api.md`.
