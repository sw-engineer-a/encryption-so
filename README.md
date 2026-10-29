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

## Talk to the chip

Type the modulus, public exponent, and private exponent as hex. **Run software RSA** uses that key in `libmh1721crypto.so` and does not open USB.

**Compare with MH1721** uses the same typed key in the library, then opens the chip over USB. Plug it in with a USB OTG adapter. The library and the chip both sign the message, and both decrypt the ciphertext the library produced. The screen reports whether those results match. They match when the typed private exponent is the key stored on the chip. PKCS#1 encryption padding is random, so the ciphertexts themselves are not compared.

Megahunt does not publish a host command set. The firmware on the chip has to answer these frames. Each frame is one command or status byte, a 16-bit big-endian length, then that many payload bytes. Status `0` means success.

| Command | Value | Phone sends | Chip returns |
|---|---|---|---|
| `GET_PUBLIC_KEY` | `0x01` | empty | modulus length, modulus, exponent length, public exponent |
| `DECRYPT` | `0x02` | ciphertext | plaintext |
| `SIGN` | `0x03` | message bytes | signature |

Lengths inside the public-key payload are also 16-bit big-endian. The modulus is unsigned big-endian, 64 to 512 bytes.
