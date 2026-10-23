# Use the RSA API in libmh1721crypto.so

Build the library first. The NDK steps are in `README-build.md`. This file is how another Android app calls the finished `.so`.

`Mh1721Crypto` loads `libmh1721crypto.so` and exposes PKCS#1 v1.5 RSA. Encryption matches Android `Cipher` `"RSA/ECB/PKCS1Padding"`. Signatures match `"SHA256withRSA"`.

The modulus must be 64 to 512 bytes (512 to 4096 bits). Use 2048 bits or larger for a new key. The library does not read keys out of the MH1721 chip. You pass the modulus and the exponent yourself.

## Add the files

The Android app in `android/` already compiles this class and packs the libraries. For a different app, copy the ABI that device needs, and copy the Java class without changing its package:

```text
app/src/main/jniLibs/arm64-v8a/libmh1721crypto.so
app/src/main/java/com/mh1721/crypto/Mh1721Crypto.java
```

Also copy `armeabi-v7a` for older phones and `x86_64` for the emulator. The class calls `System.loadLibrary("mh1721crypto")` the first time you use it. The package must stay `com.mh1721.crypto`, because the native method names are bound to that class.

## Methods

| Method | Key | What it does | Returns |
|---|---|---|---|
| `encrypt(modulus, publicExponent, data)` | public | PKCS#1 v1.5 type 2 | ciphertext, or `null` |
| `decrypt(modulus, privateExponent, data)` | private | PKCS#1 v1.5 type 2 | message, or `null` |
| `sign(modulus, privateExponent, data)` | private | SHA-256, then PKCS#1 v1.5 type 1 | signature, or `null` |
| `verify(modulus, publicExponent, data, signature)` | public | checks a SHA-256 signature | `true` or `false` |
| `version()` | | library version | `"2.0.0"` |

`encrypt` accepts at most `modulusBytes - 11` bytes of data. The ciphertext and the signature are the same length as the modulus.

Modulus and exponents are unsigned big-endian. A leading `0x00` byte, which `BigInteger.toByteArray()` adds, is accepted.

A wrong key size, a message that is too long, or padding that does not check causes `encrypt`, `decrypt`, and `sign` to return `null`. `verify` returns `false`.

## Call the API

```java
import com.mh1721.crypto.Mh1721Crypto;

import java.nio.charset.StandardCharsets;

byte[] message = "hello".getBytes(StandardCharsets.UTF_8);

byte[] cipher = Mh1721Crypto.encrypt(modulus, publicExponent, message);
byte[] plain = Mh1721Crypto.decrypt(modulus, privateExponent, cipher);

byte[] signature = Mh1721Crypto.sign(modulus, privateExponent, message);
boolean ok = Mh1721Crypto.verify(modulus, publicExponent, message, signature);
```

Encrypt and decrypt must use the same modulus. Sign and verify must use the same message bytes, including the same charset.

## Take the numbers from an Android key

`android/app/src/main/java/com/mh1721/cryptoapp/CryptoClient.java` does this. From an X.509 public key and a PKCS#8 private key:

```java
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
        .generatePublic(new X509EncodedKeySpec(x509PublicBytes));
RSAPrivateKey priv = (RSAPrivateKey) KeyFactory.getInstance("RSA")
        .generatePrivate(new PKCS8EncodedKeySpec(pkcs8PrivateBytes));

byte[] modulus = unsigned(pub.getModulus());
byte[] publicExponent = unsigned(pub.getPublicExponent());
byte[] privateExponent = unsigned(priv.getPrivateExponent());

private static byte[] unsigned(BigInteger value) {
    byte[] raw = value.toByteArray();
    if (raw.length > 1 && raw[0] == 0) {
        byte[] trimmed = new byte[raw.length - 1];
        System.arraycopy(raw, 1, trimmed, 0, trimmed.length);
        return trimmed;
    }
    return raw;
}
```

Public encryption uses `modulus` and `publicExponent`. Private decryption and signing use `modulus` and `privateExponent`.
