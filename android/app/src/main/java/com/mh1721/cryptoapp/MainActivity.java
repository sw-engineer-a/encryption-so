package com.mh1721.cryptoapp;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.mh1721.crypto.Mh1721Crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView output = findViewById(R.id.output);
        findViewById(R.id.run).setOnClickListener(v -> output.setText(runDemo()));
    }

    private String runDemo() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            CryptoClient crypto = new CryptoClient(
                    pair.getPublic().getEncoded(),
                    pair.getPrivate().getEncoded());

            String message = "hello from the android app";
            byte[] cipher = crypto.seal(message);
            String opened = crypto.open(cipher);
            byte[] signature = crypto.sign(message);
            boolean verified = crypto.verify(message, signature);

            return "version: " + Mh1721Crypto.version()
                    + "\nmessage: " + message
                    + "\nopened: " + opened
                    + "\nverify: " + verified
                    + "\ncipher bytes: " + (cipher == null ? 0 : cipher.length);
        } catch (Throwable error) {
            return error.toString();
        }
    }
}
