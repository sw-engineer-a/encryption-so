package com.mh1721.cryptoapp;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.mh1721.crypto.Mh1721Crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {
    private static final String ACTION_USB_PERMISSION = "com.mh1721.cryptoapp.USB_PERMISSION";

    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private UsbManager usbManager;
    private TextView output;
    private BroadcastReceiver usbPermissionReceiver;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        usbManager = (UsbManager) getSystemService(USB_SERVICE);
        output = findViewById(R.id.output);
        findViewById(R.id.run).setOnClickListener(v -> output.setText(runSoftwareDemo()));
        findViewById(R.id.chip).setOnClickListener(v -> chooseChip());
    }

    @Override
    protected void onStart() {
        super.onStart();
        usbPermissionReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!ACTION_USB_PERMISSION.equals(intent.getAction())) {
                    return;
                }
                UsbDevice device = readDevice(intent);
                boolean granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false);
                if (device != null && granted) {
                    talk(device);
                } else {
                    output.setText("USB permission was denied.");
                }
            }
        };
        IntentFilter filter = new IntentFilter(ACTION_USB_PERMISSION);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(usbPermissionReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(usbPermissionReceiver, filter);
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (usbPermissionReceiver != null) {
            unregisterReceiver(usbPermissionReceiver);
            usbPermissionReceiver = null;
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        io.shutdownNow();
    }

    private void chooseChip() {
        ArrayList<UsbDevice> devices = new ArrayList<>(usbManager.getDeviceList().values());
        if (devices.isEmpty()) {
            output.setText("No USB device. Connect the MH1721 with a USB OTG adapter.");
            return;
        }
        if (devices.size() == 1) {
            useDevice(devices.get(0));
            return;
        }
        String[] labels = new String[devices.size()];
        for (int i = 0; i < devices.size(); i++) {
            labels[i] = deviceLabel(devices.get(i));
        }
        new AlertDialog.Builder(this)
                .setTitle(R.string.pick_chip)
                .setItems(labels, (dialog, which) -> useDevice(devices.get(which)))
                .show();
    }

    private void useDevice(UsbDevice device) {
        if (usbManager.hasPermission(device)) {
            talk(device);
            return;
        }
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 31) {
            flags |= PendingIntent.FLAG_MUTABLE;
        }
        Intent permissionIntent = new Intent(ACTION_USB_PERMISSION);
        permissionIntent.setPackage(getPackageName());
        PendingIntent permission = PendingIntent.getBroadcast(this, 0, permissionIntent, flags);
        output.setText("Asking for USB permission to " + deviceLabel(device));
        usbManager.requestPermission(device, permission);
    }

    private void talk(UsbDevice device) {
        output.setText("Opening " + deviceLabel(device));
        io.execute(() -> {
            String text;
            try (UsbChipLink link = UsbChipLink.open(usbManager, device)) {
                text = deviceLabel(device) + "\n" + ChipSession.exchange(link);
            } catch (Exception error) {
                text = error.getClass().getSimpleName() + ": " + error.getMessage();
            }
            String show = text;
            runOnUiThread(() -> output.setText(show));
        });
    }

    private static UsbDevice readDevice(Intent intent) {
        if (Build.VERSION.SDK_INT >= 33) {
            return intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice.class);
        }
        return intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
    }

    private static String deviceLabel(UsbDevice device) {
        String name = device.getProductName();
        if (name == null || name.isEmpty()) {
            name = "USB device";
        }
        return name + String.format(" vid=%04x pid=%04x", device.getVendorId(), device.getProductId());
    }

    private String runSoftwareDemo() {
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

            return "software key, no chip"
                    + "\nversion: " + Mh1721Crypto.version()
                    + "\nmessage: " + message
                    + "\nopened: " + opened
                    + "\nverify: " + verified
                    + "\ncipher bytes: " + (cipher == null ? 0 : cipher.length);
        } catch (Throwable error) {
            return error.toString();
        }
    }
}
