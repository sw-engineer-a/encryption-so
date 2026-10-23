package com.mh1721.cryptoapp;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;

/**
 * Bulk or interrupt USB link to the MH1721. The chip enumerates as a USB device,
 * so the phone needs a USB OTG adapter.
 */
public final class UsbChipLink implements Closeable {
    private static final int TIMEOUT_MS = 3000;
    private static final int MAX_PAYLOAD = 2048;

    private final UsbDeviceConnection connection;
    private final UsbInterface usbInterface;
    private final UsbEndpoint inEndpoint;
    private final UsbEndpoint outEndpoint;
    private byte[] stash = new byte[0];

    private UsbChipLink(UsbDeviceConnection connection, UsbInterface usbInterface,
                        UsbEndpoint inEndpoint, UsbEndpoint outEndpoint) {
        this.connection = connection;
        this.usbInterface = usbInterface;
        this.inEndpoint = inEndpoint;
        this.outEndpoint = outEndpoint;
    }

    public static UsbChipLink open(UsbManager manager, UsbDevice device) throws IOException {
        Ends ends = findEnds(device);
        UsbDeviceConnection connection = manager.openDevice(device);
        if (connection == null) {
            throw new IOException("USB open failed. Grant permission for the MH1721 and try again.");
        }
        if (!connection.claimInterface(ends.usbInterface, true)) {
            connection.close();
            throw new IOException("could not claim the USB interface");
        }
        return new UsbChipLink(connection, ends.usbInterface, ends.inEndpoint, ends.outEndpoint);
    }

    public byte[] transact(byte[] request) throws IOException {
        writeAll(request);
        byte[] header = readExact(3);
        int status = header[0] & 0xff;
        int length = ((header[1] & 0xff) << 8) | (header[2] & 0xff);
        if (length > MAX_PAYLOAD) {
            throw new IOException("chip response is " + length + " bytes");
        }
        byte[] payload = length == 0 ? new byte[0] : readExact(length);
        if (status != 0) {
            throw new IOException("chip status " + status);
        }
        return payload;
    }

    @Override
    public void close() {
        try {
            connection.releaseInterface(usbInterface);
        } finally {
            connection.close();
        }
    }

    private void writeAll(byte[] data) throws IOException {
        int sent = 0;
        while (sent < data.length) {
            int count = connection.bulkTransfer(outEndpoint, data, sent, data.length - sent, TIMEOUT_MS);
            if (count <= 0) {
                throw new IOException("USB write failed");
            }
            sent += count;
        }
    }

    private byte[] readExact(int length) throws IOException {
        byte[] out = new byte[length];
        int filled = 0;
        int emptyReads = 0;
        while (filled < length) {
            if (stash.length > 0) {
                int take = Math.min(stash.length, length - filled);
                System.arraycopy(stash, 0, out, filled, take);
                stash = Arrays.copyOfRange(stash, take, stash.length);
                filled += take;
                continue;
            }
            int packetSize = Math.max(inEndpoint.getMaxPacketSize(), 64);
            byte[] packet = new byte[packetSize];
            int count = connection.bulkTransfer(inEndpoint, packet, packet.length, TIMEOUT_MS);
            if (count < 0) {
                throw new IOException("USB read failed after " + filled + " of " + length + " bytes");
            }
            if (count == 0) {
                emptyReads++;
                if (emptyReads > 2) {
                    throw new IOException("USB read timed out");
                }
                continue;
            }
            emptyReads = 0;
            int take = Math.min(count, length - filled);
            System.arraycopy(packet, 0, out, filled, take);
            filled += take;
            if (count > take) {
                stash = Arrays.copyOfRange(packet, take, count);
            }
        }
        return out;
    }

    private static Ends findEnds(UsbDevice device) throws IOException {
        Ends bulk = findEnds(device, UsbConstants.USB_ENDPOINT_XFER_BULK);
        if (bulk != null) {
            return bulk;
        }
        Ends interrupt = findEnds(device, UsbConstants.USB_ENDPOINT_XFER_INT);
        if (interrupt != null) {
            return interrupt;
        }
        throw new IOException("the USB device has no bulk or interrupt in/out pair");
    }

    private static Ends findEnds(UsbDevice device, int transferType) {
        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface usbInterface = device.getInterface(i);
            UsbEndpoint inEndpoint = null;
            UsbEndpoint outEndpoint = null;
            for (int e = 0; e < usbInterface.getEndpointCount(); e++) {
                UsbEndpoint endpoint = usbInterface.getEndpoint(e);
                if (endpoint.getType() != transferType) {
                    continue;
                }
                if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                    inEndpoint = endpoint;
                } else if (endpoint.getDirection() == UsbConstants.USB_DIR_OUT) {
                    outEndpoint = endpoint;
                }
            }
            if (inEndpoint != null && outEndpoint != null) {
                return new Ends(usbInterface, inEndpoint, outEndpoint);
            }
        }
        return null;
    }

    private static final class Ends {
        final UsbInterface usbInterface;
        final UsbEndpoint inEndpoint;
        final UsbEndpoint outEndpoint;

        Ends(UsbInterface usbInterface, UsbEndpoint inEndpoint, UsbEndpoint outEndpoint) {
            this.usbInterface = usbInterface;
            this.inEndpoint = inEndpoint;
            this.outEndpoint = outEndpoint;
        }
    }
}
