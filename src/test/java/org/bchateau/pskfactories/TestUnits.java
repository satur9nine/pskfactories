package org.bchateau.pskfactories;

import org.bouncycastle.tls.TlsPSKIdentity;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class TestUnits {

    final byte[] testPskKey = new byte[] {
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
    };

    final TlsPSKIdentityManager testIdentityMgr = new TlsPSKIdentityManager() {
        @Override
        public byte[] getHint() {
            return new byte[0];
        }

        @Override
        public byte[] getPSK(byte[] identity) {
            if (Arrays.equals("test".getBytes(), identity)) {
                return testPskKey;
            } else {
                return null;
            }
        }
    };

    @Test
    public void testRaiseAlertFatalSignalsFailure() throws Exception {
        BcPskSSLServerSocketFactory.BcPskTlsServerProtocol protocol =
            new BcPskSSLServerSocketFactory.BcPskTlsServerProtocol(
                new ByteArrayInputStream(new byte[0]),
                new ByteArrayOutputStream()
            );

        try {
            protocol.raiseAlertFatal((short) 0, "test", new RuntimeException("fatal"));
            Assertions.fail("raiseAlertFatal should have thrown an exception");
        } catch (IOException e) {
            // Success
        }
    }

    @Test
    public void testHandshakeCompletedListenerIsNotified() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            CountDownLatch latch = new CountDownLatch(1);
            AtomicBoolean notified = new AtomicBoolean(false);

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    // Trigger handshake
                    socket.getInputStream();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, new TlsPSKIdentity() {
                @Override
                public void skipIdentityHint() {}

                @Override
                public void notifyIdentityHint(byte[] psk_identity_hint) {}

                @Override
                public byte[] getPSKIdentity() {
                    return "test".getBytes();
                }

                @Override
                public byte[] getPSK() {
                    return testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);

                sslSocket.addHandshakeCompletedListener(event -> {
                    notified.set(true);
                    latch.countDown();
                });

                sslSocket.startHandshake();
            }

            Assertions.assertTrue(latch.await(5, TimeUnit.SECONDS), "Handshake completed listener was not notified");
            Assertions.assertTrue(notified.get(), "Handshake completed listener should have been notified");
        }
    }
}
