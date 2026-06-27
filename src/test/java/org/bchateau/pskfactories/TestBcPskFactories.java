package org.bchateau.pskfactories;

import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

// Test the factories without third-party client/server libraries
public class TestBcPskFactories {

    private static final byte[] KEY_1 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    private static final byte[] KEY_2 = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1 };
    private static final String ID_1 = "identity1";
    private static final String ID_2 = "identity2";

    @Test
    public void testInvalidPskFails() throws Exception {
        final int port = 4435;
        BcPskTlsParams params = new BcPskTlsParams();

        TlsPSKIdentityManager serverMgr = new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() { return new byte[0]; }
            @Override
            public byte[] getPSK(byte[] identity) {
                if (Arrays.equals(ID_1.getBytes(), identity)) return KEY_1;
                throw new IllegalArgumentException("Unknown identity");
            }
        };

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, serverMgr);

        Thread serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = serverFactory.createServerSocket(port)) {
                try (Socket socket = serverSocket.accept()) {
                    // Trigger handshake
                    socket.getInputStream();
                } catch (IOException e) {
                    // Expected failure on server side
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.start();

        // Give server a moment to start
        Thread.sleep(200);

        BasicTlsPSKIdentity clientIdentity = new BasicTlsPSKIdentity(ID_2, KEY_2);
        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, clientIdentity);

        try {
            Socket rawSocket = clientFactory.createSocket("localhost", port);
            javax.net.ssl.SSLSocket sslSocket = (javax.net.ssl.SSLSocket) rawSocket;
            Assertions.assertThrows(IOException.class, () -> {
                sslSocket.startHandshake();
            });
        } catch (IOException e) {
            // If createSocket fails due to server closing connection immediately, this is also a success
        } finally {
            serverThread.interrupt();
        }
    }
}
