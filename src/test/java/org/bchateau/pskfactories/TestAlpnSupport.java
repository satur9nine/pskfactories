package org.bchateau.pskfactories;

import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.condition.JRE.JAVA_9;

public class TestAlpnSupport {

    private static final byte[] PSK_KEY = new byte[] { 1, 2, 3, 4, 1, 2, 3, 4 };
    private static final String PSK_ID = "alpn-test";

    @Test
    @EnabledForJreRange(min = JAVA_9)
    public void testAlpnNegotiation() throws Exception {
        String alpnProtocol = "h2";
        int port = 4437;
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] {
                    org.bouncycastle.tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
                },
                0,
                new String[] { alpnProtocol }
        );

        TlsPSKIdentityManager serverMgr = new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() { return new byte[0]; }
            @Override
            public byte[] getPSK(byte[] identity) { return PSK_KEY; }
        };

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, serverMgr);

        AtomicReference<String> negotiatedProtocol = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = serverFactory.createServerSocket(port)) {
                try (Socket socket = serverSocket.accept()) {
                    // Trigger handshake to negotiate ALPN
                    socket.getInputStream();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.start();

        // Give server a moment to start
        Thread.sleep(200);

        BasicTlsPSKIdentity clientIdentity = new BasicTlsPSKIdentity(PSK_ID, PSK_KEY);
        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, clientIdentity);

        try {
            Socket socket = clientFactory.createSocket("localhost", port);
            javax.net.ssl.SSLSocket sslSocket = (javax.net.ssl.SSLSocket) socket;
            sslSocket.startHandshake();

            String result = sslSocket.getApplicationProtocol();
            System.out.println("Negotiated Protocol: " + result);
            negotiatedProtocol.set(result);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            serverThread.interrupt();
        }

        Assertions.assertEquals(alpnProtocol, negotiatedProtocol.get());
    }
}
