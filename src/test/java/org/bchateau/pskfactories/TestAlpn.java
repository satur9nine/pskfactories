/*
 * Copyright (C) 2026 Jacob Whitaker Abrams
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bchateau.pskfactories;

import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.TlsPSKIdentity;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicReference;


// Test ALPN
public class TestAlpn {

    @Test
    public void testNamedBuildersMatchPositionalForm() throws Exception {
        BcPskTlsParams positional = new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 }, 1500,
                new String[] { "h2" });
        BcPskTlsParams named = new BcPskTlsParams()
                .withSupportedProtocolVersions(new ProtocolVersion[] { ProtocolVersion.TLSv12 })
                .withSupportedCipherSuites(new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 })
                .withSessionTimeout(1500)
                .withApplicationProtocols(new String[] { "h2" });

        Assertions.assertEquals(positional.getSupportedProtocols().length, named.getSupportedProtocols().length,
                "protocol set must match the positional form");
        Assertions.assertEquals(positional.getSupportedCipherSuites().length, named.getSupportedCipherSuites().length,
                "cipher suite set must match the positional form");
        Assertions.assertEquals(positional.getSessionTimeout(), named.getSessionTimeout(),
                "timeout must match the positional form");
        Assertions.assertEquals(positional.getApplicationProtocols().length, named.getApplicationProtocols().length,
                "application protocol set must match the positional form");
        Assertions.assertEquals("h2", named.getApplicationProtocols()[0], "the named ALPN name must be kept");
    }


    /**
     * getApplicationProtocol() keeps the JDK's three states: null while it is still unknown whether
     * application protocols apply, "" once the connection decided they do not, and the negotiated
     * name (pinned by testAlpnNegotiation()) when the server answered the client's offer.
     */
    @Test
    public void testApplicationProtocolIsUndeterminedUntilNegotiated() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                300000,
                new String[0]);

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);
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
                return TesterSupport.testPskKey;
            }
        });

        AtomicReference<SSLSocket> acceptedRef = new AtomicReference<SSLSocket>();
        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            // Holds the accepted socket open while the main thread drives its handshake.
            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    acceptedRef.compareAndSet(null, (SSLSocket) socket);
                    socket.getInputStream();
                    Thread.sleep(2000);
                } catch (IOException | InterruptedException e) {
                }
            }).start();

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                Assertions.assertNull(clientSide.getApplicationProtocol(),
                        "no handshake has run, so whether application protocols will be used is still"
                                + " undetermined and the accessor reports null");
                clientSide.startHandshake();

                for (int attempt = 0; attempt < 100 && acceptedRef.get() == null; attempt++) {
                    Thread.sleep(20);
                }
                SSLSocket accepted = acceptedRef.get();
                Assertions.assertNotNull(accepted, "the server must have accepted the connection");

                Assertions.assertEquals("", clientSide.getApplicationProtocol(),
                        "no ALPN names were offered, so the accessor reports the empty string");
            }
        }
    }

    /**
     * The handshake application-protocol selector a server-end socket carries is consulted when the
     * handshake builds its ALPN offer: the name it picks from the socket's names is the name the
     * handshake negotiates, and both ends report it.
     */
    @Test
    public void testAlpnSelectorChoosesTheOfferedName() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[] { "h2", "h3" });
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<String> acceptedProtocol = new AtomicReference<>();
            AtomicReference<String> acceptedSelector = new AtomicReference<>();

            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.setHandshakeApplicationProtocolSelector((sock, names) -> "h3");
                    acceptedSelector.compareAndSet(null, serverSide.getHandshakeApplicationProtocolSelector() == null
                            ? "absent" : "installed");
                    serverSide.getInputStream();
                    acceptedProtocol.compareAndSet(null, serverSide.getHandshakeApplicationProtocol());
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, new TlsPSKIdentity() {
                @Override
                public void skipIdentityHint() {}

                @Override
                public void notifyIdentityHint(byte[] psk_identity_hint) {}

                @Override
                public byte[] getPSKIdentity() { return "test".getBytes(); }

                @Override
                public byte[] getPSK() { return TesterSupport.testPskKey; }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                clientSide.startHandshake();
                Assertions.assertEquals("h3", clientSide.getHandshakeApplicationProtocol(),
                        "the selector's pick must be the negotiated application protocol: "
                                + clientSide.getHandshakeApplicationProtocol());
            }

            acceptedThread.join();
            Assertions.assertEquals("installed", acceptedSelector.get(),
                    "the installed selector must be readable back: " + acceptedSelector.get());
            Assertions.assertEquals("h3", acceptedProtocol.get(),
                    "the accepted side must report the negotiated application protocol: " + acceptedProtocol.get());
        }
    }

    /**
     * A selector that returns no name offers the socket no ALPN protocol, so an offered name must never
     * reach the wire.
     */
    @Test
    public void testAlpnSelectorOfferingNothingDeclinesAlpn() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[] { "h2", "h3" });
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<String> acceptedProtocol = new AtomicReference<>();

            Thread acceptedThread = new Thread(() -> {
                try {
                    Socket socket = serverSocket.accept();
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.setHandshakeApplicationProtocolSelector((sock, names) -> null);
                    try {
                        serverSide.getInputStream();
                    } catch (IOException e) {
                    }
                    acceptedProtocol.compareAndSet(null, serverSide.getHandshakeApplicationProtocol());
                    socket.close();
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, new TlsPSKIdentity() {
                @Override
                public void skipIdentityHint() {}

                @Override
                public void notifyIdentityHint(byte[] psk_identity_hint) {}

                @Override
                public byte[] getPSKIdentity() { return "test".getBytes(); }

                @Override
                public byte[] getPSK() { return TesterSupport.testPskKey; }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                try {
                    clientSide.startHandshake();
                } catch (IOException e) {
                }
            }

            acceptedThread.join();
            Assertions.assertTrue(!"h2".equals(acceptedProtocol.get()) && !"h3".equals(acceptedProtocol.get()),
                    "a selector that returns no name must not negotiate an offered ALPN protocol: "
                            + acceptedProtocol.get());
        }
    }

    @Test
    public void testAlpnNegotiation() throws Exception {
        String alpnProtocol = "h2";
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] {
                        CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
                },
                0,
                new String[] { alpnProtocol }
        );

        TlsPSKIdentityManager serverMgr = new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() { return new byte[0]; }
            @Override
            public byte[] getPSK(byte[] identity) { return TesterSupport.KEY_1; }
        };

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, serverMgr);
        LinkedBlockingQueue<Integer> serverReady = new LinkedBlockingQueue<>();
        AtomicReference<String> negotiatedProtocol = new AtomicReference<>();

        Thread serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
                serverSocket.bind(new InetSocketAddress(0));
                serverReady.offer(serverSocket.getLocalPort());
                try (Socket socket = serverSocket.accept()) {
                    // Trigger handshake to negotiate ALPN
                    socket.getInputStream();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.start();

        // Wait for server thread to start
        int port = serverReady.take();
        BasicTlsPSKIdentity clientIdentity = new BasicTlsPSKIdentity("alpn-test", TesterSupport.KEY_1);
        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, clientIdentity);

        try {
            Socket socket = clientFactory.createSocket("localhost", port);
            SSLSocket sslSocket = (SSLSocket) socket;
            sslSocket.startHandshake();

            String result = sslSocket.getApplicationProtocol();
            TesterSupport.log("Negotiated Protocol: " + result);
            negotiatedProtocol.set(result);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            serverThread.join();
        }

        Assertions.assertEquals(alpnProtocol, negotiatedProtocol.get());
    }


    @Test
    public void testApplicationProtocolsAreValidated() throws Exception {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                    new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 }, 0,
                    new String[] { "" });
        });
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                    new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 }, 0,
                    new String[] { "h2", "h2" });
        });

        BcPskTlsParams params = new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 }, 0,
                new String[] { "h2" });
        Assertions.assertEquals(1, params.getApplicationProtocols().length,
                "a valid ALPN name must survive construction");
    }


    /**
     * The socket reports the ALPN outcome itself, not only through the session: before the handshake
     * nothing is known, and after it both getApplicationProtocol() and
     * getHandshakeApplicationProtocol() name the negotiated protocol.
     */
    @Test
    public void testApplicationProtocolIsReadableFromTheSocket() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[] { "h2" });
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<String> acceptedProtocol = new AtomicReference<>();

            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                    acceptedProtocol.compareAndSet(null, serverSide.getHandshakeApplicationProtocol());
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, new TlsPSKIdentity() {
                @Override
                public void skipIdentityHint() {}

                @Override
                public void notifyIdentityHint(byte[] psk_identity_hint) {}

                @Override
                public byte[] getPSKIdentity() { return "test".getBytes(); }

                @Override
                public byte[] getPSK() { return TesterSupport.testPskKey; }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                Assertions.assertNull(clientSide.getHandshakeApplicationProtocol(),
                        "the ALPN decision is unknown before the handshake runs");
                clientSide.startHandshake();
                Assertions.assertEquals("h2", clientSide.getHandshakeApplicationProtocol(),
                        "the negotiated application protocol must be readable from the socket: "
                                + clientSide.getHandshakeApplicationProtocol());
                Assertions.assertEquals(clientSide.getApplicationProtocol(),
                        clientSide.getHandshakeApplicationProtocol(),
                        "the socket and the handshake must agree on the application protocol");
            }

            acceptedThread.join();
            Assertions.assertEquals("h2", acceptedProtocol.get(),
                    "the accepted side must report the negotiated application protocol: " + acceptedProtocol.get());
        }
    }

    /**
     * getSSLParameters() reports what our handshake actually reads: the socket's enabled cipher suites,
     * enabled protocol versions, and the ALPN names it offers. It never reports the empty JDK default
     * while those are set.
     */
    @Test
    public void testSSLParametersReportTheEnabledState() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[] { "h2", "h3" });
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            SSLParameters offered = ((SSLServerSocket) serverSocket).getSSLParameters();
            Assertions.assertNotNull(offered.getCipherSuites(),
                    "the server socket must report its enabled cipher suites");
            Assertions.assertEquals(1, offered.getCipherSuites().length,
                    "the server socket must report its one enabled cipher suite");
            Assertions.assertEquals("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", offered.getCipherSuites()[0],
                    "the server socket must name its enabled cipher suite");
            Assertions.assertEquals(2, offered.getApplicationProtocols().length,
                    "the server socket must offer both ALPN names");
            Assertions.assertTrue(offered.getUseCipherSuitesOrder(),
                    "the server end picks the cipher suite, so the order flag must be set");

            AtomicReference<SSLParameters> acceptedParameters = new AtomicReference<>();
            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    acceptedParameters.compareAndSet(null, serverSide.getSSLParameters());
                    serverSide.getInputStream();
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, new TlsPSKIdentity() {
                @Override
                public void skipIdentityHint() {}

                @Override
                public void notifyIdentityHint(byte[] psk_identity_hint) {}

                @Override
                public byte[] getPSKIdentity() { return "test".getBytes(); }

                @Override
                public byte[] getPSK() { return TesterSupport.testPskKey; }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                SSLParameters wanted = clientSide.getSSLParameters();
                Assertions.assertNotNull(wanted.getCipherSuites(),
                        "the client socket must report its enabled cipher suites");
                Assertions.assertEquals(1, wanted.getCipherSuites().length,
                        "the client socket must report its one enabled cipher suite");
                Assertions.assertEquals("TLSv1.2", wanted.getProtocols()[0],
                        "the client socket must name its enabled protocol version");
                Assertions.assertEquals(2, wanted.getApplicationProtocols().length,
                        "the client socket must report both ALPN names it offers");
                Assertions.assertFalse(wanted.getUseCipherSuitesOrder(),
                        "the client end picks no cipher suite, so the order flag must stay clear");
                clientSide.startHandshake();
            }

            acceptedThread.join();
            SSLParameters accepted = acceptedParameters.get();
            Assertions.assertNotNull(accepted, "the accepted socket must report its SSLParameters");
            Assertions.assertEquals(1, accepted.getCipherSuites().length,
                    "the accepted socket must report the enabled cipher suite it inherited");
            Assertions.assertTrue(accepted.getUseCipherSuitesOrder(),
                    "the accepted socket is the server end, so the order flag must be set");
        }
    }

}
