/*
 * Copyright (C) 2024 Clover Network, Inc.
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
import org.bouncycastle.tls.TlsPSKIdentity;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;


// Test the factories without third-party client/server libraries
public class TestBcPskFactories {

    @Test
    public void testInvalidPskFails() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        TlsPSKIdentityManager serverMgr = TesterSupport.createTestTlsPSKIdentityManager();

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, serverMgr);
        LinkedBlockingQueue<Integer> serverReady = new LinkedBlockingQueue<>();
        AtomicBoolean serverHandshakeFailed = new AtomicBoolean(false);
        CountDownLatch serverVerdict = new CountDownLatch(1);

        Thread serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
                serverSocket.bind(new InetSocketAddress(0));
                serverReady.offer(serverSocket.getLocalPort());
                try (Socket socket = serverSocket.accept()) {
                    // Trigger handshake
                    socket.getInputStream();
                } catch (Exception e) {
                    serverHandshakeFailed.set(true);
                }
                serverVerdict.countDown();
            } catch (Exception e) {
                serverVerdict.countDown();
            }
        });
        serverThread.start();

        // Wait for server thread to start
        int port = serverReady.take();

        BasicTlsPSKIdentity clientIdentity = new BasicTlsPSKIdentity(TesterSupport.ID_2, TesterSupport.KEY_2);
        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, clientIdentity);

        try {
            SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket("localhost", port);
            Assertions.assertThrows(IOException.class, () -> {
                sslSocket.startHandshake();
            });
        } catch (IOException e) {
            // createSocket rejected the connection before the handshake started
        }

        Assertions.assertTrue(serverVerdict.await(5, TimeUnit.SECONDS),
                "server must reach a handshake verdict");
        Assertions.assertTrue(serverHandshakeFailed.get(),
                "server must reject an unknown PSK identity");
    }

    @Test
    public void testRaiseAlertFatalSignalsFailure() throws Exception {
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(new BcPskTlsParams(), TesterSupport.testIdentityMgr);
        BcPskTlsServerProtocol protocol =
                new BcPskTlsServerProtocol(
                        new ByteArrayInputStream(new byte[0]),
                        new ByteArrayOutputStream(),
                        serverFactory
                );

        try {
            protocol.raiseAlertFatal((short) 0, "test", new RuntimeException("fatal"));
            Assertions.fail("raiseAlertFatal should have thrown an exception");
        } catch (IOException e) {
            // Success
        }
    }

    @Test
    public void testAlertFlagsAreInstanceScoped() throws Exception {
        BcPskSSLServerSocketFactory quietFactory = new BcPskSSLServerSocketFactory(new BcPskTlsParams(), TesterSupport.testIdentityMgr);
        BcPskSSLServerSocketFactory strictFactory = new BcPskSSLServerSocketFactory(new BcPskTlsParams(), TesterSupport.testIdentityMgr);
        quietFactory.throwIOExceptionOnFatalAlert = false;

        BcPskTlsServerProtocol quietProtocol =
                new BcPskTlsServerProtocol(
                        new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream(), quietFactory);
        BcPskTlsServerProtocol strictProtocol =
                new BcPskTlsServerProtocol(
                        new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream(), strictFactory);

        quietProtocol.raiseAlertFatal((short) 0, "legacy mode continues the exchange", null);
        Assertions.assertThrows(IOException.class, () -> {
            strictProtocol.raiseAlertFatal((short) 0, "default mode signals failure", null);
        });
    }

    @Test
    public void testHandshakeCompletedListenerIsNotified() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

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
                    return TesterSupport.testPskKey;
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

    @Test
    public void testStartHandshakeIsIdempotent() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
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
                    return TesterSupport.testPskKey;
                }
            });

            CountDownLatch latch = new CountDownLatch(1);
            LinkedBlockingQueue<HandshakeCompletedEvent> events = new LinkedBlockingQueue<>();

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);

                sslSocket.addHandshakeCompletedListener(event -> {
                    events.add(event);
                    latch.countDown();
                });

                sslSocket.startHandshake();
                sslSocket.startHandshake();
                sslSocket.startHandshake();
            }

            Assertions.assertTrue(latch.await(5, TimeUnit.SECONDS), "handshake must notify its listener");
            Assertions.assertEquals(1, events.size(), "startHandshake must notify listeners exactly once");
        }
    }

    @Test
    public void testServerHandshakeListenerIsNotified() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<SSLSession> serverSession = new AtomicReference<SSLSession>();
            AtomicReference<SSLSocket> acceptedSide = new AtomicReference<SSLSocket>();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    acceptedSide.compareAndSet(null, serverSide);
                    serverSide.addHandshakeCompletedListener(event -> {
                        serverSession.compareAndSet(null, event.getSession());
                        latch.countDown();
                    });
                    serverSide.startHandshake();
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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                sslSocket.startHandshake();
            }

            Assertions.assertTrue(latch.await(5, TimeUnit.SECONDS),
                    "server handshake listener must be notified when the handshake completes");
            Assertions.assertNotNull(serverSession.get(), "server socket must expose the handshake session");
            Assertions.assertNotNull(serverSession.get().getCipherSuite(),
                    "server session must report the negotiated cipher suite");
            Assertions.assertEquals(serverSession.get(), acceptedSide.get().getSession(),
                    "the listener must receive the socket's own session object");
        }
    }

    @Test
    public void testEnabledSetsConstrainNegotiation() throws Exception {
        String pskSuite = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384";
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<SSLSession> serverSession = new AtomicReference<SSLSession>();
            AtomicReference<SSLSocket> acceptedSide = new AtomicReference<SSLSocket>();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    acceptedSide.compareAndSet(null, serverSide);
                    serverSide.setEnabledProtocols(new String[] { "TLSv1.2" });
                    serverSide.setEnabledCipherSuites(new String[] { pskSuite });
                    serverSide.addHandshakeCompletedListener(event -> {
                        serverSession.compareAndSet(null, event.getSession());
                        latch.countDown();
                    });
                    serverSide.startHandshake();
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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                clientSide.startHandshake();

                Assertions.assertNotNull(acceptedSide.get(), "the server socket must have accepted the connection");
                Assertions.assertEquals(1, acceptedSide.get().getEnabledProtocols().length,
                        "setEnabledProtocols() on the accepted socket must narrow its enabled protocols");
                Assertions.assertEquals("TLSv1.2", acceptedSide.get().getEnabledProtocols()[0],
                        "setEnabledProtocols() on the accepted socket must narrow its enabled protocols");
                Assertions.assertEquals(pskSuite, acceptedSide.get().getEnabledCipherSuites()[0],
                        "setEnabledCipherSuites() on the accepted socket must narrow its enabled suites");

                SSLSession clientSession = clientSide.getSession();
                Assertions.assertEquals("TLSv1.2", clientSession.getProtocol(),
                        "the client must see the version the accepted socket's enabled protocols forced");
                Assertions.assertEquals(pskSuite, clientSession.getCipherSuite(),
                        "the client must see the suite the accepted socket's enabled suites forced");
            }

            Assertions.assertTrue(latch.await(5, TimeUnit.SECONDS),
                    "server handshake listener must be notified when the handshake completes");
            Assertions.assertNotNull(serverSession.get(), "server socket must expose the handshake session");
            Assertions.assertEquals("TLSv1.2", serverSession.get().getProtocol(),
                    "the server must negotiate the version its enabled protocols allowed");
            Assertions.assertEquals(pskSuite, serverSession.get().getCipherSuite(),
                    "the server must negotiate the suite its enabled suites allowed");
        }
    }

    @Test
    public void testEnabledSetSettersRejectUnknownNames() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                Assertions.assertThrows(IllegalArgumentException.class,
                        () -> clientSide.setEnabledCipherSuites(new String[] { "not-a-suite" }),
                        "the client socket must reject a cipher suite it does not support");
                Assertions.assertThrows(IllegalArgumentException.class,
                        () -> clientSide.setEnabledProtocols(new String[] { "TLSv9.9" }),
                        "the client socket must reject a protocol version it does not support");
                clientSide.setEnabledProtocols(new String[] { "TLSv1.2" });
                Assertions.assertEquals(1, clientSide.getEnabledProtocols().length,
                        "a supported protocol must be accepted by the client socket");
            }
        }
    }

    @Test
    public void testCloseIsNotBlockedByStalledHandshake() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<SSLSocket> acceptedSocket = new AtomicReference<SSLSocket>();
            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    acceptedSocket.set(serverSide);
                    // No client ever sends a ClientHello, so this blocks until the socket is closed.
                    serverSide.startHandshake();
                } catch (IOException e) {
                }
            }).start();

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                for (int attempt = 0; attempt < 100 && acceptedSocket.get() == null; attempt++) {
                    Thread.sleep(20);
                }
                SSLSocket accepted = acceptedSocket.get();
                Assertions.assertNotNull(accepted,
                        "the server socket must accept the connection before the handshake stalls");

                AtomicReference<IOException> closeFailure = new AtomicReference<IOException>();
                Thread closer = new Thread(() -> {
                    try {
                        accepted.close();
                    } catch (IOException e) {
                        closeFailure.set(e);
                    }
                });
                closer.start();
                closer.join(2000);
                Assertions.assertTrue(!closer.isAlive(),
                        "close() must return while another thread is blocked in the handshake");
                Assertions.assertTrue(closeFailure.get() == null,
                        "closing the stalled socket must not fail: " + closeFailure.get());
            }
        }
    }

    @Test
    public void testClientCloseIsNotBlockedByStalledHandshake() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        AtomicReference<SSLSocket> clientSocketRef = new AtomicReference<SSLSocket>();
        AtomicReference<IOException> stalledFailure = new AtomicReference<IOException>();

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            // The accepted socket is never handshook, so the client's connect() stays blocked until
            // this thread ends and EOFs the connection.
            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    Thread.sleep(3000);
                } catch (IOException | InterruptedException e) {
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
                    return TesterSupport.testPskKey;
                }
            });

            Thread handshake = new Thread(() -> {
                try (Socket rawSocket = new Socket("localhost", actualPort)) {
                    SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                    clientSocketRef.compareAndSet(null, clientSide);
                    clientSide.startHandshake();
                } catch (IOException e) {
                    stalledFailure.compareAndSet(null, e);
                }
            });
            handshake.start();

            for (int attempt = 0; attempt < 100 && clientSocketRef.get() == null; attempt++) {
                Thread.sleep(20);
            }
            SSLSocket clientSide = clientSocketRef.get();
            Assertions.assertNotNull(clientSide, "the client socket must exist before its handshake stalls");

            // close() must not report an error where javax.net.ssl.Socket.close() reports none; the
            // wrong order (hang up, then let Bouncy Castle raise its alert) is what produces one.
            AtomicReference<IOException> closeFailure = new AtomicReference<IOException>();
            Thread closer = new Thread(() -> {
                try {
                    clientSide.close();
                } catch (IOException e) {
                    closeFailure.compareAndSet(null, e);
                }
            });
            closer.start();
            closer.join(1000);
            Assertions.assertTrue(!closer.isAlive(),
                    "close() must return while another thread is blocked in connect()");

            Assertions.assertNull(closeFailure.get(),
                    "close() must not throw while another thread is stalled in connect(); javax.net.ssl.Socket.close()"
                            + " reports no error: " + closeFailure.get());

            handshake.join(5000);
            Assertions.assertNotNull(stalledFailure.get(),
                    "the stalled handshake must have been attempted and aborted: " + stalledFailure.get());
        }
    }

    @Test
    public void testFailedHandshakeIsNotRetryable() throws Exception {
        BcPskTlsParams serverParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                300000,
                new String[0]
        );
        BcPskTlsParams clientParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv13 },
                new int[] { CipherSuite.TLS_AES_128_GCM_SHA256 },
                300000,
                new String[0]
        );

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(serverParams, TesterSupport.testIdentityMgr);

        AtomicReference<SSLSocket> acceptedSide = new AtomicReference<SSLSocket>();
        AtomicReference<IOException> serverFailure = new AtomicReference<IOException>();
        CountDownLatch handshakeAttempted = new CountDownLatch(1);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    acceptedSide.compareAndSet(null, serverSide);
                    try {
                        serverSide.startHandshake();
                    } catch (IOException e) {
                        serverFailure.compareAndSet(null, e);
                    }
                } catch (IOException e) {
                    // accept() failure: the accepted-socket assertions below cover the real path
                }
                handshakeAttempted.countDown();
            }).start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(clientParams, new TlsPSKIdentity() {
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

            IOException clientFailure = null;
            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);

                try {
                    clientSide.startHandshake();
                    Assertions.fail("the two sides share no protocol version, so the handshake must fail");
                } catch (IOException e) {
                    clientFailure = e;
                }

                IOException clientRetry = (IOException) Assertions.assertThrows(IOException.class,
                        () -> clientSide.startHandshake(),
                        "a second attempt must fail with an IOException, not Bouncy Castle's IllegalStateException");
                Assertions.assertTrue(clientFailure == clientRetry,
                        "the retry must rethrow the recorded handshake failure");
                Assertions.assertTrue(clientSide.isClosed(),
                        "a failed handshake must close the socket, as javax.net.ssl.SSLSocket documents");
            }

            Assertions.assertTrue(handshakeAttempted.await(5, TimeUnit.SECONDS),
                    "the server handshake attempt must finish");
            SSLSocket serverSide = acceptedSide.get();
            Assertions.assertNotNull(serverSide, "the server socket must have been accepted");
            IOException recordedServerFailure = serverFailure.get();
            Assertions.assertNotNull(recordedServerFailure, "the server handshake must have failed too");
            IOException serverRetry = (IOException) Assertions.assertThrows(IOException.class,
                    () -> serverSide.startHandshake(),
                    "the accepted socket must refuse a second handshake attempt");
            Assertions.assertTrue(recordedServerFailure == serverRetry,
                    "the retry must rethrow the recorded failure, not build a fresh protocol over the consumed streams");
        }
    }

    @Test
    public void testSocketToString() {
        BcPskTlsParams params = new BcPskTlsParams();
        TlsPSKIdentityManager serverMgr = TesterSupport.createTestTlsPSKIdentityManager();

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, serverMgr);
        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            String serverSocketStr = serverSocket.toString();
            int actualPort = serverSocket.getLocalPort();
            if (!serverSocketStr.contains(String.valueOf(actualPort))) {
                throw new AssertionFailedError("toString port missing/wrong, expected=" + actualPort
                        + ", toString()=\"" + serverSocketStr + "\"");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testServerSocketIntrospectionIsPopulated() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<SSLSocket> acceptedSide = new AtomicReference<SSLSocket>();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    acceptedSide.compareAndSet(null, serverSide);
                    serverSide.addHandshakeCompletedListener(event -> {
                        latch.countDown();
                    });
                    serverSide.startHandshake();
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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                sslSocket.startHandshake();
            }

            Assertions.assertTrue(latch.await(5, TimeUnit.SECONDS), "handshake must complete");
            SSLSocket accepted = acceptedSide.get();
            String suite = accepted.getSession().getCipherSuite();
            Assertions.assertNotNull(suite, "negotiated suite must be reported");

            String[] supportedSuites = accepted.getSupportedCipherSuites();
            Assertions.assertEquals(params.getSupportedCipherSuites().length, supportedSuites.length,
                    "getSupportedCipherSuites() must report the factory's suites");
            int found = -1;
            for (int i = 0; i < supportedSuites.length; i++) {
                if (supportedSuites[i].equals(suite)) {
                    found = i;
                    break;
                }
            }
            Assertions.assertTrue(found >= 0, "negotiated suite " + suite + " must be listed as supported");
            Assertions.assertEquals(params.getSupportedProtocols().length, accepted.getSupportedProtocols().length,
                    "getSupportedProtocols() must report the factory's protocols");
            Assertions.assertEquals(params.getSupportedCipherSuites().length, accepted.getEnabledCipherSuites().length,
                    "every supported suite is enabled by default");

            accepted.setEnabledCipherSuites(new String[] { suite });
            Assertions.assertEquals(1, accepted.getEnabledCipherSuites().length,
                    "setEnabledCipherSuites() must narrow the enabled set");

            Assertions.assertThrows(IllegalArgumentException.class, () -> {
                accepted.setEnabledCipherSuites(new String[] { "not-a-suite" });
            });
        }
    }

    @Test
    public void testSessionIsStableAndTimesOut() throws Exception {
        final int sessionTimeoutMillis = 100;
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                sessionTimeoutMillis);

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);
        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<Long> eventSessionCreationTime = new AtomicReference<Long>(Long.valueOf(0L));

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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);

                sslSocket.addHandshakeCompletedListener(event -> {
                    eventSessionCreationTime.set(event.getSession().getCreationTime());
                    latch.countDown();
                });

                sslSocket.startHandshake();

                Assertions.assertTrue(latch.await(5, TimeUnit.SECONDS),
                        "Handshake completed listener was not notified");

                SSLSession firstSession = sslSocket.getSession();
                firstSession.putValue("probe", "value");

                Thread.sleep(4 * sessionTimeoutMillis);

                SSLSession secondSession = sslSocket.getSession();

                Assertions.assertEquals(firstSession.getCreationTime(), secondSession.getCreationTime(),
                        "getSession() must return one session with one creation time");
                Assertions.assertEquals(firstSession.getCreationTime(), eventSessionCreationTime.get(),
                        "Handshake completed listener must be given the socket's session");
                Assertions.assertEquals("value", secondSession.getValue("probe"),
                        "Values put into the session must be visible from any handle to it");
                Assertions.assertFalse(firstSession.isValid(),
                        "Session must expire once older than the session timeout");
                Assertions.assertFalse(secondSession.isValid(),
                        "Session must expire once older than the session timeout");
            }
        }
    }

    @Test
    public void testClientSessionIsValidOnlyAfterHandshake() throws Exception {
        final int sessionTimeoutMillis = 150;
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                sessionTimeoutMillis);

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);
        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                SSLSession session = sslSocket.getSession();
                Assertions.assertFalse(session.isValid(),
                        "a socket that never handshook has no session to be valid");

                // Longer than the session timeout: a clock started at construction would already have
                // expired by the time the handshake runs.
                Thread.sleep(4 * sessionTimeoutMillis);
                long handshakeStartedAt = System.currentTimeMillis();
                sslSocket.startHandshake();

                Assertions.assertTrue(session.isValid(),
                        "the session must be valid right after its handshake, not already timed out");
                Assertions.assertTrue(session.getCreationTime() >= handshakeStartedAt,
                        "the session clock must start at the handshake, not at socket construction");
            }
        }
    }

    @Test
    public void testServerSessionIsValidOnlyAfterHandshake() throws Exception {
        final int sessionTimeoutMillis = 150;
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                sessionTimeoutMillis);

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);
        AtomicReference<SSLSocket> acceptedRef = new AtomicReference<SSLSocket>();
        AtomicReference<IOException> clientFailure = new AtomicReference<IOException>();

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            // Holds the accepted socket open while the main thread drives its handshake.
            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    acceptedRef.compareAndSet(null, (SSLSocket) socket);
                    Thread.sleep(3000);
                } catch (IOException | InterruptedException e) {
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
                    return TesterSupport.testPskKey;
                }
            });

            Thread client = new Thread(() -> {
                try (Socket rawSocket = new Socket("localhost", actualPort)) {
                    SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                    clientSide.startHandshake();
                } catch (IOException e) {
                    clientFailure.compareAndSet(null, e);
                }
            });
            client.start();

            for (int attempt = 0; attempt < 100 && acceptedRef.get() == null; attempt++) {
                Thread.sleep(20);
            }
            SSLSocket accepted = acceptedRef.get();
            Assertions.assertNotNull(accepted, "the server socket must have accepted the connection");

            SSLSession session = accepted.getSession();
            Assertions.assertFalse(session.isValid(),
                    "an accepted socket that never handshook has no session to be valid");

            Thread.sleep(4 * sessionTimeoutMillis);
            long handshakeStartedAt = System.currentTimeMillis();
            accepted.startHandshake();

            Assertions.assertTrue(session.isValid(),
                    "the session must be valid right after its handshake, not already timed out");
            Assertions.assertTrue(session.getCreationTime() >= handshakeStartedAt,
                    "the session clock must start at the handshake, not at socket construction");

            client.join(5000);
            Assertions.assertNull(clientFailure.get(),
                    "the client handshake must complete once the accepted socket handshakes");
        }
    }

    @Test
    public void testPskBufferSurvivesHandshake() throws Exception {
        // Bouncy Castle zeroes the PSK buffer it is handed, so one array shared by both ends (or reused
        // across connections) must not be handed over raw.
        final byte[] psk = new byte[] {
                0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
                0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
        };
        final byte[] expected = Arrays.copyOf(psk, psk.length);

        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 });

        final TlsPSKIdentityManager mgr = new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() { return new byte[0]; }

            @Override
            public byte[] getPSK(byte[] identity) {
                return psk;
            }
        };

        final TlsPSKIdentity clientIdentity = new TlsPSKIdentity() {
            @Override
            public void skipIdentityHint() {}

            @Override
            public void notifyIdentityHint(byte[] psk_identity_hint) {}

            @Override
            public byte[] getPSKIdentity() {
                return "shared".getBytes();
            }

            @Override
            public byte[] getPSK() {
                return psk;
            }
        };

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, mgr);
        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, clientIdentity);

        for (int attempt = 0; attempt < 2; attempt++) {
            try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
                serverSocket.bind(new InetSocketAddress(0));
                int port = serverSocket.getLocalPort();

                CountDownLatch latch = new CountDownLatch(1);

                new Thread(() -> {
                    try (Socket socket = serverSocket.accept()) {
                        socket.getInputStream();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }).start();

                try (Socket rawSocket = new Socket("localhost", port)) {
                    SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", port, true);
                    sslSocket.addHandshakeCompletedListener(event -> latch.countDown());
                    sslSocket.startHandshake();
                    Assertions.assertTrue(latch.await(5, TimeUnit.SECONDS),
                            "Handshake attempt " + attempt + " did not complete");
                }
            }

            Assertions.assertTrue(Arrays.equals(expected, psk),
                    "The factories must not mutate the caller's pre-shared key");
        }
    }

    @Test
    public void testSessionIdIsNullWithoutSession() throws Exception {
        BcPskTlsParams clientParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv13 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 });
        BcPskTlsParams serverParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 });

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(serverParams, TesterSupport.testIdentityMgr);
        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(clientParams, new TlsPSKIdentity() {
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

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    socket.getInputStream();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                SSLSession session = sslSocket.getSession();
                Assertions.assertNull(session.getId(), "no session before the handshake");
                try {
                    sslSocket.startHandshake();
                    Assertions.fail("the handshake should have failed with disjoint parameters");
                } catch (IOException e) {
                }
                Assertions.assertNull(session.getId(),
                        "a failed handshake leaves no session, and getId() must not throw");
            }
        }
    }

    @Test
    public void testToStringNamesTheWrapper() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 });

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);
        AtomicReference<SSLSocket> acceptedRef = new AtomicReference<SSLSocket>();

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            // No handshake is needed for toString(); the thread only holds the socket open.
            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    acceptedRef.compareAndSet(null, (SSLSocket) socket);
                    Thread.sleep(2000);
                } catch (IOException | InterruptedException e) {
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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);

                for (int attempt = 0; attempt < 100 && acceptedRef.get() == null; attempt++) {
                    Thread.sleep(20);
                }
                SSLSocket accepted = acceptedRef.get();
                Assertions.assertNotNull(accepted, "the server socket must have accepted the connection");
                Assertions.assertTrue(accepted.toString().startsWith("WrappedSSL"),
                        "the accepted socket must use the base WrappedSSLSocket toString");
                Assertions.assertEquals("WrappedSSL" + rawSocket.toString(), clientSide.toString(),
                        "toString must be the base's prefix plus the wrapped socket's own toString");
            }
        }
    }

    @Test
    public void testBothEndsReportTheSameNegotiatedState() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 });

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);
        AtomicReference<SSLSocket> acceptedRef = new AtomicReference<SSLSocket>();

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    acceptedRef.compareAndSet(null, (SSLSocket) socket);
                    socket.getInputStream();
                    Thread.sleep(2000);
                } catch (IOException | InterruptedException e) {
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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);

                for (int attempt = 0; attempt < 100 && acceptedRef.get() == null; attempt++) {
                    Thread.sleep(20);
                }
                SSLSocket accepted = acceptedRef.get();
                Assertions.assertNotNull(accepted, "the server socket must have accepted the connection");

                clientSide.startHandshake();

                SSLSession clientSession = clientSide.getSession();
                SSLSession serverSession = accepted.getSession();
                Assertions.assertEquals(clientSession.getCipherSuite(), serverSession.getCipherSuite(),
                        "both ends must report one negotiated cipher suite");
                Assertions.assertEquals(clientSession.getProtocol(), serverSession.getProtocol(),
                        "both ends must report one negotiated protocol version");
                Assertions.assertTrue(Arrays.equals(clientSession.getId(), serverSession.getId()),
                        "both ends must report the session's own identifier");
            }
        }
    }

    @Test
    public void testIdentityIsReadOncePerHandshake() throws Exception {
        // TLS 1.3 only: Bouncy Castle gathers the client's external PSKs (getExternalPSKs) when it
        // builds a TLS 1.3 ClientHello (TlsUtils.addPreSharedKeyToClientHello).
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv13 },
                new int[] { CipherSuite.TLS_AES_128_GCM_SHA256 });

        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);
        final int[] pskReads = new int[] { 0 };
        final int[] identityReads = new int[] { 0 };

        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, new TlsPSKIdentity() {
            @Override
            public void skipIdentityHint() {}

            @Override
            public void notifyIdentityHint(byte[] psk_identity_hint) {}

            @Override
            public byte[] getPSKIdentity() {
                identityReads[0]++;
                return "test".getBytes();
            }

            @Override
            public byte[] getPSK() {
                pskReads[0]++;
                return TesterSupport.testPskKey;
            }
        });

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    socket.getInputStream();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                clientSide.startHandshake();
                Assertions.assertEquals(1, identityReads[0],
                        "the factory must read the caller's identity bytes once per handshake");
                Assertions.assertEquals(1, pskReads[0],
                        "the factory must read the caller's PSK once per handshake, so a stateful manager"
                                + " offers the same key on the external-PSK and negotiated paths");
            }
        }
    }

    /**
     * I/O on the client drives the handshake too, as javax.net.ssl.SSLSocket guarantees: an
     * application that never calls startHandshake() still sends its ClientHello, gets a live
     * session, and has its handshake-completed listeners run.
     */
    @Test
    public void testClientIoDrivesTheHandshake() throws Exception {
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

        CountDownLatch clientListenerNotified = new CountDownLatch(1);
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
                clientSide.addHandshakeCompletedListener(event -> {
                    clientListenerNotified.countDown();
                });

                // Only the read side is touched: no startHandshake() anywhere.
                clientSide.getInputStream();

                for (int attempt = 0; attempt < 100 && acceptedRef.get() == null; attempt++) {
                    Thread.sleep(20);
                }
                Assertions.assertNotNull(acceptedRef.get(), "the server must have accepted the connection");
                Assertions.assertTrue(clientListenerNotified.await(5, TimeUnit.SECONDS),
                        "the handshake-completed listener must run when I/O drove the handshake");
                Assertions.assertTrue(clientSide.getSession().isValid(),
                        "I/O alone must have produced a live session");
            }
        }
    }

    /**
     * close() must not report an error the JDK would not: javax.net.ssl.Socket.close() is quiet and
     * best-effort, which is what keeps a with-scope cleanup from replacing an exception the body was
     * already raising. Handing Bouncy Castle's close_notify alert a socket it already hung up is how
     * the wrong order breaks that contract.
     */
    @Test
    public void testClientCloseDoesNotThrowOnALiveConnection() throws Exception {
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

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            // A peer keeps the connection two-sided; the close() under test is the client's.
            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    socket.getInputStream();
                    Thread.sleep(2000);
                } catch (IOException | InterruptedException e) {
                }
            }).start();

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                clientSide.startHandshake();

                try {
                    clientSide.close();
                } catch (IOException e) {
                    Assertions.fail("close() must not throw on a live connection; javax.net.ssl.Socket.close()"
                            + " reports no error to the with-scope cleanup that calls it: " + e);
                }
                Assertions.assertTrue(clientSide.isClosed(), "close() must leave the client socket closed");
            }
        }
    }

    /**
     * When the peer hangs up first, the client's close() writes into a connection that is already
     * going away. javax.net.ssl.Socket.close() stays quiet there, and the with-scope cleanup that
     * calls it must not replace an exception the body was already raising.
     */
    @Test
    public void testClientCloseIsQuietWhenThePeerHungUpFirst() throws Exception {
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

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            // The peer completes the handshake, then hangs up as soon as the client is ready to close.
            AtomicReference<IOException> closeFailure = new AtomicReference<IOException>();
            AtomicReference<Boolean> peerMayHangUp = new AtomicReference<Boolean>();
            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    socket.getInputStream();
                    while (peerMayHangUp.get() == null) {
                        Thread.sleep(20);
                    }
                } catch (IOException | InterruptedException e) {
                }
            }).start();

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                clientSide.startHandshake();
                peerMayHangUp.compareAndSet(null, true);
                for (int attempt = 0; attempt < 25; attempt++) {
                    Thread.sleep(20);
                }

                try {
                    clientSide.close();
                } catch (IOException e) {
                    closeFailure.compareAndSet(null, e);
                }
                Assertions.assertNull(closeFailure.get(),
                        "close() must not report an error where javax.net.ssl.Socket.close() reports none: "
                                + closeFailure.get());
            }
        }
    }


    /**
     * A listener is user code reached only after the handshake completed, so its exception must not
     * turn that completed handshake into a failed startHandshake(), and it must not hide the listeners
     * registered behind it.
     */
    @Test
    public void testThrowingClientListenerDoesNotFailTheHandshake() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    socket.getInputStream();
                    Thread.sleep(2000);
                } catch (IOException | InterruptedException e) {
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
                    return TesterSupport.testPskKey;
                }
            });

            CountDownLatch secondListenerNotified = new CountDownLatch(1);
            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                sslSocket.addHandshakeCompletedListener(event -> {
                    throw new AssertionError("the first listener faults");
                });
                sslSocket.addHandshakeCompletedListener(event -> secondListenerNotified.countDown());

                sslSocket.startHandshake();
                Assertions.assertTrue(secondListenerNotified.await(5, TimeUnit.SECONDS),
                        "the listener behind the throwing one must still be notified");
                Assertions.assertNotNull(sslSocket.getSession(), "the handshake must still have completed");
            }
        }
    }

    /**
     * The server end reaches the same notification through its accessors, so a listener's exception
     * must not fail the accessor call that ran the handshake.
     */
    @Test
    public void testThrowingServerListenerDoesNotFailTheHandshake() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<String> accessorOutcome = new AtomicReference<String>();
            AtomicReference<SSLSession> serverSession = new AtomicReference<SSLSession>();
            CountDownLatch secondListenerNotified = new CountDownLatch(1);

            new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.addHandshakeCompletedListener(event -> {
                        serverSession.compareAndSet(null, event.getSession());
                        throw new AssertionError("the first server listener faults");
                    });
                    serverSide.addHandshakeCompletedListener(event -> secondListenerNotified.countDown());
                    try {
                        serverSide.getInputStream();
                        accessorOutcome.compareAndSet(null, "returned");
                    } catch (IOException e) {
                        accessorOutcome.compareAndSet(null, e.getClass().getSimpleName());
                    }
                } catch (IOException e) {
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
                    return TesterSupport.testPskKey;
                }
            });

            try (Socket rawSocket = new Socket("localhost", actualPort)) {
                SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
                sslSocket.startHandshake();
            }

            Assertions.assertTrue(secondListenerNotified.await(5, TimeUnit.SECONDS),
                    "the listener behind the throwing one must still be notified");
            Assertions.assertEquals("returned", accessorOutcome.get(),
                    "getInputStream() must return once the handshake completed: " + accessorOutcome.get());
            Assertions.assertNotNull(serverSession.get(), "the server session must still exist");
        }
    }

    /**
     * javax.net.ssl.SSLSocket hands callers getHandshakeSession(): null before any handshake ran, and
     * the session that the completed handshake made afterwards, on both ends of the connection.
     */
    @Test
    public void testHandshakeSessionIsReadableFromTheSocket() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<String> acceptedSessionBefore = new AtomicReference<>();
            AtomicReference<SSLSession> acceptedAfter = new AtomicReference<>();

            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    acceptedSessionBefore.compareAndSet(null, serverSide.getHandshakeSession() == null ? "null" : "session");
                    serverSide.getInputStream();
                    acceptedAfter.compareAndSet(null, serverSide.getHandshakeSession());
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
                Assertions.assertNull(clientSide.getHandshakeSession(),
                        "no handshake session may be reported before a handshake runs");
                clientSide.startHandshake();
                Assertions.assertEquals(clientSide.getSession(), clientSide.getHandshakeSession(),
                        "the completed handshake's session must be readable as the handshake session");
            }

            acceptedThread.join();
            Assertions.assertEquals("null", acceptedSessionBefore.get(), "the accepted side must report no handshake session"
                    + " before its handshake ran: " + acceptedSessionBefore.get());
            Assertions.assertNotNull(acceptedAfter.get(), "the accepted side must report the handshake session"
                    + " once its handshake ran: " + acceptedAfter.get());
        }
    }

    /**
     * setSSLParameters carries one policy on all three surfaces: a non-null bundle never throws and
     * moves the two knobs a PSK handshake reads into the enabled sets; a component the bundle leaves
     * unset leaves that set alone; null fails like the other null arguments the sockets reject.
     */
    @Test
    public void testSetSSLParametersMovesTheKnobsItCan() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr);

        try (ServerSocket serverSocket = serverFactory.createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            SSLServerSocket serverEnd = (SSLServerSocket) serverSocket;
            SSLParameters knobs = new SSLParameters();
            knobs.setCipherSuites(new String[] { "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256" });
            knobs.setProtocols(new String[] { "TLSv1.3" });
            serverEnd.setSSLParameters(knobs);
            Assertions.assertEquals(1, serverEnd.getEnabledCipherSuites().length,
                    "setSSLParameters must install the bundle's cipher suite: "
                            + serverEnd.getEnabledCipherSuites().length);
            Assertions.assertEquals("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
                    serverEnd.getEnabledCipherSuites()[0], "the bundle's cipher suite must be enabled");
            Assertions.assertEquals("TLSv1.3", serverEnd.getEnabledProtocols()[0],
                    "the bundle's protocol version must be enabled");
            Assertions.assertEquals(1, serverEnd.getEnabledProtocols().length,
                    "the bundle replaces the enabled protocol versions: "
                            + serverEnd.getEnabledProtocols().length);

            AtomicReference<String> acceptedProtocol = new AtomicReference<>();
            AtomicReference<String> acceptedSuite = new AtomicReference<>();
            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    SSLParameters acceptedKnobs = new SSLParameters();
                    acceptedKnobs.setProtocols(new String[] { "TLSv1.2" });
                    serverSide.setSSLParameters(acceptedKnobs);
                    acceptedProtocol.compareAndSet(null, serverSide.getEnabledProtocols()[0]);
                    acceptedSuite.compareAndSet(null, serverSide.getEnabledCipherSuites()[0]);
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
                SSLParameters clientKnobs = new SSLParameters();
                clientKnobs.setCipherSuites(new String[] { "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256" });
                clientKnobs.setProtocols(new String[] { "TLSv1.2" });
                clientSide.setSSLParameters(clientKnobs);
                Assertions.assertEquals("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
                        clientSide.getEnabledCipherSuites()[0], "the bundle's cipher suite must be enabled");
                Assertions.assertEquals(1, clientSide.getEnabledProtocols().length,
                        "the bundle replaces the enabled protocol versions: "
                                + clientSide.getEnabledProtocols().length);
                Assertions.assertEquals("TLSv1.2", clientSide.getEnabledProtocols()[0],
                        "the bundle's protocol version must be enabled");
                Assertions.assertThrows(IllegalArgumentException.class, () -> clientSide.setSSLParameters(null),
                        "a null bundle must fail like the other null arguments the sockets reject");
                clientSide.startHandshake();
            }

            acceptedThread.join();
            Assertions.assertEquals("TLSv1.2", acceptedProtocol.get(),
                    "the accepted socket must install the bundle's protocol version: " + acceptedProtocol.get());
            Assertions.assertEquals("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", acceptedSuite.get(),
                    "a bundle that leaves the cipher suites unset must leave the inherited set alone: "
                            + acceptedSuite.get());
        }
    }

    /**
     * javax.net.ssl.SSLSession documents an unavailable session context as null and throws only
     * SecurityException. A TLS-PSK connection negotiates no D-H or DSA group, so both ends answer null
     * — for the TLS 1.2 PSK suites and for TLS 1.3 — instead of throwing UnsupportedOperationException,
     * which is what resumption/KDF consumers call unguarded.
     */
    @Test
    public void testSessionContextIsUnavailableNotUnsupported() throws Exception {
        BcPskTlsParams pskParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[0]);

        try (ServerSocket serverSocket = new BcPskSSLServerSocketFactory(pskParams, TesterSupport.testIdentityMgr).createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<SSLSession> acceptedSession = new AtomicReference<>();
            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                    acceptedSession.compareAndSet(null, serverSide.getSession());
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(pskParams, new TlsPSKIdentity() {
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
                Assertions.assertNull(clientSide.getSession().getSessionContext(),
                        "a session before any handshake must report no context rather than throwing");
                clientSide.startHandshake();
                Assertions.assertNull(clientSide.getSession().getSessionContext(),
                        "the completed TLS 1.2 PSK handshake negotiates no D-H or DSA group, so its session"
                                + " context must be reported unavailable: " + clientSide.getSession().getSessionContext());
            }

            acceptedThread.join();
            Assertions.assertNotNull(acceptedSession.get(), "the accepted side must report a session once its handshake ran");
            Assertions.assertNull(acceptedSession.get().getSessionContext(),
                    "the accepted TLS 1.2 PSK session must report no session context");
        }

        BcPskTlsParams tls13Params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv13 },
                new int[] { CipherSuite.TLS_AES_128_GCM_SHA256 });

        try (ServerSocket serverSocket = new BcPskSSLServerSocketFactory(tls13Params, TesterSupport.testIdentityMgr).createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<SSLSession> acceptedSession = new AtomicReference<>();
            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                    acceptedSession.compareAndSet(null, serverSide.getSession());
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(tls13Params, new TlsPSKIdentity() {
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
                Assertions.assertNull(clientSide.getSession().getSessionContext(),
                        "a TLS 1.3 session has no D-H or DSA group either, so its session context must be"
                                + " reported unavailable: " + clientSide.getSession().getSessionContext());
            }

            acceptedThread.join();
            Assertions.assertNotNull(acceptedSession.get(), "the accepted side must report a session once its handshake ran");
            Assertions.assertNull(acceptedSession.get().getSessionContext(),
                    "the accepted TLS 1.3 session must report no session context");
        }
    }

    /**
     * javax.net.ssl.SSLSession documents an access as a new connection established with the session data,
     * and says application-level ops (getting or setting a value) are not reflected in that time. The
     * accessor must therefore report when the connection was established — never a fresh reading of the
     * wall clock — and must report nothing for a session no connection has run. Because these factories
     * establish exactly one connection per session, the access clock and the creation clock agree.
     */
    @Test
    public void testLastAccessedTimeReportsTheConnectionNotEveryAccess() throws Exception {
        BcPskTlsParams pskParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[0]);

        try (ServerSocket serverSocket = new BcPskSSLServerSocketFactory(pskParams, TesterSupport.testIdentityMgr).createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            AtomicReference<SSLSession> acceptedSession = new AtomicReference<>();
            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                    acceptedSession.compareAndSet(null, serverSide.getSession());
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(pskParams, new TlsPSKIdentity() {
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
                SSLSession session = clientSide.getSession();

                Assertions.assertEquals(0L, session.getLastAccessedTime(),
                        "no connection has been established on a session that has not run a handshake");

                long beforeHandshake = System.currentTimeMillis();
                clientSide.startHandshake();
                long afterHandshake = System.currentTimeMillis();
                long accessed = session.getLastAccessedTime();
                Assertions.assertTrue(accessed >= beforeHandshake && accessed <= afterHandshake,
                        "the access clock must record the connection that was just established: got "
                                + accessed + " for a handshake run in [" + beforeHandshake + ", "
                                + afterHandshake + "]");
                Assertions.assertEquals(session.getCreationTime(), accessed,
                        "these factories establish exactly one connection per session, so the access clock"
                                + " reports the handshake-completion time");

                session.putValue("access-clock", "probe");
                session.getValue("access-clock");
                session.getCipherSuite();
                session.getId();
                Thread.sleep(15);
                Assertions.assertEquals(accessed, session.getLastAccessedTime(),
                        "javax.net.ssl.SSLSession: getting or setting a value is an application-level op and"
                                + " must not move the access clock");
            }

            acceptedThread.join();
            SSLSession accepted = acceptedSession.get();
            Assertions.assertNotNull(accepted, "the accepted side must report a session once its handshake ran");
            long acceptedAccessed = accepted.getLastAccessedTime();
            Assertions.assertTrue(acceptedAccessed > 0,
                    "the handshake that established the accepted connection is an access, so the clock must"
                            + " report it: " + acceptedAccessed);
            Assertions.assertEquals(accepted.getCreationTime(), acceptedAccessed,
                    "one connection per session, so the accepted access clock reports the handshake-completion"
                            + " time");
            accepted.putValue("access-clock", "probe");
            accepted.getValue("access-clock");
            Assertions.assertEquals(acceptedAccessed, accepted.getLastAccessedTime(),
                    "application-level ops must not move the accepted session's access clock");
        }
    }

    /**
     * javax.net.ssl.SSLSocketFactory.createSocket(…, boolean autoClose) is documented as "close the
     * underlying socket when this socket is closed", and JDK's SSLSocketImpl keeps the flag per socket,
     * gating close()/shutdownInput()/shutdownOutput() on it so tunneling and proxy hand-offs can keep the
     * raw connection. A socket that is not connected yet is rejected with java.net.SocketException, an
     * IOException subclass, which is what the declared throws clause promises.
     */
    @Test
    public void testCreateSocketRejectsAnUnconnectedSocketWithSocketException() {
        BcPskTlsParams pskParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[0]);

        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(pskParams, new TlsPSKIdentity() {
            @Override
            public void skipIdentityHint() {}

            @Override
            public void notifyIdentityHint(byte[] psk_identity_hint) {}

            @Override
            public byte[] getPSKIdentity() { return "test".getBytes(); }

            @Override
            public byte[] getPSK() { return TesterSupport.testPskKey; }
        });

        Socket unconnected = new Socket();
        Assertions.assertThrows(SocketException.class,
                () -> clientFactory.createSocket(unconnected, "localhost", 0, true),
                "javax.net.ssl.SSLSocketFactory layers over an already-connected socket, and JDK's SSLSocketImpl"
                        + " rejects the other case with java.net.SocketException, an IOException subclass");
        Assertions.assertThrows(SocketException.class,
                () -> clientFactory.createSocket(unconnected, "localhost", 0, false),
                "autoClose false is a supported choice, not a reason to reject an unconnected socket");
    }

    @Test
    public void testCreateSocketHonoursAutoClose() throws Exception {
        BcPskTlsParams pskParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[0]);

        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(pskParams, new TlsPSKIdentity() {
            @Override
            public void skipIdentityHint() {}

            @Override
            public void notifyIdentityHint(byte[] psk_identity_hint) {}

            @Override
            public byte[] getPSKIdentity() { return "test".getBytes(); }

            @Override
            public byte[] getPSK() { return TesterSupport.testPskKey; }
        });

        // autoClose = false: the raw socket stays open for the caller after the SSL socket is closed.
        try (ServerSocket serverSocket = new BcPskSSLServerSocketFactory(pskParams, TesterSupport.testIdentityMgr).createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            Socket handedBack = new Socket("localhost", actualPort);
            SSLSocket layeredSocket = (SSLSocket) clientFactory.createSocket(handedBack, "localhost", actualPort, false);
            layeredSocket.startHandshake();
            Assertions.assertFalse(layeredSocket.isClosed(),
                    "a completed handshake leaves the SSL socket open");
            layeredSocket.close();
            Assertions.assertTrue(layeredSocket.isClosed(),
                    "javax.net.ssl.SSLSocket: closing the SSL socket closes it, whatever autoClose says");
            Assertions.assertFalse(handedBack.isClosed(),
                    "autoClose = false hands the raw connection back: closing the SSL socket must not close it");
            handedBack.close();

            acceptedThread.join();
        }

        // autoClose = true: closing the SSL socket closes the underlying socket too.
        try (ServerSocket serverSocket = new BcPskSSLServerSocketFactory(pskParams, TesterSupport.testIdentityMgr).createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            Socket autoClosedRaw = new Socket("localhost", actualPort);
            SSLSocket autoClosedSocket = (SSLSocket) clientFactory.createSocket(autoClosedRaw, "localhost", actualPort, true);
            autoClosedSocket.startHandshake();
            autoClosedSocket.close();
            Assertions.assertTrue(autoClosedRaw.isClosed(),
                    "autoClose = true closes the underlying socket when this socket is closed");

            acceptedThread.join();
        }
    }

    /**
     * javadir java/net/Socket.java:1118 sends "one byte of urgent data … the lowest eight bits of the
     * data parameter", and java/net/Socket.java:1126-1127 refuses with
     * java.net.SocketException("Urgent data not supported") when the platform has no out-of-band channel;
     * java/net/Socket.java:1157 and java/net/Socket.java:1174 declare java.net.SocketException for the
     * SO_OOBINLINE pair, and java/net/Socket.java:1141-1144 warn that there is "no capability to
     * distinguish between normal data and urgent data unless provided by a higher level protocol". A TCP
     * urgent byte would reach the peer's record parser as record bytes, so the SSL layer refuses the
     * option inside java.net.SocketException - java.net.SocketException is what the throws clauses name,
     * so the refusals stay inside the declared types instead of inventing an exception outside them.
     */
    @Test
    public void testTheLayeredSocketRefusesUrgentDataInTheJavadirExceptionClasses() throws Exception {
        BcPskTlsParams pskParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[0]);

        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(pskParams, new TlsPSKIdentity() {
            @Override
            public void skipIdentityHint() {}

            @Override
            public void notifyIdentityHint(byte[] psk_identity_hint) {}

            @Override
            public byte[] getPSKIdentity() { return "test".getBytes(); }

            @Override
            public byte[] getPSK() { return TesterSupport.testPskKey; }
        });

        try (ServerSocket serverSocket = new BcPskSSLServerSocketFactory(pskParams, TesterSupport.testIdentityMgr).createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            Socket rawSocket = new Socket("localhost", actualPort);
            SSLSocket layeredSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
            layeredSocket.startHandshake();

            Assertions.assertThrows(SocketException.class,
                    () -> layeredSocket.sendUrgentData(65),
                    "java/net/Socket.java:1126-1127's own class for an absent out-of-band channel");
            Assertions.assertThrows(SocketException.class,
                    () -> layeredSocket.setOOBInline(true),
                    "java/net/Socket.java:1157 declares java.net.SocketException, and a TCP urgent byte"
                            + " would reach the peer's record parser as record bytes");
            layeredSocket.setOOBInline(false);
            Assertions.assertFalse(layeredSocket.getOOBInline(),
                    "the option stays off, which is what java/net/Socket.java:1174 would report");

            layeredSocket.close();
            acceptedThread.join();
        }
    }

    /**
     * javadir java/net/Socket.java:1585-1592 and java/net/Socket.java:1615-1622 shut one half of a
     * java.net.Socket down once and then refuse a repeat with
     * java.net.SocketException("Socket input is already shutdown")/"Socket output is already shutdown"
     * (and java/net/Socket.java:1588/java/net/Socket.java:1618 refuse once the socket is closed). Those
     * refusals belong to the raw socket's own java.net.Socket streams, and it is the SSL layer, not the
     * raw socket, that owns this shutdown: the SSL layer keeps its own record of each half-close, so a
     * repeat - or a shutdown after close() - answers quietly instead of leaking javadir's raw guard as a
     * failure out of a layered socket, and isInputShutdown()/isOutputShutdown() report the shutdown
     * either way.
     */
    @Test
    public void testTheLayeredSocketShutsEachHalfDownOnce() throws Exception {
        BcPskTlsParams pskParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[0]);

        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(pskParams, new TlsPSKIdentity() {
            @Override
            public void skipIdentityHint() {}

            @Override
            public void notifyIdentityHint(byte[] psk_identity_hint) {}

            @Override
            public byte[] getPSKIdentity() { return "test".getBytes(); }

            @Override
            public byte[] getPSK() { return TesterSupport.testPskKey; }
        });

        try (ServerSocket serverSocket = new BcPskSSLServerSocketFactory(pskParams, TesterSupport.testIdentityMgr).createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            Socket rawSocket = new Socket("localhost", actualPort);
            SSLSocket layeredSocket = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
            layeredSocket.startHandshake();

            layeredSocket.shutdownOutput();
            layeredSocket.shutdownOutput();
            Assertions.assertTrue(layeredSocket.isOutputShutdown(),
                    "java/net/Socket.java:1615's half-close shows up in the predicate");

            layeredSocket.shutdownInput();
            layeredSocket.shutdownInput();
            Assertions.assertTrue(layeredSocket.isInputShutdown(),
                    "java/net/Socket.java:1585's end-of-stream shows up in the predicate");

            layeredSocket.close();
            layeredSocket.shutdownInput();
            layeredSocket.shutdownOutput();

            acceptedThread.join();
        }
    }

    /**
     * javax/net/ssl/SSLSocket.java:159-181's protocol table is the vocabulary javax/net/ssl/SSLSocket.java:1091
     * getSupportedProtocols(), javax/net/ssl/SSLSocket.java:1100 getEnabledProtocols() and
     * javax/net/ssl/SSLSocket.java:1123 setEnabledProtocols() speak, and javax/net/ssl/SSLSession.java:326-334
     * getProtocol() answers with one of those names. Only TLS 1.2 and TLS 1.3 are supported, so every one of
     * those surfaces reports javadir's own spellings, and javadir's older names are refused with the reason
     * instead of being mapped or silently ignored.
     */
    @Test
    public void testProtocolNamesAreJavadirsForTheSupportedVersions() throws Exception {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv13, ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[0]);

        Assertions.assertEquals("[TLSv1.3, TLSv1.2]", Arrays.toString(params.getSupportedProtocols()),
                "the factory must report javadir's protocol names from javax/net/ssl/SSLSocket.java:159-181");
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> BcPskTlsParams.fromJavaName("TLSv1"),
                "javadir's name for TLS 1.0 must be refused, not mapped");
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> BcPskTlsParams.fromJavaName("TLSv1.1"),
                "javadir's name for TLS 1.1 must be refused, not mapped");

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

        AtomicReference<String> serverProtocol = new AtomicReference<String>();

        try (ServerSocket serverSocket = new BcPskSSLServerSocketFactory(params, TesterSupport.testIdentityMgr).createServerSocket()) {
            serverSocket.bind(new InetSocketAddress(0));
            int actualPort = serverSocket.getLocalPort();

            Thread acceptedThread = new Thread(() -> {
                try (Socket socket = serverSocket.accept()) {
                    SSLSocket serverSide = (SSLSocket) socket;
                    serverSide.getInputStream();
                    serverProtocol.compareAndSet(null, serverSide.getSession().getProtocol());
                } catch (IOException e) {
                }
            });
            acceptedThread.start();

            Socket rawSocket = new Socket("localhost", actualPort);
            SSLSocket clientSide = (SSLSocket) clientFactory.createSocket(rawSocket, "localhost", actualPort, true);
            Assertions.assertEquals("[TLSv1.3, TLSv1.2]", Arrays.toString(clientSide.getSupportedProtocols()),
                    "the client socket must report javadir's protocol names");

            Assertions.assertThrows(IllegalArgumentException.class,
                    () -> clientSide.setEnabledProtocols(new String[] { "TLSv1" }),
                    "setEnabledProtocols() must not accept javadir's name for TLS 1.0");
            clientSide.setEnabledProtocols(new String[] { "TLSv1.2" });
            Assertions.assertEquals("TLSv1.2", clientSide.getEnabledProtocols()[0],
                    "the enabled set must keep javadir's spelling");

            clientSide.startHandshake();
            Assertions.assertEquals("TLSv1.2", clientSide.getSession().getProtocol(),
                    "javax/net/ssl/SSLSession.java:334 must name the negotiated version with javadir's spelling");

            acceptedThread.join();
            Assertions.assertEquals("TLSv1.2", serverProtocol.get(),
                    "the accepted socket's session must name the same negotiation with javadir's spelling");

            clientSide.close();
        }
    }

    /**
     * SSLv3, TLS 1.0 and TLS 1.1 are refused at construction: their CBC + HMAC record path carries the
     * BEAST/BREACH/RFC 44782 attacks this library cannot switch off, so no socket built from these params can
     * ever negotiate them - javadir's javax/net/ssl/SSLSocket.java:159-181 table lists them, but that table
     * describes javadir, not this library. A DTLS version is refused the same way: it has no
     * javax/net/ssl/SSLSocket.java name.
     */
    @Test
    public void testUnsafeProtocolVersionsAreRefusedAtConstruction() throws Exception {
        int[] pskSuite = new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA };

        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv10 }, pskSuite, 0, new String[0]);
        },
                "TLS 1.0 must not be configurable through the factory");
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv11 }, pskSuite, 0, new String[0]);
        },
                "TLS 1.1 must not be configurable through the factory");
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.SSLv3 }, pskSuite, 0, new String[0]);
        },
                "SSLv3 must not be configurable through the factory");
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.DTLSv12 }, pskSuite, 0, new String[0]);
        },
                "a DTLS version must not be configurable through the factory");
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> new BcPskTlsParams().withSupportedProtocolVersions(new ProtocolVersion[] { ProtocolVersion.TLSv11 }),
                "the named setter must refuse an unsafe version too");
    }

}
