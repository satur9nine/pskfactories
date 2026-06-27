package org.bchateau.pskfactories;

import fi.iki.elonen.NanoHTTPD;
import okhttp3.Call;
import okhttp3.ConnectionSpec;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.net.Socket;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

// Test the factories by integrating then into small/popular client/server libraries
public class TestServerClientIntegration {

    /**
     * Test secret key, real implementations should not hardcode keys in source code like this!
     */
    final byte[] testPskKey = new byte[] {
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
    };

    final String TEST_IDENTITY_KEY = "test";

    final BasicTlsPSKIdentity testIdentity = new BasicTlsPSKIdentity("test", testPskKey);

    final TlsPSKIdentityManager testIdentityMgr = new TlsPSKIdentityManager() {
        @Override
        public byte[] getHint() {
            // If multiple keys are supported this could signal which key to use
            return new byte[0];
        }

        @Override
        public byte[] getPSK(byte[] identity) {
            if (Arrays.equals(TEST_IDENTITY_KEY.getBytes(), identity)) {
                return testPskKey;
            } else {
                throw new IllegalArgumentException("Unrecognized identity rejected");
            }
        }
    };

    final BcPskTlsParams defaultParams = new BcPskTlsParams();

    final BcPskTlsParams tls12Params = new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv12 },
            new int[] { org.bouncycastle.tls.CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 });

    final BcPskTlsParams tls13Params = new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv13 },
            new int[] { org.bouncycastle.tls.CipherSuite.TLS_AES_128_GCM_SHA256 });

    interface HttpServerFinisher {
        void stop();
    }

    private static void runPskClient(int port, BcPskTlsParams params, BasicTlsPSKIdentity identity) throws IOException {
        log("Running OkHttp Client backed by BC");

        OkHttpClient client = new OkHttpClient.Builder()
                .callTimeout(3, TimeUnit.SECONDS)
                // Empty trust manager is required, null is not allowed
                .sslSocketFactory(new BcPskSSLSocketFactory(params, identity), new BcPskSSLSocketFactory.EmptyX509TrustManager())
                .hostnameVerifier((hostname, session) -> true)
                .connectionSpecs(Collections.singletonList(new ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
                        // Must specify the CipherSuite, ConnectionSpec.RESTRICTED_TLS doesn't support PSK
                        .cipherSuites(params.getSupportedCipherSuites())
                        .tlsVersions(params.getSupportedProtocols())
                        .build()))
                .addInterceptor(new SSLHandshakeInterceptor())
                .build();

        Call call;
        for (int i = 0; i < 6; i++) {
            if (i % 2 == 0) {
                log("Making a GET request");
                call = client.newCall(new Request.Builder().
                        url("https://localhost:" + port).build());

            } else {
                log("Making a PUT request");
                call = client.newCall(new Request.Builder()
                        .method("PUT", RequestBody.create(MediaType.get("text/plain"), "Hi"))
                        .url("https://localhost:" + port).build());
            }

            try (Response resp = call.execute()) {
                log("Got: " + resp.code());
                if (resp.code() != 429) {
                    throw new AssertionError("Unexpected HTTP response code: " + resp.code());
                }
            }
        }
    }

    private static int startPskServer(int port, BcPskTlsParams params, TlsPSKIdentityManager identityMgr, AtomicReference<HttpServerFinisher> finisherRef)
            throws IOException {
        NanoHTTPD nano = new NanoHTTPD(port) {
            @Override
            protected ServerRunnable createServerRunnable(final int timeout) {
                return new ServerRunnable(timeout) {
                    @Override
                    public void run() {
                        log("ServerRunnable starting");
                        super.run();
                        log("ServerRunnable stopped");
                    }
                };
            }

            @Override
            protected ClientHandler createClientHandler(final Socket finalAccept, final java.io.InputStream inputStream) {
                log("Creating ClientHandler");
                return super.createClientHandler(finalAccept, inputStream);
            }

            @Override
            public Response serve(IHTTPSession session) {
                Map<String, String> parameters = new HashMap<>();
                try {
                    // Must consume the body
                    session.parseBody(parameters);
                } catch (IOException e) {
                    return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_PLAINTEXT,
                            "SERVER INTERNAL ERROR: IOException: " + e.getMessage());
                } catch (ResponseException e) {
                    return newFixedLengthResponse(e.getStatus(), NanoHTTPD.MIME_PLAINTEXT, e.getMessage());
                }
                return newFixedLengthResponse(Response.Status.TOO_MANY_REQUESTS, NanoHTTPD.MIME_PLAINTEXT,
                        "Too much");
            }
        };

        // Setting sslProtocols param to null tells NanoHTTPD to allow all protocols supported by the factory
        nano.makeSecure(new BcPskSSLServerSocketFactory(params, identityMgr), null);

        log("Starting Nano HTTP server backed by BC");
        nano.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);

        int boundPort = (port == 0) ? nano.getListeningPort() : port;
        finisherRef.set(nano::stop);
        return boundPort;
    }

    public static void log(String s) {
        RuntimeMXBean rb = ManagementFactory.getRuntimeMXBean();
        System.out.println(String.format(Locale.US, "%08d", rb.getUptime()) + ": " + s +
                " (" + Thread.currentThread() + ")");
    }

    @Test
    public void testServerTlsDefaultClientTlsDefaultConnect() throws Exception {
        AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
        try {
            int port = startPskServer(0, defaultParams, testIdentityMgr, server);
            runPskClient(port, defaultParams, testIdentity);
        } finally {
            if (server.get() != null) {
                server.get().stop();
            }
        }
    }

    @Test
    public void testServerTls12ClientTlsDefaultConnect() throws Exception {
        AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
        try {
            int port = startPskServer(0, tls12Params, testIdentityMgr, server);
            runPskClient(port, defaultParams, testIdentity);
        } finally {
            if (server.get() != null) {
                server.get().stop();
            }
        }
    }

    @Test
    public void testServerTlsDefaultClientTls12Connect() throws Exception {
        AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
        try {
            int port = startPskServer(0, defaultParams, testIdentityMgr, server);
            runPskClient(port, tls12Params, testIdentity);
        } finally {
            if (server.get() != null) {
                server.get().stop();
            }
        }
    }

    @Test
    public void testServerTlsDefaultClientTls13Connect() throws Exception {
        AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
        try {
            int port = startPskServer(0, defaultParams, testIdentityMgr, server);
            runPskClient(port, tls13Params, testIdentity);
        } finally {
            if (server.get() != null) {
                server.get().stop();
            }
        }
    }

    @Test
    public void testServerTls13ClientTlsDefaultConnect() throws Exception {
        AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
        try {
            int port = startPskServer(0, tls13Params, testIdentityMgr, server);
            runPskClient(port, defaultParams, testIdentity);
        } finally {
            if (server.get() != null) {
                server.get().stop();
            }
        }
    }

    @Test
    public void testServerTls13ClientTls12Reject() {
        // Incompatible versions
        Assertions.assertThrows(IOException.class, () -> {
            AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
            try {
                int port = startPskServer(0, tls13Params, testIdentityMgr, server);
                runPskClient(port, tls12Params, testIdentity);
            } finally {
                if (server.get() != null) {
                    server.get().stop();
                }
            }
        });
    }

    @Test
    public void testServerTls12ClientTls13Reject() {
        // Incompatible versions
        Assertions.assertThrows(IOException.class, () -> {
            AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
            try {
                int port = startPskServer(0, tls12Params, testIdentityMgr, server);
                runPskClient(port, tls13Params, testIdentity);
            } finally {
                if (server.get() != null) {
                    server.get().stop();
                }
            }
        });
    }

    @Test
    public void testServerClientKeyMismatch() {
        // These tests trigger TLS handshake failures. If the server factory is not implemented
        // with lazy handshaking and correct isClosed() delegation, these tests can trigger
        // an infinite loop in the server (e.g. NanoHTTPD), pinning the CPU and causing OOM.
        Assertions.assertThrows(IOException.class, () -> {
            final byte[] testPskKey2 = new byte[] {
                    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
            };

            final BasicTlsPSKIdentity testIdentity2 = new BasicTlsPSKIdentity("test", testPskKey2);

            AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
            try {
                int port = startPskServer(0, defaultParams, testIdentityMgr, server);
                runPskClient(port, defaultParams, testIdentity2);
            } finally {
                if (server.get() != null) {
                    server.get().stop();
                }
            }
        });
    }

    @Test
    public void testServerClientIdentityMismatch() {
        // These tests trigger TLS handshake failures. If the server factory is not implemented
        // with lazy handshaking and correct isClosed() delegation, these tests can trigger
        // an infinite loop in the server (e.g. NanoHTTPD), pinning the CPU and causing OOM.
        Assertions.assertThrows(IOException.class, () -> {
            final BasicTlsPSKIdentity testIdentity2 = new BasicTlsPSKIdentity("other", testPskKey);

            AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
            try {
                int port = startPskServer(0, defaultParams, testIdentityMgr, server);
                runPskClient(port, defaultParams, testIdentity2);
            } finally {
                if (server.get() != null) {
                    server.get().stop();
                }
            }
        });
    }

}
