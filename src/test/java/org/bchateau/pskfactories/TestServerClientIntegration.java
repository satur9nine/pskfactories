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
import org.bouncycastle.tls.CipherSuite;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

// Test the factories by integrating then into small/popular client/server libraries
public class TestServerClientIntegration {

    /**
     * Test secret key, real implementations should not hardcode keys in source code like this!
     */
    private static final byte[] testPskKey = new byte[] {
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
    };

    private static final String TEST_IDENTITY_KEY = "test";

    private static final TlsPSKIdentityManager testIdentityMgr = new TlsPSKIdentityManager() {
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

    private static final BcPskTlsParams defaultParams = new BcPskTlsParams();

    private static final BcPskTlsParams tls12Params = new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv12 },
            new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 });

    private static final BcPskTlsParams tls13Params = new BcPskTlsParams(new ProtocolVersion[] { ProtocolVersion.TLSv13 },
            new int[] { CipherSuite.TLS_AES_128_GCM_SHA256 });

    interface HttpServerFinisher {
        void stop();
    }

    private static BasicTlsPSKIdentity createBasicTlsPSKIdentity() {
        // NOTE: BasicTlsPSKIdentity is mutable and should not be re-used
        return new BasicTlsPSKIdentity("test", testPskKey);
    }

    private static void runPskClient(int port, BcPskTlsParams params, BasicTlsPSKIdentity identity) throws IOException {
        TesterSupport.log("Running OkHttp Client backed by BC");

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
                TesterSupport.log("Making a GET request");
                call = client.newCall(new Request.Builder().
                        url("https://localhost:" + port).build());

            } else {
                TesterSupport.log("Making a PUT request");
                call = client.newCall(new Request.Builder()
                        .method("PUT", RequestBody.create(MediaType.get("text/plain"), "Hi"))
                        .url("https://localhost:" + port).build());
            }

            try (Response resp = call.execute()) {
                TesterSupport.log("Got: " + resp.code());
                if (resp.code() != 429) {
                    throw new AssertionError("Unexpected HTTP response code: " + resp.code());
                }
            }
        }
    }

    private static int startPskServer(BcPskTlsParams params, TlsPSKIdentityManager identityMgr, AtomicReference<HttpServerFinisher> finisherRef)
            throws IOException {
        NanoHTTPD nano = new NanoHTTPD(0) {
            @Override
            protected ServerRunnable createServerRunnable(final int timeout) {
                return new ServerRunnable(timeout) {
                    @Override
                    public void run() {
                        TesterSupport.log("ServerRunnable starting");
                        super.run();
                        TesterSupport.log("ServerRunnable stopped");
                    }
                };
            }

            @Override
            protected ClientHandler createClientHandler(final Socket finalAccept, final InputStream inputStream) {
                TesterSupport.log("Creating ClientHandler");
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

        finisherRef.set(nano::stop);

        TesterSupport.log("Starting Nano HTTP server backed by BC");
        nano.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);

        return nano.getListeningPort();
    }

    @Test
    public void testServerTlsDefaultClientTlsDefaultConnect() throws Exception {
        AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
        try {
            int port = startPskServer(defaultParams, testIdentityMgr, server);
            runPskClient(port, defaultParams, createBasicTlsPSKIdentity());
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
            int port = startPskServer(tls12Params, testIdentityMgr, server);
            runPskClient(port, defaultParams, createBasicTlsPSKIdentity());
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
            int port = startPskServer(defaultParams, testIdentityMgr, server);
            runPskClient(port, tls12Params, createBasicTlsPSKIdentity());
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
            int port = startPskServer(defaultParams, testIdentityMgr, server);
            runPskClient(port, tls13Params, createBasicTlsPSKIdentity());
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
            int port = startPskServer(tls13Params, testIdentityMgr, server);
            runPskClient(port, defaultParams, createBasicTlsPSKIdentity());
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
                int port = startPskServer(tls13Params, testIdentityMgr, server);
                runPskClient(port, tls12Params, createBasicTlsPSKIdentity());
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
                int port = startPskServer(tls12Params, testIdentityMgr, server);
                runPskClient(port, tls13Params, createBasicTlsPSKIdentity());
            } finally {
                if (server.get() != null) {
                    server.get().stop();
                }
            }
        });
    }

    @Test
    public void testServerClientKeyMismatch() {
        Assertions.assertThrows(IOException.class, () -> {
            final byte[] testPskKey2 = new byte[] {
                    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
                    0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
            };

            final BasicTlsPSKIdentity testIdentity2 = new BasicTlsPSKIdentity("test", testPskKey2);

            AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
            try {
                int port = startPskServer(defaultParams, testIdentityMgr, server);
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
        Assertions.assertThrows(IOException.class, () -> {
            final BasicTlsPSKIdentity testIdentity2 = new BasicTlsPSKIdentity("other", testPskKey);

            AtomicReference<HttpServerFinisher> server = new AtomicReference<>();
            try {
                int port = startPskServer(defaultParams, testIdentityMgr, server);
                runPskClient(port, defaultParams, testIdentity2);
            } finally {
                if (server.get() != null) {
                    server.get().stop();
                }
            }
        });
    }

}
