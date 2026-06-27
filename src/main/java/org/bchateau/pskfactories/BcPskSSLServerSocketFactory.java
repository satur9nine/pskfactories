/*
 * Copyright (C) 2024 Clover Network, Inc.
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import org.bouncycastle.tls.BasicTlsPSKExternal;
import org.bouncycastle.tls.PSKTlsServer;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.PskIdentity;
import org.bouncycastle.tls.TlsPSKExternal;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;


/**
 * This SSLServerSocketFactory provides TLS pre-shared key (PSK) cipher suites via Bouncy Castle.
 */
public class BcPskSSLServerSocketFactory extends SSLServerSocketFactory {

    /**
     * Log all warnings.
     */
    public static boolean logWarnings = false;

    /**
     * Old versions of this class did not throw on fatal alerts, set this to false to restore that behavior.
     */
    public static boolean throwIOExceptionOnFatalAlert = true;

    private final BcPskTlsParams params;
    private final TlsCrypto crypto;
    private final TlsPSKIdentityManager pskIdentityMgr;

    public BcPskSSLServerSocketFactory(BcPskTlsParams params, TlsPSKIdentityManager pskIdentityMgr) {
        System.out.println("BcPskSSLServerSocketFactory constructor called");
        this.params = params;
        this.crypto = new BcTlsCrypto(new SecureRandom());
        this.pskIdentityMgr = pskIdentityMgr;
    }

    static class BcPskTlsServerProtocol extends TlsServerProtocol {

        public BcPskTlsServerProtocol(InputStream input, OutputStream output) {
            super(input, output);
        }

        @Override
        protected void raiseAlertFatal(short alertDescription, String message, Throwable cause) throws IOException {
            if (throwIOExceptionOnFatalAlert) {
                throw new IOException(message, cause);
            }

            // Legacy behavior
            System.err.println("Fatal alert: " + message);
            if (cause != null) {
                cause.printStackTrace();
            }
        }

        @Override
        protected void raiseAlertWarning(short alertDescription, String message) throws IOException {
            if (logWarnings) {
                System.out.println(message);
            }
        }
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return createServerSocket(port, 50);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        TlsServer tlsServer = createTlsServer();
        return createSSLServerSocket(tlsServer, port, backlog);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        TlsServer tlsServer = createTlsServer();
        return createSSLServerSocket(tlsServer, port, backlog, ifAddress);
    }

    private TlsServer createTlsServer() {
        return new PSKTlsServer(crypto, pskIdentityMgr) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return params.getSupportedProtocolVersions();
            }

            @Override
            protected int[] getSupportedCipherSuites() {
                return params.getSupportedCipherSuiteCodes();
            }

            @Override
            protected Vector getProtocolNames() {
                String[] protocols = params.getApplicationProtocols();
                if (protocols.length == 0) return null;
                Vector v = new Vector();
                for (String p : protocols) {
                    v.add(org.bouncycastle.tls.ProtocolName.asUtf8Encoding(p));
                }
                return v;
            }

            @Override
            public TlsPSKExternal getExternalPSK(Vector identities) {
                if (identities == null || identities.isEmpty()) {
                    return null;
                }

                for (Object identity : identities) {
                    PskIdentity clientIdentity = (PskIdentity) identity;

                    byte[] selectedPsk = pskIdentityMgr.getPSK(clientIdentity.getIdentity());
                    if (selectedPsk != null) {
                        TlsSecret secret = crypto.createSecret(selectedPsk);
                        return new BasicTlsPSKExternal(clientIdentity.getIdentity(), secret);
                    }
                }

                // No matching identity found
                return null;
            }
        };
    }

    @Override
    public ServerSocket createServerSocket() throws IOException {
        TlsServer tlsServer = createTlsServer();
        return createSSLServerSocket(tlsServer, -1);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return params.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return params.getSupportedCipherSuites();
    }

    private SSLServerSocket createSSLServerSocket(final TlsServer tlsServer) throws IOException {
        return createSSLServerSocket(tlsServer, 0);
    }

    private SSLServerSocket createSSLServerSocket(final TlsServer tlsServer, int port) throws IOException {
        return createSSLServerSocket(tlsServer, port, 50);
    }

    private SSLServerSocket createSSLServerSocket(final TlsServer tlsServer, int port, int backlog) throws IOException {
        return createSSLServerSocket(tlsServer, port, backlog, null);
    }

    private SSLServerSocket createSSLServerSocket(final TlsServer tlsServer, int port, int backlog, InetAddress ifAddress) throws IOException {
        final ServerSocket delegate = new ServerSocket();
        delegate.setReuseAddress(true);
        if (port >= 0 || ifAddress != null) {
            delegate.bind(ifAddress == null ? new java.net.InetSocketAddress(port) : new java.net.InetSocketAddress(ifAddress, port));
        }

        final SSLServerSocket serverSocket = new SSLServerSocket() {
            private String[] enabledCipherSuites = params.getSupportedCipherSuites();
            private String[] enabledProtocols = params.getSupportedProtocols();
            private boolean enableSessionCreation = true;

            @Override
            public void bind(java.net.SocketAddress bindpoint) throws IOException {
                System.out.println("Server: binding to " + bindpoint);
                delegate.bind(bindpoint);
            }

            @Override
            public boolean isBound() {
                return delegate.isBound();
            }

            @Override
            public Socket accept() throws IOException {
                System.out.println("Server: waiting for accept...");
                try {
                    Socket insecureSocket = delegate.accept();
                    System.out.println("Server: accepted connection from " + insecureSocket.getRemoteSocketAddress());
                    // We return a WrappedSocket here instead of performing the TLS handshake synchronously.
                    // This is critical for integration with servers like NanoHTTPD: if the handshake
                    // fails (e.g. identity mismatch), throwing an IOException here causes the
                    // server listener loop to retry accept() immediately in a tight loop.
                    return new WrappedSocket(insecureSocket, tlsServer, crypto);
                } catch (IOException e) {
                    System.err.println("Server: accept failed: " + e.getMessage());
                    throw e;
                }
            }

            @Override
            public boolean isClosed() {
                // Critical: must delegate isClosed() to the underlying socket.
                // If this returns false after delegate.close() is called, some server
                // loops (like NanoHTTPD) will keep calling accept(), which will
                // immediately throw "Socket is closed", resulting in an infinite loop
                // that consumes 100% CPU and leads to OutOfMemoryError.
                return delegate.isClosed();
            }

            @Override
            public void close() throws IOException {
                delegate.close();
            }

            @Override
            public InetAddress getInetAddress() {
                return delegate.getInetAddress();
            }

            @Override
            public int getLocalPort() {
                return delegate.getLocalPort();
            }

            @Override
            public SocketAddress getLocalSocketAddress() {
                return delegate.getLocalSocketAddress();
            }

            @Override
            public void setSoTimeout(int timeout) throws SocketException {
                delegate.setSoTimeout(timeout);
            }

            @Override
            public int getSoTimeout() throws IOException {
                return delegate.getSoTimeout();
            }

            @Override
            public void setReuseAddress(boolean on) throws SocketException {
                delegate.setReuseAddress(on);
            }

            @Override
            public boolean getReuseAddress() throws SocketException {
                return delegate.getReuseAddress();
            }

            @Override
            public boolean getEnableSessionCreation() {
                return enableSessionCreation;
            }

            @Override
            public String[] getEnabledCipherSuites() {
                return enabledCipherSuites.clone();
            }

            @Override
            public String[] getEnabledProtocols() {
                return enabledProtocols.clone();
            }

            @Override
            public boolean getNeedClientAuth() {
                return false;
            }

            @Override
            public String[] getSupportedProtocols() {
                return params.getSupportedProtocols();
            }

            @Override
            public boolean getUseClientMode() {
                return false;
            }

            @Override
            public boolean getWantClientAuth() {
                return false;
            }

            @Override
            public void setEnabledCipherSuites(String[] suites) {
                Set<String> supported = new HashSet<>();
                Collections.addAll(supported, getSupportedCipherSuites());

                List<String> enabled = new ArrayList<>();
                for (String s : suites) {
                    if (supported.contains(s)) {
                        enabled.add(s);
                    }
                }
                enabledCipherSuites = enabled.toArray(new String[0]);
            }

            @Override
            public void setEnableSessionCreation(boolean flag) {
                enableSessionCreation = flag;
            }

            @Override
            public void setEnabledProtocols(String[] protocols) {
                Set<String> supported = new HashSet<>();
                Collections.addAll(supported, getSupportedProtocols());

                List<String> enabled = new ArrayList<>();
                for (String s : protocols) {
                    if (supported.contains(s)) {
                        enabled.add(s);
                    }
                }
                enabledProtocols = enabled.toArray(new String[0]);
            }

            @Override
            public void setNeedClientAuth(boolean need) {
                // Ignored, PSK ensures mutual auth
            }

            @Override
            public void setUseClientMode(boolean mode) {
                // Ignored, PSK ensures mutual auth
            }

            @Override
            public void setWantClientAuth(boolean want) {
                // Ignored, PSK ensures mutual auth
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return params.getSupportedCipherSuites();
            }
        };

        return serverSocket;
    }
}
