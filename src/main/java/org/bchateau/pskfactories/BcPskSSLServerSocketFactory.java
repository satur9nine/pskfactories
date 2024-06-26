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

    private static final boolean DEBUG = false;

    private final BcPskTlsParams params;
    private final TlsCrypto crypto;
    private final TlsPSKIdentityManager pskIdentityMgr;

    public BcPskSSLServerSocketFactory(BcPskTlsParams params, TlsPSKIdentityManager pskIdentityMgr) {
        this.params = params;
        this.crypto = new BcTlsCrypto(new SecureRandom());
        this.pskIdentityMgr = pskIdentityMgr;
    }

    private static class BcPskTlsServerProtocol extends TlsServerProtocol {

        public BcPskTlsServerProtocol(InputStream input, OutputStream output) {
            super(input, output);
        }

        @Override
        protected void raiseAlertFatal(short alertDescription, String message, Throwable cause) throws IOException {
            cause.printStackTrace();
        }

        @Override
        protected void raiseAlertWarning(short alertDescription, String message) throws IOException {
            if (DEBUG) {
                System.out.println(message);
            }
        }
    }

    @Override
    public ServerSocket createServerSocket() throws IOException {
        TlsServer tlsServer = new PSKTlsServer(crypto, pskIdentityMgr) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return params.getSupportedProtocolVersions();
            }

            @Override
            protected int[] getSupportedCipherSuites() {
                return params.getSupportedCipherSuiteCodes();
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
        return createSSLServerSocket(tlsServer);
    }

    /**
     * Not supported.
     */
    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        throw new UnsupportedOperationException();
    }

    /**
     * Not supported.
     */
    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        throw new UnsupportedOperationException();
    }

    /**
     * Not supported.
     */
    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        throw new UnsupportedOperationException();
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
        return new SSLServerSocket() {
            private TlsServerProtocol tlsServerProtocol;
            private String[] enabledCipherSuites = params.getSupportedCipherSuites();
            private String[] enabledProtocols = params.getSupportedProtocols();
            private boolean enableSessionCreation = true;

            @Override
            public void close() throws IOException {
                TlsServerProtocol tsp = tlsServerProtocol;
                if (tsp != null && !tsp.isClosed()) {
                    tsp.close();
                }
                super.close();
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

            @Override
            public Socket accept() throws IOException {
                Socket insecureSocket = super.accept();
                tlsServerProtocol = new BcPskTlsServerProtocol(insecureSocket.getInputStream(), insecureSocket.getOutputStream());
                tlsServerProtocol.accept(tlsServer);
                return new WrappedSocket(insecureSocket, tlsServerProtocol.getInputStream(), tlsServerProtocol.getOutputStream());
            }
        };
    }
}