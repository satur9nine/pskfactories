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
import java.net.SocketOption;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;
import java.util.Vector;

import javax.net.ssl.SSLParameters;
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
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.TlsPeer;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;


/**
 * This SSLServerSocketFactory provides TLS pre-shared key (PSK) cipher suites via Bouncy Castle.
 */
public class BcPskSSLServerSocketFactory extends SSLServerSocketFactory {

    /**
     * Echo warning-level alerts to stdout as they are raised. The alert is sent on the wire
     * either way; this flag only decides whether the caller sees it.
     */
    public boolean logWarnings = false;

    /**
     * Old versions of this class did not throw on fatal alerts, set this to false to restore that behavior.
     * That mode reports a failed handshake as a successful one, so it is legacy-only; leave it true unless
     * matching an old caller.
     */
    public boolean throwIOExceptionOnFatalAlert = true;

    // Backlog of connections queued on the delegate ServerSocket; same default as
    // sun.security.ssl.SSLServerSocketFactoryImpl's.
    private static final int DEFAULT_BACKLOG = 50;

    private final BcPskTlsParams params;
    private final TlsCrypto crypto;
    private final TlsPSKIdentityManager pskIdentityMgr;

    public BcPskSSLServerSocketFactory(BcPskTlsParams params, TlsPSKIdentityManager pskIdentityMgr) {
        this.params = params;
        this.crypto = new BcTlsCrypto(new SecureRandom());
        this.pskIdentityMgr = pskIdentityMgr;
    }


    /**
     * The negotiation policy this factory was built with: BcPskSSLEngine reads the ALPN
     * names it offers and the session-validity window from it.
     */
    protected BcPskTlsParams getConfiguration() {
        return params;
    }
    /**
     * Bouncy Castle zeroes the pre-shared key buffer it is handed (TlsPSKKeyExchange.generatePreMasterSecret
     * does Arrays.fill(psk, 0)), so a manager whose getPSK() returns a caller-owned array is destroyed by the
     * first handshake that uses it. This wrapper hands out a fresh copy on each read instead.
     */
    private static TlsPSKIdentityManager copyOnRead(final TlsPSKIdentityManager manager) {
        return new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() {
                return manager.getHint();
            }

            @Override
            public byte[] getPSK(byte[] identity) {
                return copy(manager.getPSK(identity));
            }
        };
    }

    private static byte[] copy(final byte[] value) {
        return value == null ? null : Arrays.copyOf(value, value.length);
    }

    /**
     * Builds this factory's alert-policy server protocol over the given streams.
     */
    BcPskTlsServerProtocol createProtocol(InputStream input, OutputStream output) {
        return new BcPskTlsServerProtocol(input, output, this);
    }

    /**
     * Builds this factory's alert-policy server protocol in org.bouncycastle.tls.TlsProtocol's
     * non-blocking (queue) mode, for javax.net.ssl.SSLEngine callers that feed the record
     * layer through offerInput()/readOutput() rather than streams.
     */
    BcPskTlsServerProtocol createProtocol() {
        return new BcPskTlsServerProtocol(this);
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {
        return createServerSocket(port, DEFAULT_BACKLOG);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException {
        return createSSLServerSocket(port, backlog, null);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        return createSSLServerSocket(port, backlog, ifAddress);
    }

    /**
     * Builds the Bouncy Castle server for one accepted connection. The handshake is driven by the
     * socket's enabled cipher suites and protocols rather than everything the factory supports, so
     * setEnabledCipherSuites()/setEnabledProtocols() actually constrain negotiation. One server per
     * accepted socket also keeps AbstractTlsServer's per-handshake state (ALPN names, selected
     * protocol) off objects shared between concurrent handshakes. The ALPN names offered to the peer
     * come in as an argument so a socket carrying a handshake application-protocol selector can
     * narrow them; an empty list offers none.
     */
    protected TlsServer createTlsServer(final String[] enabledCipherSuites, final String[] enabledProtocols,
                                        final String[] applicationProtocols) {
        return new PSKTlsServer(crypto, copyOnRead(pskIdentityMgr)) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return BcPskTlsParams.sortHighestFirst(BcPskTlsParams.fromSupportedProtocolVersions(enabledProtocols));
            }

            @Override
            protected int[] getSupportedCipherSuites() {
                return BcPskTlsParams.fromSupportedCipherSuiteCodes(enabledCipherSuites);
            }

            @Override
            protected Vector getProtocolNames() {
                String[] protocols = applicationProtocols;
                if (protocols.length == 0) return null;
                Vector v = new Vector();
                for (String p : protocols) {
                    v.add(ProtocolName.asUtf8Encoding(p));
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

                // None of the peer's identities names a key this manager holds. Refusing here is
                // deliberate: PSK suites cannot prove either peer without a shared secret.
                return null;
            }
        };
    }

    @Override
    public ServerSocket createServerSocket() throws IOException {
        return createSSLServerSocket(null, DEFAULT_BACKLOG, null);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return params.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return params.getSupportedCipherSuites();
    }

    private SSLServerSocket createSSLServerSocket(Integer port, int backlog,
                                                  InetAddress ifAddress) throws IOException {
        final BcPskSSLServerSocketFactory factory = this;
        final ServerSocket delegate = new ServerSocket();
        delegate.setReuseAddress(true);
        if (port != null) {
            SocketAddress endpoint = (ifAddress == null)
                    ? new InetSocketAddress(port)
                    : new InetSocketAddress(ifAddress, port);
            delegate.bind(endpoint, backlog);
        }

        final SSLServerSocket serverSocket = new SSLServerSocket() {
            private String[] enabledCipherSuites = params.getSupportedCipherSuites();
            private String[] enabledProtocols = params.getSupportedProtocols();
            private boolean enableSessionCreation = true;

            @Override
            public void bind(SocketAddress bindpoint) throws IOException {
                delegate.bind(bindpoint);
            }

            @Override
            public boolean isBound() {
                return delegate.isBound();
            }

            @Override
            public Socket accept() throws IOException {
                Socket insecureSocket = delegate.accept();
                // The accepted socket inherits this server socket's enabled sets; the TLS server is
                // built from them when the handshake starts, so setEnabled* here or on the accepted
                // socket both constrain negotiation.
                return new WrappedSocket(insecureSocket, factory, params, enabledCipherSuites, enabledProtocols);
            }

            @Override
            public boolean isClosed() {
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
            public void bind(SocketAddress endpoint, int backlog) throws IOException {
                delegate.bind(endpoint, backlog);
            }

            @Override
            public ServerSocketChannel getChannel() {
                return delegate.getChannel();
            }

            @Override
            public String toString() {
                if (!delegate.isBound()) {
                    return "ServerSocket[unbound]";
                }
                return "ServerSocket[addr=" + delegate.getInetAddress() +
                        ",localport=" + delegate.getLocalPort() + "]";
            }

            @Override
            public void setReceiveBufferSize(int size) throws SocketException {
                delegate.setReceiveBufferSize(size);
            }

            @Override
            public int getReceiveBufferSize() throws SocketException {
                return delegate.getReceiveBufferSize();
            }

            @Override
            public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
                delegate.setPerformancePreferences(connectionTime, latency, bandwidth);
            }

            @Override
            public <T> ServerSocket setOption(SocketOption<T> name, T value) throws IOException {
                return delegate.setOption(name, value);
            }

            @Override
            public <T> T getOption(SocketOption<T> name) throws IOException {
                return delegate.getOption(name);
            }

            @Override
            public Set<SocketOption<?>> supportedOptions() {
                return delegate.supportedOptions();
            }

            @Override
            public void setSSLParameters(SSLParameters sslParameters) {
                if (sslParameters == null) {
                    throw new IllegalArgumentException("'sslParameters' cannot be null");
                }

                String[] cipherSuites = sslParameters.getCipherSuites();
                if (cipherSuites != null) {
                    setEnabledCipherSuites(cipherSuites);
                }

                String[] protocols = sslParameters.getProtocols();
                if (protocols != null) {
                    setEnabledProtocols(protocols);
                }
            }

            // The handshake reads this socket's enabled sets and ALPN names; it picks its own suite
            // order when it answers a client's offer, so the order flag is set here.
            @Override
            public SSLParameters getSSLParameters() {
                return BcPskTlsParams.fromEnabledState(getEnabledCipherSuites(), getEnabledProtocols(),
                        params.getApplicationProtocols(), true);
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
                // Same contract as the accepted socket: unknown names are rejected, not dropped
                enabledCipherSuites = BcPskTlsParams.requireSupported(suites, getSupportedCipherSuites(), "cipher suite");
            }

            @Override
            public void setEnableSessionCreation(boolean flag) {
                enableSessionCreation = flag;
            }

            @Override
            public void setEnabledProtocols(String[] protocols) {
                enabledProtocols = BcPskTlsParams.requireSupported(protocols, getSupportedProtocols(), "protocol");
            }

            @Override
            public void setNeedClientAuth(boolean need) {
                // PSK suites prove both peers hold the shared secret, so client authentication
                // has nothing to configure.
            }

            @Override
            public void setUseClientMode(boolean mode) {
                // PSK suites prove both peers hold the shared secret, so client/server mode
                // has nothing to configure.
            }

            @Override
            public void setWantClientAuth(boolean want) {
                // PSK suites prove both peers hold the shared secret, so client authentication
                // has nothing to configure.
            }

            @Override
            public String[] getSupportedCipherSuites() {
                return params.getSupportedCipherSuites();
            }
        };

        return serverSocket;
    }
}

/**
 * This factory's org.bouncycastle.tls.TlsServerProtocol with the alert policy the socket classes
 * used to inline, plus the negotiated-session accessors BcPskSSLEngine needs. Package level,
 * not nested in the factory, so BcPskSSLEngine can name the type.
 */
class BcPskTlsServerProtocol extends TlsServerProtocol {
    private final BcPskSSLServerSocketFactory factory;

    // Streams-backed: BC's blocking record layer sits directly on the accepted socket's
    // streams (org/bouncycastle/tls/TlsProtocol.java:182 picks blocking mode from the ctor shape).
    public BcPskTlsServerProtocol(InputStream input, OutputStream output,
                                                BcPskSSLServerSocketFactory factory) {
        super(input, output);
        this.factory = factory;
    }

    // No streams: org/bouncycastle/tls/TlsProtocol.java:174, the queue-backed non-blocking variant
    // javax.net.ssl.SSLEngine callers drive with offerInput()/readOutput().
    public BcPskTlsServerProtocol(BcPskSSLServerSocketFactory factory) {
        super();
        this.factory = factory;
    }

    // javax/net/ssl/SSLEngine.java#closeOutbound(): closes only the outbound
    // half and queues its close_notify alert, so BcPskSSLEngine asks for the alert alone instead
    // of Bouncy Castle's TlsProtocol#close(), which closes both halves at once.
    public void raiseCloseNotifyAlert() throws IOException {
        raiseAlertWarning(AlertDescription.close_notify,
                "Connection closed by javax.net.ssl.SSLEngine#closeOutbound()");
    }

    @Override
    protected void raiseAlertFatal(short alertDescription, String message, Throwable cause) throws IOException {
        if (!blocking) {
            // javax.net.ssl.SSLEngine has no channel to hand an alert to the caller mid-record, so
            // the alert stays in the record layer's output queue and wrap() flushes it, the way
            // org/bouncycastle/tls/TlsProtocol.java:1710 does it for Bouncy Castle's jsse
            // org/bouncycastle/jsse/provider/ProvSSLEngine.java.
            TlsPeer peer = getPeer();
            if (peer != null) {
                peer.notifyAlertRaised(AlertLevel.fatal, alertDescription, message, cause);
            }
            try {
                safeWriteRecord(ContentType.alert,
                        new byte[] { (byte) AlertLevel.fatal, (byte) alertDescription }, 0, 2);
            } catch (IOException e) {
                // Already on an error path; a queue that cannot hold the alert changes nothing.
            }
            return;
        }

        if (factory.throwIOExceptionOnFatalAlert) {
            throw new IOException(message, cause);
        }

        // Legacy mode: report the alert and let the caller see a successful handshake.
        System.err.println("Fatal alert: " + message);
        if (cause != null) {
            cause.printStackTrace();
        }
    }

    @Override
    protected void raiseAlertWarning(short alertDescription, String message) throws IOException {
        if (!blocking) {
            // close_notify must reach the peer: javax/net/ssl/SSLEngine.java#closeOutbound() only closes the outbound
            // half, and the alert it queued still has to be flushed with wrap() before isOutboundDone() answers true.
            TlsPeer peer = getPeer();
            if (peer != null) {
                peer.notifyAlertRaised(AlertLevel.warning, alertDescription, message, null);
            }
            safeWriteRecord(ContentType.alert,
                    new byte[] { (byte) AlertLevel.warning, (byte) alertDescription }, 0, 2);
            return;
        }

        if (factory.logWarnings) {
            System.out.println(message);
        }
    }

    String getCipherSuite() {
        return BcPskTlsParams.getCipherSuite(getContext());
    }

    String getProtocol() {
        return BcPskTlsParams.getProtocol(getContext());
    }

    byte[] getSessionId() {
        return BcPskTlsParams.getSessionId(getContext());
    }

    String getApplicationProtocol() {
        return BcPskTlsParams.getApplicationProtocol(getContext());
    }
}
