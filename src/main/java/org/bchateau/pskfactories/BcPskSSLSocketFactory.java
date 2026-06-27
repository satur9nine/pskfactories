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
import java.net.Socket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.tls.BasicTlsPSKExternal;
import org.bouncycastle.tls.PSKTlsClient;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsPSKExternal;
import org.bouncycastle.tls.TlsPSKIdentity;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.TlsPeer;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;


/**
 * This SSLSocketFactory provides TLS pre-shared key (PSK) cipher suites via Bouncy Castle.
 * <p>
 * When using an instance of this class with OkHttpClient (and possibly other HTTP clients) you
 * must provide an instance of {@link EmptyX509TrustManager} because a null TrustManager is not
 * allowed, but the security of matching pre-shared keys is still enforced.
 */
public class BcPskSSLSocketFactory extends SSLSocketFactory {

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

    private final BcPskTlsParams params;
    private final TlsCrypto crypto;
    private final TlsPSKIdentity pskIdentity;

    public BcPskSSLSocketFactory(BcPskTlsParams params, TlsPSKIdentity pskIdentity) {
        this.params = params;
        this.crypto = new BcTlsCrypto(new SecureRandom());
        this.pskIdentity = pskIdentity;
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
     * does Arrays.fill(psk, 0)), so an identity whose getPSK() returns a caller-owned array is destroyed by the
     * first handshake that uses it. This wrapper hands out a fresh copy on each read instead.
     */
    private static TlsPSKIdentity copyOnRead(final TlsPSKIdentity identity) {
        return new TlsPSKIdentity() {
            @Override
            public void skipIdentityHint() {
                identity.skipIdentityHint();
            }

            @Override
            public void notifyIdentityHint(byte[] psk_identity_hint) {
                identity.notifyIdentityHint(psk_identity_hint);
            }

            @Override
            public byte[] getPSKIdentity() {
                return copy(identity.getPSKIdentity());
            }

            @Override
            public byte[] getPSK() {
                return copy(identity.getPSK());
            }
        };
    }

    private static byte[] copy(final byte[] value) {
        return value == null ? null : Arrays.copyOf(value, value.length);
    }

    // javax.net.ssl.SSLSocketFactory.createSocket(…, boolean autoClose) leaves it to the caller whether
    // closing this SSL socket closes the underlying one, and JDK's SSLSocketImpl gates its own super.close()
    // on that flag. Here the record layer belongs to Bouncy Castle: org/bouncycastle/tls/RecordStream.java:319
    // closes the java.io.InputStream/java.io.OutputStream it was handed, and for a java.net.Socket either
    // close shuts the whole connection down. With autoClose false the raw socket is the caller's property,
    // so BC gets these views: reads and writes delegate, close() stays with the caller.
    private static class BorrowedInputStream extends InputStream {
        private final InputStream borrowed;

        public BorrowedInputStream(InputStream borrowed) {
            super();
            this.borrowed = borrowed;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            return borrowed.read(buffer, offset, length);
        }

        @Override
        public int read() throws IOException {
            return borrowed.read();
        }

        @Override
        public void close() {
            // The caller owns the raw socket; javax.net.ssl.SSLSocketFactory's autoClose = false means
            // closing the SSL socket must not close it.
        }
    }

    private static class BorrowedOutputStream extends OutputStream {
        private final OutputStream borrowed;

        public BorrowedOutputStream(OutputStream borrowed) {
            super();
            this.borrowed = borrowed;
        }

        @Override
        public void write(byte[] buffer, int offset, int length) throws IOException {
            borrowed.write(buffer, offset, length);
        }

        @Override
        public void write(int b) throws IOException {
            borrowed.write(b);
        }

        @Override
        public void flush() throws IOException {
            borrowed.flush();
        }

        @Override
        public void close() {
            // Same as BorrowedInputStream: the caller hangs the raw socket up.
        }
    }

    /**
     * Builds this factory's alert-policy client protocol over the given streams.
     */
    BcPskTlsClientProtocol createProtocol(InputStream input, OutputStream output) {
        return new BcPskTlsClientProtocol(input, output, this);
    }

    /**
     * Builds this factory's alert-policy client protocol in org.bouncycastle.tls.TlsProtocol's
     * non-blocking (queue) mode, for javax.net.ssl.SSLEngine callers that feed the record
     * layer through offerInput()/readOutput() rather than over the stream pair.
     */
    BcPskTlsClientProtocol createProtocol() {
        return new BcPskTlsClientProtocol(this);
    }

    /**
     * Builds the Bouncy Castle client for one handshake attempt. Like the server side's
     * createTlsServer, the enabled sets come in as arguments so callers that constrain
     * negotiation per-connection (a javax.net.ssl.SSLSocket's enabled arrays, or a
     * javax.net.ssl.SSLEngine's) share one definition. The ALPN names offered to the peer
     * come in as an argument too; an empty array offers none.
     */
    TlsClient createTlsClient(final String[] enabledCipherSuites, final String[] enabledProtocols,
                                            final String[] applicationProtocols) {
        return new PSKTlsClient(crypto, copyOnRead(pskIdentity)) {
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return BcPskTlsParams.fromSupportedProtocolVersions(enabledProtocols);
            }

            @Override
            protected int[] getSupportedCipherSuites() {
                return BcPskTlsParams.fromSupportedCipherSuiteCodes(enabledCipherSuites);
            }

            @Override
            protected Vector getProtocolNames() {
                String[] protocols = applicationProtocols;
                if (protocols.length == 0) {
                    return null;
                }
                Vector protocolNames = new Vector();
                for (String protocol : protocols) {
                    protocolNames.add(ProtocolName.asUtf8Encoding(protocol));
                }
                return protocolNames;
            }

            @Override
            public Vector getExternalPSKs() {
                Vector<TlsPSKExternal> externals = new Vector<>();
                TlsSecret secret = crypto.createSecret(pskIdentity.getPSK());
                externals.add(new BasicTlsPSKExternal(pskIdentity.getPSKIdentity(), secret));
                return externals;
            }
        };
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return params.getSupportedCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return params.getSupportedCipherSuites();
    }

    /**
     * Creates a socket and connects it to the specified host and port.
     */
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        Socket socket = new Socket(host, port);
        return createSocket(socket, host, port, true);
    }

    /**
     * Creates a socket and connects it to the specified InetAddress and port. java.net.InetAddress
     * in this dialect exposes no bare host name (toString() renders "name/number"), so getPeerHost()
     * on the resulting socket reports the numeric address.
     */
    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        Socket socket = new Socket(host, port);
        return createSocket(socket, host.getHostAddress(), port, true);
    }

    /**
     * Creates a socket and connects it to the specified host and port, using the specified local address and port.
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        Socket socket = new Socket();
        socket.bind(new InetSocketAddress(localHost, localPort));
        socket.connect(new InetSocketAddress(host, port));
        return createSocket(socket, host, port, true);
    }

    /**
     * Creates a socket and connects it to the specified address and port, using the specified local
     * address and port. getPeerHost() reports the numeric address, see the note on the two-argument
     * InetAddress overload.
     */
    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        Socket socket = new Socket();
        socket.bind(new InetSocketAddress(localAddress, localPort));
        socket.connect(new InetSocketAddress(address, port));
        return createSocket(socket, address.getHostAddress(), port, true);
    }

    /**
     * Layers a TLS-PSK connection over an already-connected socket. autoClose is
     * javax.net.ssl.SSLSocketFactory's "close the underlying socket when this socket is closed": false
     * hands the raw connection back to the caller (tunneling, proxy hand-off). A socket that is not
     * connected yet is rejected the way javax.net.ssl.SSLSocketImpl does, with java.net.SocketException —
     * an IOException subclass, so the declared throws clause still covers the rejection.
     */
    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        if (!socket.isConnected()) {
            throw new SocketException("Underlying socket is not connected");
        }

        // autoClose = false: hand BC the borrowed views so its record-layer close cannot hang the
        // caller's raw socket up; autoClose = true keeps the socket's own streams.
        BcPskTlsClientProtocol tlsClientProtocol =
                new BcPskTlsClientProtocol(
                        autoClose ? socket.getInputStream() : new BorrowedInputStream(socket.getInputStream()),
                        autoClose ? socket.getOutputStream() : new BorrowedOutputStream(socket.getOutputStream()),
                        this);

        return new WrappedSSLSocket(socket, autoClose) {
            private String[] enabledCipherSuites = params.getSupportedCipherSuites();
            private String[] enabledProtocols = params.getSupportedProtocols();

            private boolean enableSessionCreation = true;
            private volatile boolean handshakeCompleted = false;
            private volatile IOException handshakeFailure = null;

            // A dedicated lock, not this: a client blocked in connect() must not hold the socket's
            // own lock, or close() would stall behind the handshake.
            private final Object handshakeLock = new Object();

            // The session clock starts when a handshake completes, not when the socket is built:
            // 0 means no session yet, so isValid() stays false until one runs.
            private volatile long sessionCreationTime = 0;

            // javax.net.ssl.SSLSession keeps two clocks: the session-representation one above, and an
            // access clock that only moves when a new connection is established on the session —
            // application-level ops such as putValue/getValue never move it. 0 means nothing has
            // re-used this session yet, so the access clock falls back to creation, and isValid()
            // measures the session timeout from that access clock.
            private volatile long lastAccessedTime = 0;

            // Handshaking is lazy and driven by whoever reaches it first: reading or writing here
            // runs the handshake before handing back the record-protocol streams.
            @Override
            public InputStream getInputStream() throws IOException {
                ensureHandshake();
                return tlsClientProtocol.getInputStream();
            }

            @Override
            public OutputStream getOutputStream() throws IOException {
                ensureHandshake();
                return tlsClientProtocol.getOutputStream();
            }

            @Override
            public void close() throws IOException {
                // The TLS connection hangs up first: Bouncy Castle's close() (org/bouncycastle/tls/TlsProtocol.java:1904) runs
                // handleClose(true), which raises the close_notify alert over the record layer and only
                // then closes it, so the raw socket has to be alive when that happens. Its own errors are
                // best-effort by design, as WrappedSocket.close() does on the server end, because the
                // hang-up below has to run either way: javax.net.ssl.Socket.close() reports no error to
                // the with-scope cleanup that calls this, and a throw here would replace whatever the
                // body was already propagating.
                try {
                    synchronized (tlsClientProtocol) {
                        tlsClientProtocol.close();
                    }
                } catch (IOException e) {
                    // Best-effort: the raw socket is hung up below either way.
                }
                super.close();
            }

            public String getApplicationProtocol() {
                return tlsClientProtocol.getApplicationProtocol();
            }

            // The session of the most recent handshake attempt: null until one completes, so a caller
            // can tell "no handshake yet" from "handshake that made no session".
            @Override
            public SSLSession getHandshakeSession() {
                return handshakeCompleted ? session : null;
            }

            // Same three states as the session's getApplicationProtocol(): null while the ALPN decision
            // is unknown, "" when this connection uses no application protocol, otherwise the name the
            // server answered the client's offer with.
            @Override
            public String getHandshakeApplicationProtocol() {
                return tlsClientProtocol.getApplicationProtocol();
            }

            // The client end picks nothing: it reports the sets its handshake will use and the ALPN
            // names it offers, with the suite-order flag left unset.
            @Override
            public SSLParameters getSSLParameters() {
                return BcPskTlsParams.fromEnabledState(getEnabledCipherSuites(), getEnabledProtocols(),
                        params.getApplicationProtocols(), false);
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

            @Override
            public void startHandshake() throws IOException {
                ensureHandshake();
            }

            // The handshake runs once, whichever accessor gets there first: getInputStream,
            // getOutputStream or startHandshake. A failure is recorded and rethrown because Bouncy
            // Castle's connect() is one-shot, and listeners run outside the lock so user code can
            // neither hold nor extend it.
            private void ensureHandshake() throws IOException {
                if (handshakeCompleted) {
                    return;
                }

                synchronized (handshakeLock) {
                    if (handshakeCompleted) {
                        return;
                    }
                    if (handshakeFailure != null) {
                        throw handshakeFailure;
                    }
                    runHandshake();
                }

                notifyHandshakeCompleted(new HandshakeCompletedEvent(this, session));
            }

            // The handshake attempt itself; runs under handshakeLock. A failure is recorded so later
            // calls rethrow it instead of re-entering Bouncy Castle's one-shot connect().
            private void runHandshake() throws IOException {

                TlsClient tlsClient =
                        createTlsClient(enabledCipherSuites, enabledProtocols,
                                params.getApplicationProtocols());

                try {
                    tlsClientProtocol.connect(tlsClient);
                    sessionCreationTime = System.currentTimeMillis();
                    handshakeCompleted = true;
                } catch (IOException e) {
                    // javax.net.ssl.SSLSocket: a failed handshake closes the socket, and BC's
                    // connect() is one-shot, so a retry must not re-enter it.
                    handshakeFailure = e;
                    try {
                        close();
                    } catch (IOException ignored) {
                        // Best-effort: the handshake failure is what the caller must see.
                    }
                    try {
                        // javax.net.ssl.SSLSocketFactory's layered createSocket goes further: "if a
                        // protocol error is detected, that existing connection is automatically closed",
                        // so the raw socket is hung up here even when autoClose is false.
                        socket.close();
                    } catch (IOException ignored) {
                        // Best-effort: the handshake failure is what the caller must see.
                    }
                    throw e;
                }
            }

            private final SSLSession session = new SSLSession() {
                    private boolean isValid = true;

                    // TLS record limits: 2^14 plaintext bytes, plus Bouncy Castle's headroom for
                    // compression and cipher overhead. These mirror TlsContext's constants.
                    protected static final int MAX_DATA_LENGTH = 16384;
                    protected static final int MAX_COMPRESSED_DATA_LENGTH
                            = MAX_DATA_LENGTH + 1024;
                    protected static final int MAX_CIPHERED_DATA_LENGTH
                            = MAX_COMPRESSED_DATA_LENGTH + 1024;
                    protected static final int MAX_SSL_PACKET_SIZE
                            = MAX_CIPHERED_DATA_LENGTH + 5;

                    private final Map<String, Object> valueMap = Collections.synchronizedMap(new HashMap<>());

                    @Override
                    public int getApplicationBufferSize() {
                        return tlsClientProtocol.getApplicationDataLimit();
                    }

                    @Override
                    public String getCipherSuite() {
                        return tlsClientProtocol.getCipherSuite();
                    }

                    @Override
                    public long getCreationTime() {
                        return sessionCreationTime;
                    }

                    @Override
                    public byte[] getId() {
                        return tlsClientProtocol.getSessionId();
                    }

                    @Override
                    public long getLastAccessedTime() {
                        return lastAccessedTime != 0 ? lastAccessedTime : sessionCreationTime;
                    }

                    @Override
                    public Certificate[] getLocalCertificates() {
                        return null;
                    }

                    @Override
                    public Principal getLocalPrincipal() {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public int getPacketBufferSize() {
                        return MAX_SSL_PACKET_SIZE;
                    }

                    @Override
                    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
                        return null;
                    }

                    @Override
                    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
                        return null;
                    }

                    @Override
                    public String getPeerHost() {
                        return host;
                    }

                    @Override
                    public int getPeerPort() {
                        return port;
                    }

                    @Override
                    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
                        return null;
                    }

                    @Override
                    public String getProtocol() {
                        return tlsClientProtocol.getProtocol();
                    }

                    public String getApplicationProtocol() {
                        return tlsClientProtocol.getApplicationProtocol();
                    }

                    // javax.net.ssl.SSLSession documents an unavailable context as null, and only SecurityException
                    // as a throw. A TLS-PSK connection negotiates no D-H or DSA group, so there is no context here;
                    // callers of the resumption/KDF getters must treat null as "no context", as with the JDK.
                    @Override
                    public SSLSessionContext getSessionContext() {
                        return null;
                    }

                    public Object getValue(String name) {
                        return valueMap.get(name);
                    }

                    public String[] getValueNames() {
                        synchronized (valueMap) {
                            return valueMap.keySet().toArray(new String[valueMap.size()]);
                        }
                    }

                    @Override
                    public void invalidate() {
                        isValid = false;
                    }

                    @Override
                    public boolean isValid() {
                        if (!isValid || sessionCreationTime == 0) {
                            // No handshake has completed yet, so there is no session to be valid.
                            return false;
                        }
                        boolean timedOut = params.getSessionTimeout() > 0
                                          && (System.currentTimeMillis() - getLastAccessedTime() >= params.getSessionTimeout());
                        return !timedOut && !socket.isClosed() && !tlsClientProtocol.isClosed();
                    }

                    @Override
                    public void putValue(String name, Object value) {
                        notifyUnbound(name, valueMap.put(name, value));
                        notifyBound(name, value);
                    }

                    @Override
                    public void removeValue(String name) {
                        notifyUnbound(name, valueMap.remove(name));
                    }

                    private void notifyBound(String name, Object value) {
                        if (value instanceof SSLSessionBindingListener) {
                            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(this, name));
                        }
                    }

                    private void notifyUnbound(String name, Object value) {
                        if (value instanceof SSLSessionBindingListener) {
                            ((SSLSessionBindingListener) value).valueUnbound(new SSLSessionBindingEvent(this, name));
                        }
                    }
                };

            @Override
            public SSLSession getSession() {
                return session;
            }
        };
    }

    /**
     * PSK TLS does not use certificates but clients may still require a non-null X509TrustManager so this one can
     * be used.
     */
    static class EmptyX509TrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}

/**
 * This factory's org.bouncycastle.tls.TlsClientProtocol plus the alert policy the socket classes
 * used to inline, and the negotiated-session accessors BcPskSSLEngine needs. Package level rather
 * than nested in the factory, so BcPskSSLEngine can name the type.
 */
class BcPskTlsClientProtocol extends TlsClientProtocol {
    private final BcPskSSLSocketFactory factory;

    // Streams-backed: BC's blocking record layer sits directly on the socket's streams
    // (org/bouncycastle/tls/TlsProtocol.java:182 picks blocking mode from the ctor shape)
    public BcPskTlsClientProtocol(InputStream input, OutputStream output,
                                                BcPskSSLSocketFactory factory) {
        super(input, output);
        this.factory = factory;
    }

    // No streams: org/bouncycastle/tls/TlsProtocol.java:174, the queue-backed non-blocking variant
    // javax.net.ssl.SSLEngine callers drive with offerInput()/readOutput().
    public BcPskTlsClientProtocol(BcPskSSLSocketFactory factory) {
        super();
        this.factory = factory;
    }

    @Override
    public void close() throws IOException {
        // Before any handshake, BC's peer and record state are null and its close() dereferences
        // them; cleanupHandshake() drops the half-built record layer instead.
        if (getPeer() == null) {
            cleanupHandshake();
        } else {
            super.close();
        }
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
