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
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import javax.security.cert.X509Certificate;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLParameters;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLSocket;

/**
 * Wraps one Socket with another Socket but redirects IO to provided parameter
 * streams to allow for TLS implementation to process the data moving through
 * the Socket.
 *
 * Handshaking is performed lazily on the first call to getInputStream,
 * getOutputStream, or startHandshake; handshake-completed listeners fire when that
 * first handshake finishes, on whichever call triggered it. The handshake is built
 * from this socket's enabled cipher suites and protocols, so setEnabledCipherSuites
 * and setEnabledProtocols must be called before that first call to have any effect.
 *
 * Only the handshake is coordinated across threads: exactly one handshake runs, and close()
 * stays callable while another thread is blocked in it. Concurrent reads and writes on the
 * returned streams are the caller's job, as with java.net.Socket. A failed handshake closes the socket
 * and records its failure: later calls rethrow that IOException instead of attempting a handshake
 * over the consumed connection.
 *
 * The session clock starts when a handshake completes, so a socket that never handshook has no valid session.
 */
class WrappedSocket extends WrappedSSLSocket {

    private volatile BcPskTlsServerProtocol protocol;
    private volatile InputStream in;
    private volatile OutputStream out;
    private final BcPskSSLServerSocketFactory factory;
    private final BcPskTlsParams params;
    private volatile String[] enabledCipherSuites;
    private volatile String[] enabledProtocols;

    // Guards the one-shot handshake only; I/O and close() never take it, so a socket stalled
    // mid-handshake can still be closed (java.net.Socket uses the same shape).
    private final Object handshakeLock = new Object();
    private IOException handshakeFailure = null;

    // The session clock starts when a handshake completes, not when the socket is built: 0 means
    // no session yet, so isValid() stays false until one runs.
    private volatile long sessionCreationTime = 0;

    // javax.net.ssl.SSLSession keeps two clocks: the session-representation one above, and an access
    // clock that only moves when a new connection is established on the session (application-level ops
    // such as putValue/getValue never move it). 0 means nothing has re-used this session yet, so the
    // access clock falls back to creation — what these sockets always see, since one handshake runs per
    // socket. isValid() measures the session timeout from that access clock, as the JDK documents.
    private volatile long lastAccessedTime = 0;

    /**
     * @param initialEnabledCipherSuites Cipher suites this socket may negotiate; a server socket
     * passes its own set so the accepted socket inherits it.
     * @param initialEnabledProtocols Protocol versions this socket may negotiate, inherited the
     * same way.
     */
    public WrappedSocket(Socket socket, BcPskSSLServerSocketFactory factory, BcPskTlsParams params,
                        String[] initialEnabledCipherSuites, String[] initialEnabledProtocols) throws IOException {
        super(socket);
        this.factory = factory;
        this.params = params;
        this.enabledCipherSuites = initialEnabledCipherSuites.clone();
        this.enabledProtocols = initialEnabledProtocols.clone();
    }

    private final SSLSession session = new SSLSession() {
        private boolean isValid = true;

        // TLS record limits: 2^14 plaintext bytes, plus Bouncy Castle's headroom for compression
        // and cipher overhead; MAX_SSL_PACKET_SIZE adds the 5-byte record header (type, version,
        // length). getPacketBufferSize() reports the last of them.
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
            return protocol == null ? 0 : protocol.getApplicationDataLimit();
        }

        @Override
        public String getCipherSuite() {
            return protocol == null ? null : protocol.getCipherSuite();
        }

        @Override
        public long getCreationTime() {
            return sessionCreationTime;
        }

        @Override
        public byte[] getId() {
            return protocol == null ? null : protocol.getSessionId();
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
        public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
            return null;
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            return null;
        }

        @Override
        public String getPeerHost() {
            InetAddress peer = socket.getInetAddress();
            return peer == null ? null : peer.toString();
        }

        @Override
        public int getPeerPort() {
            return socket.getPort();
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            return null;
        }

        @Override
        public String getProtocol() {
            return protocol == null ? null : protocol.getProtocol();
        }

        // null until the ALPN decision is known, "" when this connection uses no application protocol,
        // otherwise the negotiated name.
        public String getApplicationProtocol() {
            return protocol == null ? null : protocol.getApplicationProtocol();
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
            return !timedOut && !socket.isClosed() && protocol != null && !protocol.isClosed();
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

    private void ensureHandshake() throws IOException {
        if (protocol != null) {
            return;
        }
        synchronized (handshakeLock) {
            if (protocol != null) {
                return;
            }
            if (handshakeFailure != null) {
                throw handshakeFailure;
            }

            runHandshake();
        }

        // Listeners run outside the lock: user code must not hold or extend the handshake lock.
        notifyHandshakeCompleted(new HandshakeCompletedEvent(this, session));
    }

    // The handshake attempt itself; runs under handshakeLock. A failure is recorded so later
    // calls rethrow it instead of attempting the consumed connection again.
    private void runHandshake() throws IOException {
        try {
            BcPskTlsServerProtocol tlsProtocol =
                    new BcPskTlsServerProtocol(socket.getInputStream(),
                            socket.getOutputStream(), factory);
            tlsProtocol.accept(factory.createTlsServer(enabledCipherSuites, enabledProtocols,
                    applicationProtocolsToOffer()));
            sessionCreationTime = System.currentTimeMillis();
            this.protocol = tlsProtocol;
            this.in = tlsProtocol.getInputStream();
            this.out = tlsProtocol.getOutputStream();
        } catch (IOException e) {
            // javax.net.ssl.SSLSocket: a failed handshake closes the socket, and the connection
            // is consumed — retrying would build a fresh protocol over half-read streams.
            handshakeFailure = e;
            try {
                close();
            } catch (IOException ignored) {
                // Best-effort: the handshake failure is what the caller must see.
            }
            throw e;
        }
    }

    @Override
    public InputStream getInputStream() throws IOException {
        ensureHandshake();
        return in;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        ensureHandshake();
        return out;
    }

    @Override
    public void startHandshake() throws IOException {
        ensureHandshake();
    }

    @Override
    public void close() throws IOException {
        try {
            if (protocol != null) {
                protocol.close();
            }
        } catch (IOException e) {
            // Best-effort close of the TLS protocol; the wrapped socket is closed below either way.
        }
        super.close();
    }

    @Override
    public boolean getEnableSessionCreation() {
        return true;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {}

    @Override
    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites.clone();
    }

    @Override
    public void setEnabledCipherSuites(String[] cipherSuites) {
        enabledCipherSuites = BcPskTlsParams.requireSupported(cipherSuites, params.getSupportedCipherSuites(), "cipher suite");
    }

    @Override
    public String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        enabledProtocols = BcPskTlsParams.requireSupported(protocols, params.getSupportedProtocols(), "protocol");
    }

    @Override
    public boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public void setNeedClientAuth(boolean need) {}

    @Override
    public boolean getWantClientAuth() {
        return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {}

    @Override
    public String[] getSupportedCipherSuites() {
        return params.getSupportedCipherSuites().clone();
    }

    @Override
    public String[] getSupportedProtocols() {
        return params.getSupportedProtocols().clone();
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    // The session of the most recent handshake attempt: null until one completes, the object itself
    // afterwards, matching how javax.net.ssl.SSLSocket reports a handshake that has not run.
    @Override
    public SSLSession getHandshakeSession() {
        return protocol == null ? null : session;
    }

    // Same three states as the session's getApplicationProtocol(): null while the ALPN decision is
    // unknown, "" when this connection uses no application protocol, otherwise the negotiated name.
    @Override
    public String getHandshakeApplicationProtocol() {
        return protocol == null ? null : protocol.getApplicationProtocol();
    }

    // The handshake reads its own cipher suite list, so the order flag says this end picks.
    @Override
    public SSLParameters getSSLParameters() {
        return BcPskTlsParams.fromEnabledState(getEnabledCipherSuites(), getEnabledProtocols(),
                applicationProtocolsToOffer(), true);
    }

    @Override
    public void setUseClientMode(boolean mode) {}

    @Override
    public boolean getUseClientMode() {
        return false;
    }

    // The ALPN names this socket offers the peer: its own names, narrowed to the single name a
    // handshake application-protocol selector returns. Returning null offers none, so a peer that
    // asked for ALPN gets no_application_protocol; Bouncy Castle otherwise keeps the first name the
    // peer also offered.
    private String[] applicationProtocolsToOffer() {
        String[] names = params.getApplicationProtocols();
        BiFunction<SSLSocket, List<String>, String> selector = getHandshakeApplicationProtocolSelector();
        if (selector == null) {
            return names;
        }

        List<String> candidates = new ArrayList<String>();
        for (String name : names) {
            candidates.add(name);
        }

        String chosen = selector.apply((SSLSocket) this, candidates);
        if (chosen == null) {
            return new String[0];
        }

        return new String[] { chosen };
    }
}
