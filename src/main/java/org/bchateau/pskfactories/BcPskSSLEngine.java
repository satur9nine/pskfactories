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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;
import java.security.Principal;
import java.security.cert.Certificate;
import javax.security.cert.X509Certificate;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.RecordFormat;
import org.bouncycastle.tls.RecordPreview;

public class BcPskSSLEngine extends SSLEngine {

    private final BcPskSSLSocketFactory clientFactory;
    private final BcPskSSLServerSocketFactory serverFactory;

    private final String peerHost;
    private final int peerPort;

    // The enabled sets the handshake reads; createTlsClient()/createTlsServer() take them as
    // arguments, mirroring how the socket classes let setEnabled* constrain negotiation.
    private String[] enabledCipherSuites;
    private String[] enabledProtocols;
    // The ALPN names this engine offers; setSSLParameters() replaces them, as SSLParameters is
    // where a caller supplies the ALPN list for a javax.net.ssl.SSLEngine.
    private String[] applicationProtocols;

    private BcPskTlsClientProtocol clientProtocol;
    private BcPskTlsServerProtocol serverProtocol;
    private TlsProtocol protocol;
    private BcPskTlsParams params;

    // javax/net/ssl/SSLEngine.java#setUseClientMode(): the handshake may not begin before the mode is set.
    private boolean useClientModeSet;
    // A second beginHandshake() would be renegotiation, which this library never attempts.
    private boolean handshakeBegun;
    // javax/net/ssl/SSLEngine.java#getHandshakeStatus(): FINISHED marks the one result that completes the
    // handshake; BC's anonymous peers give the handshake-complete callback no handle, so the
    // engine reports it on the first observation of isHandshaking() turning false.
    private boolean returnedFinished;
    // closeInbound()/closeOutbound() before any handshake: nothing to flush, everything done.
    private boolean closedEarly;
    /*
     * javax/net/ssl/SSLEngine.java#closeOutbound() and its #closeInbound() (the class javadoc's
     * phases 4-5) close the halves one at a time, so the halves are tracked here: Bouncy Castle's
     * TlsProtocol#close() runs its handleClose (org/bouncycastle/tls/TlsProtocol.java:283-306),
     * which marks the whole connection closed at once and would make isInboundDone() true before
     * the peer's close_notify could be read or flushed.
     */
    private boolean outboundClosed;
    private boolean inboundClosed;
    /*
     * Bouncy Castle reports a peer's rejection as IOException out of the record layer. javax.net.ssl.SSLEngine
     * documents no throw channel for an error raised inside unwrap(), so the engine stores it and
     * the next wrap() throws it - the deferred-exception shape Bouncy Castle's own jsse
     * org/bouncycastle/jsse/provider/ProvSSLEngine.java:491-505 uses, so a caller like Tomcat's
     * SecureNioChannel can still flush the alert record the failed unwrap buffered.
     */
    private SSLException deferredException;

    private long sessionCreationTime;
    private long lastAccessedTime;

    /**
     * A client-mode engine: it initiates handshakes and offers the factory's pre-shared key to the
     * peer at peerHost:peerPort.
     */
    public BcPskSSLEngine(BcPskSSLSocketFactory factory, String peerHost, int peerPort) {
        super(peerHost, peerPort);
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.clientFactory = factory;
        this.serverFactory = null;
        this.params = factory.getConfiguration();
        this.enabledCipherSuites = factory.getDefaultCipherSuites();
        this.enabledProtocols = this.params.getSupportedProtocols().clone();
        this.applicationProtocols = this.params.getApplicationProtocols();
    }

    /**
     * A server-mode engine: it waits for the handshake and answers with the factory's pre-shared key.
     */
    public BcPskSSLEngine(BcPskSSLServerSocketFactory factory, String peerHost, int peerPort) {
        super(peerHost, peerPort);
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.clientFactory = null;
        this.serverFactory = factory;
        this.params = factory.getConfiguration();
        this.enabledCipherSuites = factory.getDefaultCipherSuites();
        this.enabledProtocols = this.params.getSupportedProtocols().clone();
        this.applicationProtocols = this.params.getApplicationProtocols();
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
            return protocol == null ? 0 : applicationDataLimit();
        }

        // javax/net/ssl/SSLEngine.java#getSession(): before a handshake the null suite is reported,
        // named SSL_NULL_WITH_NULL_NULL; after one it reports what was negotiated.
        @Override
        public String getCipherSuite() {
            return protocol == null ? "SSL_NULL_WITH_NULL_NULL" : negotiatedCipherSuite();
        }

        @Override
        public long getCreationTime() {
            return sessionCreationTime;
        }

        @Override
        public byte[] getId() {
            return protocol == null ? null : negotiatedSessionId();
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

        // A TLS-PSK connection authenticates both ends with the pre-shared key and negotiates no
        // certificates, so the peer certificate getters report nothing, as javax.net.ssl.SSLSession
        // documents for connections without peer certificates.
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
            return peerHost;
        }

        @Override
        public int getPeerPort() {
            return peerPort;
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            return null;
        }

        @Override
        public String getProtocol() {
            return protocol == null ? null : negotiatedProtocol();
        }

        // null until the ALPN decision is known, "" when this connection uses no application
        // protocol, otherwise the negotiated name.
        public String getApplicationProtocol() {
            return protocol == null ? null : negotiatedApplicationProtocol();
        }

        // javax/net/ssl/SSLSession.java#getSessionContext() documents an unavailable context as null, and only
        // SecurityException as a throw. A TLS-PSK connection negotiates no D-H or DSA group, so
        // there is no context here; callers of the resumption/KDF getters must treat null as
        // "no context", as with the JDK's PSK sessions.
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
            return !timedOut && protocol != null && !protocol.isClosed();
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

    // The negotiated values come from the protocol adapter subclasses: org.bouncycastle.tls.TlsProtocol
    // declares getContext() protected and abstract (org/bouncycastle/tls/TlsProtocol.java:221), so no caller outside an
    // adapter can read the record state; the socket classes override the getters on their adapters.
    private String negotiatedCipherSuite() {
        return clientProtocol != null ? clientProtocol.getCipherSuite() : serverProtocol.getCipherSuite();
    }

    private String negotiatedProtocol() {
        return clientProtocol != null ? clientProtocol.getProtocol() : serverProtocol.getProtocol();
    }

    private byte[] negotiatedSessionId() {
        return clientProtocol != null ? clientProtocol.getSessionId() : serverProtocol.getSessionId();
    }

    private String negotiatedApplicationProtocol() {
        return clientProtocol != null ? clientProtocol.getApplicationProtocol() : serverProtocol.getApplicationProtocol();
    }

    private int applicationDataLimit() {
        return clientProtocol != null ? clientProtocol.getApplicationDataLimit() : serverProtocol.getApplicationDataLimit();
    }

    @Override
    public synchronized void beginHandshake() throws SSLException {
        if (!useClientModeSet) {
            throw new IllegalStateException("Client/Server mode must be set before the handshake can begin");
        }
        if (closedEarly) {
            throw new SSLException("Connection is already closed");
        }
        if (handshakeBegun) {
            // org/bouncycastle/jsse/provider/ProvSSLEngine.java:96 refuses a second attempt: Bouncy
            // Castle's org/bouncycastle/tls/TlsProtocol.java:188-200 renegotiation hook is commented out,
            // so a second attempt would reuse a record layer the first one consumed.
            throw new UnsupportedOperationException("Renegotiation not supported");
        }
        handshakeBegun = true;

        try {
            if (clientFactory != null) {
                BcPskTlsClientProtocol candidate = clientFactory.createProtocol();
                this.protocol = candidate;
                this.clientProtocol = candidate;
                candidate.connect(clientFactory.createTlsClient(enabledCipherSuites, enabledProtocols,
                        applicationProtocolsToOffer()));
            } else {
                BcPskTlsServerProtocol candidate = serverFactory.createProtocol();
                this.protocol = candidate;
                this.serverProtocol = candidate;
                candidate.accept(serverFactory.createTlsServer(enabledCipherSuites, enabledProtocols,
                        applicationProtocolsToOffer()));
            }
            sessionCreationTime = System.currentTimeMillis();
        } catch (SSLException e) {
            throw e;
        } catch (IOException e) {
            // org/bouncycastle/jsse/provider/ProvSSLEngine.java:128-131: a failed handshake attempt
            // to a javax.net.ssl.SSLEngine caller; the record layer is consumed either way.
            throw new SSLException(e);
        }
    }

    @Override
    public synchronized HandshakeStatus getHandshakeStatus() {
        if (protocol != null) {
            if (protocol.getAvailableOutputBytes() > 0 || deferredException != null) {
                return HandshakeStatus.NEED_WRAP;
            }
            if (protocol.isHandshaking()) {
                return HandshakeStatus.NEED_UNWRAP;
            }
        }
        return HandshakeStatus.NOT_HANDSHAKING;
    }

    // The first result that sees the handshake complete reports FINISHED; later ones report
    // NOT_HANDSHAKING, as javax/net/ssl/SSLEngine.java#getHandshakeStatus() documents for javax.net.ssl.SSLEngine.
    private HandshakeStatus finishedOrNotHandshaking() {
        if (!returnedFinished && protocol != null && !protocol.isHandshaking()) {
            returnedFinished = true;
            return HandshakeStatus.FINISHED;
        }
        return HandshakeStatus.NOT_HANDSHAKING;
    }

    private Status getStatus() {
        // javax/net/ssl/SSLEngine.java#closeOutbound() and its #closeInbound(): a half closed by the caller
        // or by the peer's close_notify makes the engine CLOSED.
        return protocol != null && (protocol.isClosed() || outboundClosed || inboundClosed) ?
                Status.CLOSED : Status.OK;
    }

    // javax/net/ssl/SSLEngine.java#closeOutbound(): queues the close_notify
    // alert in the record layer's output buffer for wrap() to flush. The alert helper lives on
    // the library's protocol subclasses (BC's TlsProtocol#close() would close both halves at
    // once), and exactly one of them backs this engine.
    private void queueCloseNotifyAlert() throws IOException {
        if (clientProtocol != null) {
            clientProtocol.raiseCloseNotifyAlert();
        } else {
            serverProtocol.raiseCloseNotifyAlert();
        }
    }

    private RecordPreview peekRecordPreview(ByteBuffer src) throws IOException {
        if (src.remaining() < RecordFormat.FRAGMENT_OFFSET) {
            return null;
        }

        byte[] recordHeader = new byte[RecordFormat.FRAGMENT_OFFSET];

        int position = src.position();
        src.get(recordHeader);
        src.position(position);

        return protocol.previewInputRecord(recordHeader);
    }

    private int getTotalRemaining(ByteBuffer[] bufs, int off, int len, int limit) {
        int result = 0;
        for (int i = 0; i < len; ++i) {
            ByteBuffer buf = bufs[off + i];
            int next = buf.remaining();
            if (next >= (limit - result)) {
                return limit;
            }
            result += next;
        }
        return result;
    }

    private boolean hasInsufficientSpace(ByteBuffer[] dsts, int off, int len, int amount) {
        return getTotalRemaining(dsts, off, len, amount) < amount;
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset,
                                                           int length, ByteBuffer dst) throws SSLException {
        if (deferredException != null) {
            SSLException e = deferredException;
            deferredException = null;
            throw e;
        }

        if (closedEarly) {
            return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }

        if (!handshakeBegun) {
            beginHandshake();
        }

        int bytesProduced = 0;

        final int outputAvailable = protocol.getAvailableOutputBytes();
        if (outputAvailable > 0) {
            /*
             * Flush what the record layer already buffered - the ClientHello/ServerHello side of the
             * handshake, or the alert a rejected peer left behind. Take everything when dst can hold
             * it, otherwise one whole record (org/bouncycastle/tls/TlsProtocol.java:1238 previewOutputRecord()).
             */
            int remaining = dst.remaining();
            if (remaining >= outputAvailable) {
                bytesProduced = outputAvailable;
            } else {
                bytesProduced = protocol.previewOutputRecord();
                if (remaining < bytesProduced) {
                    return new SSLEngineResult(Status.BUFFER_OVERFLOW,
                            HandshakeStatus.NEED_WRAP, 0, 0);
                }
            }

            protocol.readOutput(dst, bytesProduced);

            if (bytesProduced < outputAvailable) {
                return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_WRAP, 0, bytesProduced);
            }
            // All of it was flushed, so no early return here: control leaves both branches and the
            // tail below reports the flushed bytes plus what the peer needs next.
        } else if (!outboundClosed && protocol.isConnected()) {
            try {
                int bytesConsumed = 0;

                /*
                 * Generate at most one maximum-sized application data record per call
                 * (org/bouncycastle/tls/TlsProtocol.java:1414 getApplicationDataLimit()).
                 */
                int srcRemaining = getTotalRemaining(srcs, offset, length, applicationDataLimit());
                if (srcRemaining > 0) {
                    RecordPreview preview = protocol.previewOutputRecord(srcRemaining);

                    int srcLimit = preview.getContentLimit();
                    int dstLimit = preview.getRecordSize();

                    if (dst.remaining() < dstLimit) {
                        return new SSLEngineResult(Status.BUFFER_OVERFLOW,
                                HandshakeStatus.NOT_HANDSHAKING, 0, 0);
                    }

                    byte[] buffer = new byte[srcLimit];

                    for (int srcIndex = 0; srcIndex < length && bytesConsumed < srcLimit; ++srcIndex) {
                        ByteBuffer src = srcs[offset + srcIndex];
                        int count = Math.min(src.remaining(), srcLimit - bytesConsumed);
                        if (count > 0) {
                            src.get(buffer, bytesConsumed, count);
                            bytesConsumed += count;
                        }
                    }

                    protocol.writeApplicationData(buffer, 0, bytesConsumed);

                    bytesProduced = protocol.getAvailableOutputBytes();
                    protocol.readOutput(dst, bytesProduced);
                }

                return new SSLEngineResult(getStatus(), finishedOrNotHandshaking(),
                        bytesConsumed, bytesProduced);
            } catch (IOException e) {
                throw new SSLException(e);
            }
        }

        if (protocol.isHandshaking()) {
            return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_UNWRAP, 0, bytesProduced);
        }

        return new SSLEngineResult(getStatus(), finishedOrNotHandshaking(), 0, bytesProduced);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset,
                                                             int length) throws SSLException {
        final HandshakeStatus initialHandshakeStatus = getHandshakeStatus();

        if (isInboundDone()) {
            return new SSLEngineResult(Status.CLOSED, initialHandshakeStatus, 0, 0);
        }

        if (!handshakeBegun) {
            beginHandshake();
        }

        switch (initialHandshakeStatus) {
        case NEED_UNWRAP:
        case NOT_HANDSHAKING:
            break;
        default:
            return new SSLEngineResult(Status.OK, initialHandshakeStatus, 0, 0);
        }

        int bytesConsumed = 0;
        try {
            RecordPreview preview = peekRecordPreview(src);
            if (preview == null || src.remaining() < preview.getRecordSize()) {
                return new SSLEngineResult(Status.BUFFER_UNDERFLOW, initialHandshakeStatus, 0, 0);
            }
            if (hasInsufficientSpace(dsts, offset, length, preview.getContentLimit())) {
                return new SSLEngineResult(Status.BUFFER_OVERFLOW, initialHandshakeStatus, 0, 0);
            }

            bytesConsumed = preview.getRecordSize();
            byte[] record = new byte[bytesConsumed];
            src.get(record);

            protocol.offerInput(record, 0, record.length);
        } catch (IOException e) {
            /*
             * A rejected record leaves the alert the record layer queued in its output buffer
             * (raiseAlertFatal on the protocol subclasses), so the result asks for NEED_WRAP and
             * the exception is stored for the next wrap() to surface once that alert is flushable
             * - javax/net/ssl/SSLEngine.java#closeOutbound(), the shape
             * org/bouncycastle/jsse/provider/ProvSSLEngine.java:491-505 keeps so that a caller can still
             * drain the alert. An engine whose inbound half is closed has no flush left, so it throws.
             */
            if (isInboundDone()) {
                throw new SSLException(e);
            }

            this.deferredException = new SSLException(e);

            return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_WRAP, bytesConsumed, 0);
        }

        int appDataAvailable = protocol.getAvailableInputBytes(), bytesProduced = 0;
        for (int dstIndex = 0; appDataAvailable > 0; ++dstIndex) {
            ByteBuffer dst = dsts[offset + dstIndex];
            int count = Math.min(dst.remaining(), appDataAvailable);
            if (count > 0) {
                protocol.readInput(dst, count);
                bytesProduced += count;
                appDataAvailable -= count;
            }
        }

        HandshakeStatus resultHandshakeStatus = getHandshakeStatus();
        if (resultHandshakeStatus == HandshakeStatus.NOT_HANDSHAKING) {
            resultHandshakeStatus = finishedOrNotHandshaking();
        }

        return new SSLEngineResult(getStatus(), resultHandshakeStatus, bytesConsumed, bytesProduced);
    }

    // javax/net/ssl/SSLEngine.java#getDelegatedTask(): tasks carry the CPU-heavy half of an
    // asymmetric-certificate handshake. TLS-PSK negotiation is symmetric, so every step runs
    // inside the wrap()/unwrap() call that drives it, and there is never a task to run.
    @Override
    public synchronized Runnable getDelegatedTask() {
        return null;
    }

    @Override
    public synchronized void closeInbound() throws SSLException {
        if (closedEarly) {
            // javax.net.ssl.SSLEngine closed before any handshake: nothing to flush, everything done.
        } else if (protocol == null) {
            this.closedEarly = true;
        } else {
            inboundClosed = true;
            try {
                // BC's closeInput() is the EOF half: a peer that never sent close_notify fails
                // here (javax/net/ssl/SSLEngine.java#closeInbound() documents that it throws then),
                // and an inbound half already closed by that alert returns quietly.
                protocol.closeInput();
            } catch (IOException e) {
                throw new SSLException(e);
            }
        }
    }

    @Override
    public synchronized boolean isInboundDone() {
        return closedEarly || inboundClosed || (protocol != null && protocol.isClosed());
    }

    @Override
    public synchronized void closeOutbound() {
        if (closedEarly) {
            // javax.net.ssl.SSLEngine closed before any handshake: nothing to flush, everything done.
        } else if (protocol == null) {
            this.closedEarly = true;
        } else {
            outboundClosed = true;
            if (!protocol.isClosed()) {
                try {
                    // javax/net/ssl/SSLEngine.java#closeOutbound(): only the outbound half
                    // closes, and its close_notify alert joins the record layer's output queue.
                    queueCloseNotifyAlert();
                } catch (IOException e) {
                    // javax/net/ssl/SSLEngine.java#closeOutbound() reports no error: the caller flushes
                    // the buffered close_notify alert with wrap() next, and isOutboundDone()
                    // watches the record layer's remaining output.
                }
            }
        }
    }

    @Override
    public synchronized boolean isOutboundDone() {
        return closedEarly || (protocol != null && (protocol.isClosed() || outboundClosed)
                && protocol.getAvailableOutputBytes() < 1);
    }

    @Override
    public synchronized String[] getSupportedCipherSuites() {
        return params.getSupportedCipherSuites().clone();
    }

    @Override
    public synchronized String[] getEnabledCipherSuites() {
        return enabledCipherSuites.clone();
    }

    @Override
    public synchronized void setEnabledCipherSuites(String[] suites) {
        // Same convention as the socket classes: a null list enables nothing, an unknown name fails
        // here rather than silently leaving the set unchanged (BcPskTlsParams.java#requireSupported()).
        enabledCipherSuites = BcPskTlsParams.requireSupported(suites, params.getSupportedCipherSuites(), "cipher suite");
    }

    @Override
    public synchronized String[] getSupportedProtocols() {
        return params.getSupportedProtocols().clone();
    }

    @Override
    public synchronized String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols) {
        enabledProtocols = BcPskTlsParams.requireSupported(protocols, params.getSupportedProtocols(), "protocol");
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    // The session of the running or completed handshake attempt: null until beginHandshake() ran,
    // mirroring how javax/net/ssl/SSLSocket.java#getHandshakeSession() reports a handshake that has not started.
    @Override
    public SSLSession getHandshakeSession() {
        return protocol == null ? null : session;
    }

    // Same three states as the session's getApplicationProtocol(): null while the ALPN decision is
    // unknown, "" when this connection uses no application protocol, otherwise the negotiated name.
    @Override
    public String getApplicationProtocol() {
        return protocol == null ? null : negotiatedApplicationProtocol();
    }

    @Override
    public String getHandshakeApplicationProtocol() {
        return protocol == null ? null : negotiatedApplicationProtocol();
    }

    private BiFunction<SSLEngine, List<String>, String> applicationProtocolSelector;

    @Override
    public BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return applicationProtocolSelector;
    }

    @Override
    public void setHandshakeApplicationProtocolSelector(BiFunction<SSLEngine, List<String>, String> selector) {
        applicationProtocolSelector = selector;
    }

    /**
     * The ALPN names this engine offers the peer: its factory's names, narrowed to the single name a
     * handshake application-protocol selector returns. Returning none offers none, so a peer that
     * asked for ALPN gets no_application_protocol; Bouncy Castle otherwise keeps the first name the
     * peer also offered. Only the server side of a connection consults a selector, as
     * javax.net.ssl.SSLEngine documents.
     */
    private String[] applicationProtocolsToOffer() {
        String[] names = applicationProtocols;
        if (applicationProtocolSelector == null) {
            return names;
        }

        List<String> candidates = new ArrayList<>();
        Collections.addAll(candidates, names);

        String chosen = applicationProtocolSelector.apply(this, candidates);
        if (chosen == null) {
            return new String[0];
        }

        return new String[] { chosen };
    }

    /*
     * One policy on every surface, as the socket classes do: the enabled sets plus the ALPN names
     * this engine will offer, and the order flag says whether this end prefers its own suite order.
     */
    @Override
    public SSLParameters getSSLParameters() {
        return BcPskTlsParams.fromEnabledState(getEnabledCipherSuites(), getEnabledProtocols(),
                applicationProtocolsToOffer(), clientFactory == null);
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters sslParameters) {
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

        String[] applicationProtocolsFromParams = sslParameters.getApplicationProtocols();
        if (applicationProtocolsFromParams != null) {
            this.applicationProtocols = applicationProtocolsFromParams;
        }
    }

    @Override
    public synchronized void setUseClientMode(boolean mode) {
        if (handshakeBegun) {
            throw new IllegalArgumentException("Client/Server mode cannot be changed after the handshake has begun");
        }
        if (mode == (clientFactory == null)) {
            throw new IllegalStateException(
                    "This engine is bound to the side of the factory it was built with; use the matching engine for the other side");
        }
        useClientModeSet = true;
    }

    @Override
    public synchronized boolean getUseClientMode() {
        return clientFactory != null;
    }

    /*
     * A TLS-PSK connection authenticates both ends with the pre-shared key, so the certificate
     * handshake's client-auth knobs have nothing to toggle: the setters are inert and the getters
     * report false, as javax/net/ssl/SSLSocket.java's #setNeedClientAuth(), #setWantClientAuth(),
     * #getNeedClientAuth() and #getWantClientAuth() do for certificate peers.
     */
    @Override
    public synchronized void setNeedClientAuth(boolean need) {}

    @Override
    public synchronized boolean getNeedClientAuth() {
        return false;
    }

    @Override
    public synchronized void setWantClientAuth(boolean want) {}

    @Override
    public synchronized boolean getWantClientAuth() {
        return false;
    }

    // Every handshake attempt builds a fresh TlsProtocol object, so session creation is always on
    // and the setter has nothing to switch off.
    @Override
    public synchronized void setEnableSessionCreation(boolean flag) {}

    @Override
    public synchronized boolean getEnableSessionCreation() {
        return true;
    }

    @Override
    public String toString() {
        return "BcPskSSLEngine(" + getPeerHost() + ":" + getPeerPort() + ")";
    }
}
