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

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;

import java.util.function.BiFunction;

/**
 * This class delegates most functionality to a wrapped regular Socket.
 */
abstract class WrappedSSLSocket extends SSLSocket {

    protected final Socket socket;

    private final List<HandshakeCompletedListener> listeners = new ArrayList<>(2);

    // javax.net.ssl.SSLSocketFactory.createSocket(…, boolean autoClose) documents autoClose as "close the
    // underlying socket when this socket is closed", and JDK's SSLSocketImpl keeps that flag per socket
    // while its own tlsIsClosed keeps the SSL layer reporting itself hung up. false hands the raw
    // connection back to the caller (tunneling, proxy hand-off), so the mutations below are gated and
    // the predicates above report the SSL layer's own view. The accepted-socket end has no such choice.
    protected boolean autoClose = true;
    private boolean sslLayerClosed = false;
    private boolean inputShutdownRequested = false;
    private boolean outputShutdownRequested = false;

    public WrappedSSLSocket(Socket socket) {
        // No super(): java.net.Socket's constructor would open a connection of its own, and this
        // class only ever wraps the already-connected socket the factory hands it.
        this.socket = socket;
    }

    public WrappedSSLSocket(Socket socket, boolean autoClose) {
        this(socket);
        this.autoClose = autoClose;
    }

    // javax.net.ssl.SSLSocket inherits java.net.Socket's connect, and java/net/Socket.java#connect() refuses an
    // already-connected socket with java.net.SocketException("already connected"): the factories only ever
    // layer onto a socket that is connected already, so a layered socket cannot be re-pointed.
    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        socket.connect(endpoint, timeout);
    }

    @Override
    public InetAddress getInetAddress() {
        return socket.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return socket.getLocalAddress();
    }

    @Override
    public int getPort() {
        return socket.getPort();
    }

    @Override
    public int getLocalPort() {
        return socket.getLocalPort();
    }

    @Override
    public abstract InputStream getInputStream() throws IOException;

    @Override
    public abstract OutputStream getOutputStream() throws IOException;

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        socket.setTcpNoDelay(on);
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return socket.getTcpNoDelay();
    }

    @Override
    public void setSoLinger(boolean on, int val) throws SocketException {
        socket.setSoLinger(on, val);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return socket.getSoLinger();
    }

    // java/net/Socket.java#setSoTimeout() governs reads on the socket's own java.net.Socket streams, which is what
    // the record layer (and so the handshake) reads; the SSL layer's getInputStream() hands out the
    // record-layer's decrypted stream, whose reads are memory reads that no SO_TIMEOUT can reach.
    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        socket.setSoTimeout(timeout);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return socket.getSoTimeout();
    }

    @Override
    public void close() throws IOException {
        sslLayerClosed = true;
        if (autoClose) {
            socket.close();
        }
    }

    @Override
    public boolean isClosed() {
        return sslLayerClosed || socket.isClosed();
    }

    @Override
    public boolean isConnected() {
        return socket.isConnected();
    }

    @Override
    public boolean isBound() {
        return socket.isBound();
    }

    // java/net/Socket.java#shutdownInput() places the input stream at end of stream, and java/net/Socket.java
    // names the refusals that follow: its "Socket is closed" and "Socket input is already shutdown". Those guards
    // belong to the raw socket's own java.net.Socket streams, and it is the SSL layer, not the raw socket,
    // that owns this shutdown - so once the SSL layer has marked the read half closed, a repeat answers
    // quietly and java/net/Socket.java's raw guards cannot re-raise out of a layered socket.
    @Override
    public void shutdownInput() throws IOException {
        if (isInputShutdown()) {
            return;
        }

        inputShutdownRequested = true;
        if (autoClose && !socket.isInputShutdown()) {
            socket.shutdownInput();
        }
    }

    // Same as shutdownInput(), against java/net/Socket.java#shutdownOutput(): the SSL layer marks its write
    // half closed once, and only a socket whose write half is still live gets java.net.Socket's
    // half-close, which terminates the connection without a close_notify alert - the TLS peer sees an
    // abrupt end of stream, so a TLS-clean hang-up is close(), which sends the alert.
    @Override
    public void shutdownOutput() throws IOException {
        if (isOutputShutdown()) {
            return;
        }

        outputShutdownRequested = true;
        if (autoClose && !socket.isOutputShutdown()) {
            socket.shutdownOutput();
        }
    }

    @Override
    public boolean isInputShutdown() {
        return inputShutdownRequested || socket.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return outputShutdownRequested || socket.isOutputShutdown();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return socket.getRemoteSocketAddress();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return socket.getLocalSocketAddress();
    }

    // java/net/Socket.java#setOOBInline() and java/net/Socket.java#getOOBInline() declare java.net.SocketException
    // for the TCP urgent-data option, and java/net/Socket.java#sendUrgentData() already refuses
    // java.net.SocketException("Urgent data not supported") when the platform gives no out-of-band
    // channel. TLS gives no way to tell urgent data from record bytes, so enabling the option is refused
    // with java.net.SocketException's own class, leaving the declared throws clause honest, while
    // disabling it - the JDK's own default - is a no-op, and java/net/Socket.java#getOOBInline() reports it off.
    @Override
    public void setOOBInline(boolean on) throws SocketException {
        if (on) {
            throw new SocketException("Urgent data not supported");
        }
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return false;
    }

    // java/net/Socket.java#getChannel() returns the channel only for a socket opened through
    // java.nio.channels.SocketChannel; a factory socket was not, and the SSL layer's stream pair is the
    // only way into the connection, so the raw plaintext channel is never handed out.
    @Override
    public SocketChannel getChannel() {
        return null;
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException {
        socket.setSendBufferSize(size);
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return socket.getSendBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        socket.setReceiveBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return socket.getReceiveBufferSize();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        socket.setKeepAlive(on);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return socket.getKeepAlive();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        socket.setTrafficClass(tc);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return socket.getTrafficClass();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        socket.setReuseAddress(on);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return socket.getReuseAddress();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        socket.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    // javax.net.ssl.SSLSocket inherits java.net.Socket's bind, and java/net/Socket.java#bind() refuses an
    // already-bound socket with java.net.SocketException("Already bound"); a connected socket is bound,
    // so a layered socket keeps its peer and cannot be re-pointed.
    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        socket.bind(bindpoint);
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        throw new SocketException("Urgent data not supported");
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("'listener' cannot be null");
        }

        synchronized (listeners) {
            listeners.add(listener);
        }
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("'listener' cannot be null");
        }
        synchronized (listeners) {
            if (!listeners.remove(listener)) {
                throw new IllegalArgumentException("'listener' is not registered");
            }
        }
    }

    // javax.net.ssl.SSLSocket lets a caller install an ALPN selector. WrappedSocket consults it when
    // it builds its server; javax.net.ssl.SSLSocket documents that the selector has no effect unless
    // the socket is the server end of the connection, so on a client socket this only stores and
    // reports the value.
    private BiFunction<SSLSocket, List<String>, String> applicationProtocolSelector;

    @Override
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return applicationProtocolSelector;
    }

    @Override
    public void setHandshakeApplicationProtocolSelector(BiFunction<SSLSocket, List<String>, String> selector) {
        applicationProtocolSelector = selector;
    }

    /**
     * SSLParameters on our sockets carries one policy on every surface: a non-null bundle never throws
     * and moves the two knobs a PSK handshake reads into the enabled sets, so names this socket does
     * not support fail the way setEnabledCipherSuites()/setEnabledProtocols() do. A component the
     * bundle does not set leaves that set alone, as javax.net.ssl.SSLSocket documents for incomplete
     * bundles; the fields that describe certificate-authenticated connections (peer/host
     * identification, retransmissions, ticket bits) have no meaning for a PSK connection, so a
     * handshake never consults them.
     */
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

    protected void notifyHandshakeCompleted(HandshakeCompletedEvent event) {
        List<HandshakeCompletedListener> snapshot;
        synchronized (listeners) {
            snapshot = new ArrayList<HandshakeCompletedListener>(listeners);
        }
        // Listeners run outside the lock: a listener may add or remove listeners while being notified.
        // Their failures are contained per listener: this only runs once the handshake completed, so
        // user code in a listener must not turn that completed handshake into a failed accessor call,
        // and one throwing listener must not hide the listeners registered after it. javax.net.ssl.SSLSocket
        // has no channel for reporting such a failure either.
        for (HandshakeCompletedListener listener : snapshot) {
            try {
                listener.handshakeCompleted(event);
            } catch (Throwable listenerFailure) {
                // Best-effort hook: nothing a listener does can undo the completed handshake.
            }
        }
    }

    @Override
    public String toString() {
        return "WrappedSSL" + socket.toString();
    }
}
