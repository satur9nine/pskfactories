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
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.TlsCloseable;
import org.bouncycastle.tls.TlsServer;

/**
 * Wraps one Socket with another Socket but redirects IO to provided parameter
 * streams to allow for TLS implementation to process the data moving through
 * the Socket.
 * 
 * Handshaking is performed lazily on the first call to getInputStream, 
 * getOutputStream, or startHandshake.
 */
class WrappedSocket extends WrappedSSLSocket {

    private final TlsServer tlsServer;
    private final TlsCrypto crypto;
    private TlsCloseable protocol;
    private InputStream in;
    private OutputStream out;

    public WrappedSocket(Socket socket, TlsServer tlsServer, TlsCrypto crypto) throws IOException {
        super(socket);
        this.tlsServer = tlsServer;
        this.crypto = crypto;
    }

    private synchronized void ensureHandshake() throws IOException {
        if (protocol != null) {
            return;
        }

        BcPskSSLServerSocketFactory.BcPskTlsServerProtocol tlsProtocol = 
                new BcPskSSLServerSocketFactory.BcPskTlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
        tlsProtocol.accept(tlsServer);
        this.protocol = tlsProtocol;
        this.in = tlsProtocol.getInputStream();
        this.out = tlsProtocol.getOutputStream();
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
        } catch (Exception e) {
            // Ignore
        }
        super.close();
    }

    @Override
    public String toString() {
        return "Wrapped" + socket.toString();
    }

    @Override
    public boolean getEnableSessionCreation() {
        return true;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {}

    @Override
    public String[] getEnabledCipherSuites() {
        return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] cipherSuites) {}

    @Override
    public String[] getEnabledProtocols() {
        return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {}

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
        return new String[0];
    }

    @Override
    public String[] getSupportedProtocols() {
        return new String[0];
    }

    @Override
    public javax.net.ssl.SSLSession getSession() {
        return null;
    }

    @Override
    public void setUseClientMode(boolean mode) {}

    @Override
    public boolean getUseClientMode() {
        return false;
    }
}
