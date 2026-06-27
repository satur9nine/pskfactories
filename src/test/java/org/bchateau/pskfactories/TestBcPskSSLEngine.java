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

import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;
import java.io.IOException;
import java.nio.Buffer;


// Test the BcPskSSLEngine without third-party client/server libraries
public class TestBcPskSSLEngine {

   @Test
    public void testSslEngineDrivesNonBlockingPskHandshake() throws IOException {
        BcPskTlsParams params = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                new String[] { "h2" });

        TlsPSKIdentityManager serverMgr = TesterSupport.createTestTlsPSKIdentityManager();
        BcPskSSLServerSocketFactory serverFactory = new BcPskSSLServerSocketFactory(params, serverMgr);
        BasicTlsPSKIdentity clientIdentity = new BasicTlsPSKIdentity(TesterSupport.ID_1, TesterSupport.KEY_1);
        BcPskSSLSocketFactory clientFactory = new BcPskSSLSocketFactory(params, clientIdentity);

        SSLEngine clientEngine = new BcPskSSLEngine(clientFactory, "localhost", 443);
        SSLEngine serverEngine = new BcPskSSLEngine(serverFactory, "localhost", 443);
        clientEngine.setUseClientMode(true);
        serverEngine.setUseClientMode(false);
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        // The two inboxes hold wire bytes one engine produced and its peer has not read yet; the
        // application-data buffers are what each end receives from unwrap().
        ByteBuffer toServer = ByteBuffer.allocate(65536);
        ByteBuffer toClient = ByteBuffer.allocate(65536);
        toServer.limit(0);
        toClient.limit(0);

        driveHandshakeToCompletion(clientEngine, serverEngine);
        Assertions.assertEquals("h2", clientEngine.getApplicationProtocol(),
                "client engine reports negotiated ALPN");
        Assertions.assertEquals("h2", serverEngine.getApplicationProtocol(),
                "server engine reports negotiated ALPN");
    }

    /*
     * A record the peer's inbox only partly supplies must be held back: unwrap() reports
     * BUFFER_UNDERFLOW, consumes nothing, and the same inbox later yields the whole record exactly
     * once - so a stalled wire transfer neither loses bytes nor replays them.
     */
    @Test
    public void testEngineHoldsBackAnIncompleteRecord() throws IOException {
        SSLEngine[] pair = enginePair(tls12PskParams(new String[] { "h2" }));
        SSLEngine clientEngine = pair[0];
        SSLEngine serverEngine = pair[1];
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        ByteBuffer toServer = ByteBuffer.allocate(65536);
        toServer.limit(0);
        Assertions.assertTrue(pumpWireBytes(clientEngine, ByteBuffer.allocate(0), toServer),
                "the initiating engine must put its handshake record on the wire");
        int wholeRecord = toServer.limit();

        ByteBuffer applicationData = ByteBuffer.allocate(65536);
        ByteBuffer[] destinations = new ByteBuffer[] { applicationData };
        toServer.limit(4);
        ((Buffer) toServer).position(0);
        SSLEngineResult underflow = serverEngine.unwrap(toServer, destinations, 0, 1);
        Assertions.assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW, underflow.getStatus(),
                "a partial record header must not be interpreted");
        Assertions.assertEquals(0, underflow.bytesConsumed(), "unwrap() consumes no bytes on BUFFER_UNDERFLOW");
        Assertions.assertEquals(4, toServer.limit(), "the withheld bytes stay in the inbox");

        toServer.limit(wholeRecord);
        SSLEngineResult consumed = serverEngine.unwrap(toServer, destinations, 0, 1);
        Assertions.assertEquals(wholeRecord, consumed.bytesConsumed(),
                "the whole record is consumed exactly once");
    }

    /*
     * wrap() must never split a record and never take application data it cannot fit: a cramped
     * destination reports BUFFER_OVERFLOW with the payload untouched, and the retry with room
     * moves the same bytes on. The peer then receives the payload byte for byte.
     */
    @Test
    public void testEngineRefusesToSplitARecordOutOfTooSmallABuffer() throws IOException {
        SSLEngine[] pair = enginePair(tls12PskParams(new String[] { "h2" }));
        SSLEngine clientEngine = pair[0];
        SSLEngine serverEngine = pair[1];
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        ByteBuffer[] noApplicationData = new ByteBuffer[] { ByteBuffer.allocate(0) };
        ByteBuffer cramped = ByteBuffer.allocate(32);
        SSLEngineResult crampedResult = clientEngine.wrap(noApplicationData, 0, 1, cramped);
        Assertions.assertEquals(SSLEngineResult.Status.BUFFER_OVERFLOW, crampedResult.getStatus(),
                "a handshake record larger than the destination must be refused");
        Assertions.assertEquals(0, crampedResult.bytesProduced(), "no partial record is emitted");
        Assertions.assertEquals(0, cramped.position(), "the refused call writes nothing");

        driveHandshakeToCompletion(clientEngine, serverEngine);

        byte[] payload = new byte[1000];
        for (int i = 0; i < payload.length; ++i) {
            payload[i] = (byte) i;
        }
        ByteBuffer source = ByteBuffer.allocate(1000);
        source.put(payload);
        source.position(0);

        ByteBuffer tooSmall = ByteBuffer.allocate(500);
        SSLEngineResult overflow = clientEngine.wrap(new ByteBuffer[] { source }, 0, 1, tooSmall);
        Assertions.assertEquals(SSLEngineResult.Status.BUFFER_OVERFLOW, overflow.getStatus(),
                "an application data record larger than the destination must be refused");
        Assertions.assertEquals(0, overflow.bytesConsumed(), "the refused call consumes no application data");
        Assertions.assertEquals(0, source.position(), "the payload stays unread for the next wrap()");

        ByteBuffer inbox = ByteBuffer.allocate(65536);
        inbox.limit(0);
        Assertions.assertTrue(pumpWireBytes(clientEngine, source, inbox),
                "the retry with room must move the payload");

        ByteBuffer serverApplicationData = ByteBuffer.allocate(8192);
        Assertions.assertTrue(feedRecords(serverEngine, inbox, serverApplicationData),
                "the peer reads the record the engine sent");
        byte[] received = new byte[payload.length];
        serverApplicationData.position(0);
        serverApplicationData.get(received);
        Assertions.assertArrayEquals(payload, received, "the payload must survive the record layer byte for byte");
    }

    /*
     * closeOutbound() only closes the outbound half; the buffered close_notify alert still has to
     * be flushed with wrap() before isOutboundDone() answers true, and the peer's isInboundDone()
     * turns true only once it has read that alert.
     */
    @Test
    public void testEngineFlushesCloseNotifyBeforeReportingDone() throws IOException {
        SSLEngine[] pair = enginePair(tls12PskParams(new String[] { "h2" }));
        SSLEngine clientEngine = pair[0];
        SSLEngine serverEngine = pair[1];
        driveHandshakeToCompletion(clientEngine, serverEngine);

        clientEngine.closeOutbound();
        Assertions.assertFalse(clientEngine.isOutboundDone(),
                "the close_notify alert is still buffered when the half closes");
        ByteBuffer toServer = ByteBuffer.allocate(65536);
        toServer.limit(0);
        Assertions.assertTrue(pumpWireBytes(clientEngine, ByteBuffer.allocate(0), toServer),
                "close_notify must be flushable with wrap()");
        Assertions.assertTrue(clientEngine.isOutboundDone(),
                "outbound is done once the alert bytes left");

        ByteBuffer serverApplicationData = ByteBuffer.allocate(65536);
        Assertions.assertTrue(feedRecords(serverEngine, toServer, serverApplicationData),
                "the peer reads the close_notify alert");
        Assertions.assertEquals(0, toServer.limit(), "the inbox holds nothing after the alert");
        Assertions.assertTrue(serverEngine.isInboundDone(),
                "the peer's inbound stream is closed by the alert");

        serverEngine.closeOutbound();
        ByteBuffer toClient = ByteBuffer.allocate(65536);
        toClient.limit(0);
        Assertions.assertTrue(pumpWireBytes(serverEngine, ByteBuffer.allocate(0), toClient),
                "the peer's close_notify must be flushable too");
        ByteBuffer clientApplicationData = ByteBuffer.allocate(65536);
        Assertions.assertTrue(feedRecords(clientEngine, toClient, clientApplicationData),
                "the initiating engine reads its peer's alert");
        Assertions.assertTrue(clientEngine.isInboundDone(), "both inbound halves report done");
        clientEngine.closeInbound();
        Assertions.assertTrue(clientEngine.isInboundDone(), "closeInbound() is idempotent");
    }

    /*
     * Ends that share no cipher suite must still report the rejection instead of swallowing it:
     * unwrap() throws the record layer's handshake_failure, and the rejecting engine's alert stays
     * queued so its next wrap() carries it to the peer, which reports that alert as its own
     * rejection and closes both halves.
     */
    @Test
    public void testEngineThrowsAndStillFlushesTheAlertForAMissingCipherSuite() throws IOException {
        BcPskTlsParams clientParams = tls12PskParams(new String[] { "h2" });
        BcPskTlsParams serverParams = new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 },
                0,
                new String[] { "h2" });
        SSLEngine clientEngine = new BcPskSSLEngine(
                new BcPskSSLSocketFactory(clientParams, new BasicTlsPSKIdentity(TesterSupport.ID_1, TesterSupport.KEY_1)), "localhost", 443);
        SSLEngine serverEngine = new BcPskSSLEngine(
                new BcPskSSLServerSocketFactory(serverParams, TesterSupport.createTestTlsPSKIdentityManager()), "localhost", 443);
        clientEngine.setUseClientMode(true);
        serverEngine.setUseClientMode(false);
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        ByteBuffer toServer = ByteBuffer.allocate(65536);
        toServer.limit(0);
        Assertions.assertTrue(pumpWireBytes(clientEngine, ByteBuffer.allocate(0), toServer),
                "the offering engine still puts its client_hello on the wire");

        SSLException rejection = null;
        try {
            feedRecords(serverEngine, toServer, ByteBuffer.allocate(65536));
        } catch (SSLException e) {
            rejection = e;
        }
        Assertions.assertNotNull(rejection,
                "a client_hello offering no selectable suite must be refused at unwrap()");
        Assertions.assertTrue(rejection.getMessage().contains("handshake_failure(40)"),
                "the refusal names the fatal alert the record layer raised: " + rejection.getMessage());
        Assertions.assertTrue(serverEngine.isInboundDone(), "the refusing engine's inbound half is done");
        Assertions.assertFalse(serverEngine.isOutboundDone(),
                "the refusal leaves its alert queued for wrap()");

        ByteBuffer toClient = ByteBuffer.allocate(65536);
        toClient.limit(0);
        Assertions.assertTrue(pumpWireBytes(serverEngine, ByteBuffer.allocate(0), toClient),
                "wrap() moves the queued alert once unwrap() refused the record");
        byte[] flushed = new byte[toClient.limit()];
        ((Buffer) toClient).position(0);
        toClient.get(flushed);
        Assertions.assertEquals((byte) 0x15, flushed[0], "the flushed record is an alert record");
        Assertions.assertTrue(serverEngine.isOutboundDone(), "outbound is done once the alert left");

        SSLException peerVerdict = null;
        try {
            feedRecords(clientEngine, toClient, ByteBuffer.allocate(65536));
        } catch (SSLException e) {
            peerVerdict = e;
        }
        Assertions.assertNotNull(peerVerdict,
                "the offering engine reports its peer's fatal alert as an SSLException");
        Assertions.assertTrue(peerVerdict.getMessage().contains("handshake_failure(40)"),
                "the alert the offering engine reads is the peer's handshake_failure: "
                        + peerVerdict.getMessage());
        Assertions.assertTrue(clientEngine.isInboundDone() && clientEngine.isOutboundDone(),
                "both halves of the offering engine close once the alert crossed");
        Assertions.assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, clientEngine.getHandshakeStatus(),
                "a failed handshake leaves the offering engine not handshaking");
        Assertions.assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, serverEngine.getHandshakeStatus(),
                "a failed handshake leaves the refusing engine not handshaking");
    }

    /*
     * A record whose AEAD tag fails to verify must never reach the application buffer: unwrap()
     * throws, the bad record is not replayed, and the bad_record_mac alert the engine queued is
     * still flushable with its next wrap().
     */
    @Test
    public void testEngineRefusesARecordWhoseAuthenticationTagFails() throws IOException {
        SSLEngine[] pair = enginePair(tls12PskParams(new String[] { "h2" }));
        SSLEngine clientEngine = pair[0];
        SSLEngine serverEngine = pair[1];
        driveHandshakeToCompletion(clientEngine, serverEngine);

        ByteBuffer source = ByteBuffer.allocate(24);
        for (int i = 0; i < source.capacity(); ++i) {
            source.put((byte) ('a' + i));
        }

        ((Buffer) source).position(0);
        ByteBuffer toServer = ByteBuffer.allocate(65536);
        toServer.limit(0);
        Assertions.assertTrue(pumpWireBytes(clientEngine, source, toServer),
                "the application record reaches the wire");
        int recordBytes = toServer.limit();
        byte[] wire = new byte[recordBytes];
        ((Buffer) toServer).position(0);
        toServer.get(wire);

        byte[] tampered = wire.clone();
        tampered[recordBytes - 1] = (byte) (tampered[recordBytes - 1] ^ 0x01);
        ByteBuffer inbox = ByteBuffer.allocate(65536);
        inbox.put(tampered);

        ByteBuffer applicationData = ByteBuffer.allocate(65536);
        SSLException refusal = null;
        try {
            feedRecords(serverEngine, inbox, applicationData);
        } catch (SSLException e) {
            refusal = e;
        }
        Assertions.assertNotNull(refusal, "a record whose tag check fails must not be accepted");
        Assertions.assertTrue(refusal.getMessage().contains("bad_record_mac(20)"),
                "the refusal names the fatal alert the tag check raised: " + refusal.getMessage());
        Assertions.assertEquals(0, applicationData.position(),
                "no plaintext reaches the application buffer");

        Assertions.assertTrue(serverEngine.isInboundDone(), "the refused record closes the inbound half");
        ByteBuffer drained = ByteBuffer.allocate(65536);
        drained.limit(0);
        Assertions.assertTrue(pumpWireBytes(serverEngine, ByteBuffer.allocate(0), drained),
                "wrap() flushes the queued bad_record_mac alert");
        byte[] alertRecord = new byte[drained.limit()];
        ((Buffer) drained).position(0);
        drained.get(alertRecord);
        Assertions.assertEquals((byte) 0x15, alertRecord[0], "the flushed record is an alert record");
        Assertions.assertTrue(serverEngine.isOutboundDone(),
                "outbound is done once the alert left");
        Assertions.assertFalse(pumpWireBytes(serverEngine, ByteBuffer.allocate(0), drained),
                "a second wrap() has nothing left to flush");
    }

    /*
     * Only the server end consults a selector, and it must see the names the client offered: the
     * name it returns is what both ends report as the negotiated application protocol.
     */
    @Test
    public void testEngineAlpnSelectorChoosesTheNameBothEndsOffer() throws IOException {
        SSLEngine[] pair = enginePair(tls12PskParams(new String[] { "h2", "http/1.1" }));
        SSLEngine clientEngine = pair[0];
        SSLEngine serverEngine = pair[1];
        serverEngine.setHandshakeApplicationProtocolSelector(
                (engine, names) -> names.contains("http/1.1") ? "http/1.1" : null);
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();
        driveHandshakeToCompletion(clientEngine, serverEngine);

        Assertions.assertEquals("http/1.1", clientEngine.getApplicationProtocol(),
                "the client engine reports the name its peer selected");
        Assertions.assertEquals("http/1.1", serverEngine.getHandshakeApplicationProtocol(),
                "the server engine reports the name it selected");
    }

    /*
     * The session the engine hands out tracks the negotiated record state, and the ALPN names come
     * and go through SSLParameters, so a caller can replace them after construction.
     */
    @Test
    public void testEngineSessionSurfaceTracksTheNegotiatedState() throws IOException {
        SSLEngine[] pair = enginePair(tls12PskParams(new String[] { "h2" }));
        SSLEngine clientEngine = pair[0];
        SSLEngine serverEngine = pair[1];
        driveHandshakeToCompletion(clientEngine, serverEngine);

        SSLSession clientSession = clientEngine.getSession();
        Assertions.assertEquals("TLSv1.2", clientSession.getProtocol(),
                "the session reports the negotiated record version");
        Assertions.assertEquals("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", clientSession.getCipherSuite(),
                "the session reports the negotiated cipher suite");
        Assertions.assertEquals("localhost", clientSession.getPeerHost(),
                "the session names the peer the engine was built for");
        Assertions.assertEquals(443, clientSession.getPeerPort(),
                "the session names the peer port the engine was built for");
        Assertions.assertTrue(clientSession.isValid(),
                "a negotiated PSK session stays valid while its record layer is open");
        Assertions.assertNotNull(clientEngine.getHandshakeSession(),
                "the handshake session is readable once the handshake finished");

        SSLParameters policy = clientEngine.getSSLParameters();
        Assertions.assertEquals(1, policy.getApplicationProtocols().length,
                "getSSLParameters() carries the ALPN names this engine offers: "
                        + policy.getApplicationProtocols().length);
        Assertions.assertEquals("h2", policy.getApplicationProtocols()[0],
                "getSSLParameters() carries the ALPN name this engine offers");

        SSLParameters knob = new SSLParameters();
        knob.setApplicationProtocols(new String[] { "h3" });
        clientEngine.setSSLParameters(knob);
        Assertions.assertEquals("h3", clientEngine.getSSLParameters().getApplicationProtocols()[0],
                "setSSLParameters() must move the ALPN names the engine offers");
    }

    // Engine fixtures: every engine test negotiates the same TLS 1.2 PSK suite; only the ALPN
    // names it offers vary, so the parameter builder takes those.
    private static BcPskTlsParams tls12PskParams(String[] applicationProtocols) {
        return new BcPskTlsParams(
                new ProtocolVersion[] { ProtocolVersion.TLSv12 },
                new int[] { CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 },
                0,
                applicationProtocols);
    }

    // [client-mode engine, server-mode engine] wired to each other's address, with modes set but
    // no handshake begun, so a test can register an ALPN selector before it starts.
    private static SSLEngine[] enginePair(BcPskTlsParams params) {
        SSLEngine clientEngine = new BcPskSSLEngine(
                new BcPskSSLSocketFactory(params, new BasicTlsPSKIdentity(TesterSupport.ID_1, TesterSupport.KEY_1)), "localhost", 443);
        SSLEngine serverEngine = new BcPskSSLEngine(
                new BcPskSSLServerSocketFactory(params, TesterSupport.createTestTlsPSKIdentityManager()), "localhost", 443);
        clientEngine.setUseClientMode(true);
        serverEngine.setUseClientMode(false);
        return new SSLEngine[] { clientEngine, serverEngine };
    }

    // Shuttles each engine's wire bytes into its peer's inbox until both report a settled handshake.
    private static void driveHandshakeToCompletion(SSLEngine clientEngine, SSLEngine serverEngine)
            throws IOException {
        ByteBuffer toServer = ByteBuffer.allocate(65536);
        ByteBuffer toClient = ByteBuffer.allocate(65536);
        toServer.limit(0);
        toClient.limit(0);
        ByteBuffer clientReceived = ByteBuffer.allocate(65536);
        ByteBuffer serverReceived = ByteBuffer.allocate(65536);

        boolean completed = false;
        for (int round = 0; round < 64 && !completed; ++round) {
            boolean progress = false;
            progress |= pumpWireBytes(clientEngine, ByteBuffer.allocate(0), toServer);
            progress |= pumpWireBytes(serverEngine, ByteBuffer.allocate(0), toClient);
            progress |= feedRecords(serverEngine, toServer, serverReceived);
            progress |= feedRecords(clientEngine, toClient, clientReceived);
            completed = handshakeSettled(clientEngine) && handshakeSettled(serverEngine);
            if (!completed && !progress) {
                Assertions.fail("engine handshake stalled before completion");
            }
        }

        Assertions.assertTrue(completed, "SSLEngine handshake must complete in bounded rounds");
    }

    // Wraps what an engine wants to send and appends the produced wire bytes to its peer's inbox,
    // reporting whether any bytes moved. The application-data source is empty during a handshake.
    private static boolean pumpWireBytes(SSLEngine engine, ByteBuffer applicationData, ByteBuffer peerInbox)
            throws IOException {
        ByteBuffer[] sources = new ByteBuffer[] { applicationData };
        ByteBuffer output = ByteBuffer.allocate(65536);
        engine.wrap(sources, 0, sources.length, output);
        int produced = output.position();
        if (produced == 0) {
            return false;
        }
        byte[] wire = new byte[produced];
        ((Buffer) output).position(0);
        output.get(wire);
        int filled = peerInbox.limit();
        Buffer inbox = peerInbox;
        inbox.limit(filled + produced);
        inbox.position(filled);
        peerInbox.put(wire);
        return true;
    }

    // Unwraps one whole record from an inbox, compacting a partial record to the front so the next
    // pump can append to it, and reports whether the engine consumed any bytes.
    private static boolean feedRecords(SSLEngine engine, ByteBuffer inbox, ByteBuffer applicationData)
            throws IOException {
        if (inbox.limit() == 0) {
            return false;
        }
        ByteBuffer[] destinations = new ByteBuffer[] { applicationData };
        ((Buffer) inbox).position(0);
        engine.unwrap(inbox, destinations, 0, destinations.length);
        int consumed = inbox.position();
        int leftover = inbox.limit() - consumed;
        byte[] pending = new byte[leftover];
        inbox.get(pending);
        ((Buffer) inbox).position(0);
        inbox.limit(leftover);
        if (leftover > 0) {
            inbox.put(pending);
        }
        return consumed > 0;
    }

    private static boolean handshakeSettled(SSLEngine engine) {
        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
        return status == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                || status == SSLEngineResult.HandshakeStatus.FINISHED;
    }
}
