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

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.ProtocolName;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsSession;
import javax.net.ssl.SSLParameters;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides basic conversion methods and specifies supported cipher suites and TLS protocol
 * versions. Only TLS 1.2 and TLS 1.3 are accepted: SSLv3, TLS 1.0 and TLS 1.1 - and the DTLS
 * versions - are refused by the constructors. If older/unusual cipher suites are to be used
 * some internal methods here will need to be expanded.
 */
public class BcPskTlsParams {

    // Default policy: AEAD suites only. Bouncy Castle's own PSKTlsClient defaults are CBC/SHA-1
    // heavy, so the supported set here is narrowed to the TLS 1.2 ECDHE-PSK AEAD suites and the
    // TLS 1.3 AEAD suites; the CBC names the map below still carries are opt-in only.
    private static final int[] defaultSupportedCipherSuiteCodes = new int[] {
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
    };

    private static final ProtocolVersion[] defaultSupportedProtocolVersions = new ProtocolVersion[] {
            ProtocolVersion.TLSv13,
            ProtocolVersion.TLSv12,
    };

    private static final Comparator<ProtocolVersion> protocolComparator = (o1, o2) -> {
        if (o1.equals(o2)) {
            return 0;
        } else if (o1.isEarlierVersionOf(o2)) {
            return 1;
        }
        return -1;
    };

    private final ProtocolVersion[] supportedProtocolVersions;
    private final int[] supportedCipherSuiteCodes;
    private final String[] supportedCipherSuites;
    private final String[] supportedProtocols;
    private final int sessionTimeout;
    private final String[] applicationProtocols;
    private static final int DEFAULT_SESSION_TIMEOUT = 0; // No timeout by default

    /**
     * Create an instance that supports TLSv1.2 and TLSv1.3 with the following cipher suites:
     * <pre>
     * TLS_AES_128_GCM_SHA256,
     * TLS_AES_256_GCM_SHA384,
     * TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
     * TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
     * TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
     * </pre>
     */
    public BcPskTlsParams() {
        this(defaultSupportedProtocolVersions, defaultSupportedCipherSuiteCodes, DEFAULT_SESSION_TIMEOUT, new String[0]);
    }

    /**
     * Create an instance that supports TLSv1.2 and TLSv1.3 with the following cipher suites:
     * <pre>
     * TLS_AES_128_GCM_SHA256,
     * TLS_AES_256_GCM_SHA384,
     * TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
     * TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
     * TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
     * </pre>
     * @param sessionTimeout The session timeout in milliseconds. 0 or negative means no timeout.
     */
    public BcPskTlsParams(int sessionTimeout) {
        this(defaultSupportedProtocolVersions, defaultSupportedCipherSuiteCodes, sessionTimeout, new String[0]);
    }

    /**
     * Create an instance that supports the given protocol versions and cipher suites. It is up to
     * the caller to ensure the given cipher suites are compatible with the given protocol versions
     * (i.e.: if TLSv1.2 only is given then only TLSv1.2 cipher suites must be given).
     */
    public BcPskTlsParams(ProtocolVersion[] supportedProtocolVersions, int[] supportedCipherSuiteCodes) {
        this(supportedProtocolVersions, supportedCipherSuiteCodes, DEFAULT_SESSION_TIMEOUT, new String[0]);
    }

    /**
     * Create an instance that supports the given protocol versions and cipher suites. It is up to
     * the caller to ensure the given cipher suites are compatible with the given protocol versions
     * (i.e.: if TLSv1.2 only is given then only TLSv1.2 cipher suites must be given).
     *
     * @param supportedProtocolVersions Supported TLS protocol versions.
     * @param supportedCipherSuiteCodes Supported cipher suite codes.
     * @param sessionTimeout The session timeout in milliseconds. 0 or negative means no timeout.
     */
    public BcPskTlsParams(ProtocolVersion[] supportedProtocolVersions, int[] supportedCipherSuiteCodes, int sessionTimeout) {
        this(supportedProtocolVersions, supportedCipherSuiteCodes, sessionTimeout, new String[0]);
    }

    /**
     * Create an instance that supports the given protocol versions, cipher suites, and application protocols.
     *
     * @param supportedProtocolVersions Supported TLS protocol versions; SSLv3, TLS 1.0 and TLS 1.1 are refused.
     * @param supportedCipherSuiteCodes Supported cipher suite codes.
     * @param sessionTimeout The session timeout in milliseconds. 0 or negative means no timeout.
     * @param applicationProtocols Supported application protocols (ALPN). Names must be unique,
     * non-empty, printable ASCII, and at most 255 octets. Violations throw IllegalArgumentException.
     */
    public BcPskTlsParams(ProtocolVersion[] supportedProtocolVersions, int[] supportedCipherSuiteCodes, int sessionTimeout, String[] applicationProtocols) {
        requireSecureProtocolVersions(supportedProtocolVersions);
        this.supportedProtocolVersions = sortHighestFirst(supportedProtocolVersions);
        this.supportedCipherSuiteCodes = supportedCipherSuiteCodes.clone();
        this.supportedCipherSuites = cipherSuiteCodesToStrings(supportedCipherSuiteCodes);
        this.supportedProtocols = protocolVersionsToStrings(supportedProtocolVersions);
        this.sessionTimeout = sessionTimeout;
        this.applicationProtocols = validateApplicationProtocols(applicationProtocols);
    }

    /**
     * Named alternatives to the positional four-argument constructor. The instance is immutable so
     * each returns a new one; use these where the positional form would put two ints or two arrays
     * side by side.
     */
    public BcPskTlsParams withSupportedProtocolVersions(ProtocolVersion[] versions) {
        return new BcPskTlsParams(versions, supportedCipherSuiteCodes, sessionTimeout, applicationProtocols);
    }

    public BcPskTlsParams withSupportedCipherSuites(int[] cipherSuiteCodes) {
        return new BcPskTlsParams(supportedProtocolVersions, cipherSuiteCodes, sessionTimeout, applicationProtocols);
    }

    public BcPskTlsParams withSessionTimeout(int timeoutMillis) {
        return new BcPskTlsParams(supportedProtocolVersions, supportedCipherSuiteCodes, timeoutMillis, applicationProtocols);
    }

    public BcPskTlsParams withApplicationProtocols(String[] names) {
        return new BcPskTlsParams(supportedProtocolVersions, supportedCipherSuiteCodes, sessionTimeout, names);
    }

    /**
     * ALPN names are 1-255 printable ASCII octets on the wire (RFC 7301). Rejecting bad names here turns
     * a confusing no_application_protocol alert from the peer into a construction-time error. The TLS 1.2
     * or later requirement needs no check here: requireSecureProtocolVersions refuses older versions.
     */
    private static String[] validateApplicationProtocols(String[] protocols) {
        if (protocols == null) {
            return new String[0];
        }

        for (int i = 0; i < protocols.length; i++) {
            String name = protocols[i];
            if (name == null || name.isEmpty()) {
                throw new IllegalArgumentException("Application protocol name at index " + i + " is empty");
            }
            if (name.length() > 255) {
                throw new IllegalArgumentException("Application protocol name \"" + name + "\" exceeds the 255-octet ALPN limit");
            }
            for (int c = 0; c < name.length(); c++) {
                char ch = name.charAt(c);
                if (ch < 0x21 || ch > 0x7E) {
                    throw new IllegalArgumentException("Application protocol name \"" + name
                            + "\" contains a character outside printable ASCII");
                }
            }
            for (int j = 0; j < i; j++) {
                if (name.equals(protocols[j])) {
                    throw new IllegalArgumentException("Duplicate application protocol name \"" + name + "\"");
                }
            }
        }

        return Arrays.copyOf(protocols, protocols.length);
    }

    /**
     * Only TLS 1.2 and TLS 1.3 are allowed. The JDK's javax/net/ssl/SSLSocket.java#getSupportedProtocols()
     * also offers SSLv3, TLSv1 and TLSv1.1, but their CBC + HMAC record path carries the BEAST/BREACH/RFC
     * 44782 attacks this library cannot switch off, so an unsafe version must not be configurable through
     * the factory at all: refusing it at construction leaves nothing for a socket to negotiate. The list is
     * an allow-list rather than an age test so the DTLS versions stay out too - they
     * belong to java.dtls.* and have no javax/net/ssl/SSLSocket.java name.
     */
    private static void requireSecureProtocolVersions(ProtocolVersion[] versions) {
        for (ProtocolVersion version : versions) {
            if (!version.equals(ProtocolVersion.TLSv12) && !version.equals(ProtocolVersion.TLSv13)) {
                throw new IllegalArgumentException("TLS protocol versions other than TLS 1.2 and TLS 1.3 are not supported"
                        + ", offending version = " + version);
            }
        }
    }

    // javax/net/ssl/SSLSocket.java#getSupportedProtocols(), javax/net/ssl/SSLSocket.java#getEnabledProtocols()
    // and javax/net/ssl/SSLSocket.java#setEnabledProtocols() speak the standard protocol names, and
    // javax/net/ssl/SSLSession.java#getProtocol() answers with one of them ("the standard name of the
    // protocol used for all connections in the session"). Only TLSv1.2/TLSv1.3 names can come out of here:
    // requireSecureProtocolVersions refuses SSLv3, TLS 1.0 and TLS 1.1, so the JDK's older names ("SSLv3",
    // "TLSv1", "TLSv1.1") are never reported, and the OpenSSL-style "TLSv1.0" spelling is not the JDK's name.
    public static String toJavaName(ProtocolVersion version) {
        switch (version.getFullVersion()) {
            case 0x0303:
                return "TLSv1.2";
            case 0x0304:
                return "TLSv1.3";
        }

        throw new IllegalArgumentException("Unable to get java name for: " + version);
    }

    public static ProtocolVersion fromJavaName(String version) {
        switch (version) {
            case "TLSv1.2":
                return ProtocolVersion.TLSv12;
            case "TLSv1.3":
                return ProtocolVersion.TLSv13;
            case "SSLv3":
            case "TLSv1":
            case "TLSv1.0":
            case "TLSv1.1":
                throw new IllegalArgumentException("SSLv3, TLS 1.0 and TLS 1.1 are not supported: use TLSv1.2 or TLSv1.3");
        }

        throw new IllegalArgumentException("Unable to get protocol version for: " + version);
    }

    private static final HashMap<String, Integer> suiteToCodeMap = new HashMap<>();
    private static final HashMap<Integer, String> codeToSuiteMap = new HashMap<>();

    static {
        // JSSE suite names to Bouncy Castle's integer codes, tabulated from the constants in
        // org/bouncycastle/tls/CipherSuite.java. A name left out here is refused by
        // fromCipherSuiteString, never negotiated.
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_128_CBC_SHA", 0x0090);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", 0x00AA);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", 0x00AB);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", 0x00B2);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", 0x00B3);
        suiteToCodeMap.put("TLS_AES_128_GCM_SHA256", 0x1301);
        suiteToCodeMap.put("TLS_AES_256_GCM_SHA384", 0x1302);
        suiteToCodeMap.put("TLS_CHACHA20_POLY1305_SHA256", 0x1303);
        suiteToCodeMap.put("TLS_AES_128_CCM_SHA256", 0x1304);
        suiteToCodeMap.put("TLS_AES_128_CCM_8_SHA256", 0x1305);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 0xC035);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", 0xC037);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xCCAC);
        suiteToCodeMap.put("TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 0xCCAD);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", 0xD001);
        suiteToCodeMap.put("TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384", 0xD002);

        for (Map.Entry<String, Integer> entry : suiteToCodeMap.entrySet()) {
            codeToSuiteMap.put(entry.getValue(), entry.getKey());
        }
    }

    public static String toCipherSuiteString(int code) {
        String suite = codeToSuiteMap.get(code);
        if (suite == null) {
            throw new IllegalArgumentException("Unsupported TLS cipher code: " + code);
        } else {
            return suite;
        }
    }

    public static int fromCipherSuiteString(String name) {
        Integer code = suiteToCodeMap.get(name);
        if (code == null) {
            throw new IllegalArgumentException("Unsupported TLS cipher: " + name);
        } else {
            return code;
        }
    }

    private static String[] protocolVersionsToStrings(ProtocolVersion[] versions) {
        String[] protocolStrings = new String[versions.length];
        for (int i = 0; i < versions.length; i++) {
            protocolStrings[i] = toJavaName(versions[i]);
        }
        return protocolStrings;
    }

    private static String[] cipherSuiteCodesToStrings(int[] codes) {
        String[] suiteStrings = new String[codes.length];
        for (int i = 0; i < codes.length; i++) {
            suiteStrings[i] = toCipherSuiteString(codes[i]);
        }
        return suiteStrings;
    }

    public String[] getSupportedCipherSuites() {
        return supportedCipherSuites.clone();
    }

    public String[] getSupportedProtocols() {
        return supportedProtocols.clone();
    }

    public int[] getSupportedCipherSuiteCodes() {
        return supportedCipherSuiteCodes.clone();
    }

    public int getSessionTimeout() {
        return sessionTimeout;
    }

    public String[] getApplicationProtocols() {
        return applicationProtocols.clone();
    }

    public ProtocolVersion[] getSupportedProtocolVersions() {
        return supportedProtocolVersions.clone();
    }

    public static int[] fromSupportedCipherSuiteCodes(String[] jsseCipherSuites) {
        int[] cipherSuiteCodes = new int[jsseCipherSuites.length];
        for (int i = 0; i < jsseCipherSuites.length; i++) {
            cipherSuiteCodes[i] = fromCipherSuiteString(jsseCipherSuites[i]);
        }
        return cipherSuiteCodes;
    }

    public static ProtocolVersion[] fromSupportedProtocolVersions(String[] jsseProtocols) {
        ProtocolVersion[] protocolVersions = new ProtocolVersion[jsseProtocols.length];
        for (int i = 0; i < jsseProtocols.length; i++) {
            protocolVersions[i] = fromJavaName(jsseProtocols[i]);
        }
        return protocolVersions;
    }

    /**
     * Bouncy Castle breaks if TLSv1.2 is listed earlier than TLSv1.3, so every ProtocolVersion[]
     * handed to it is ordered highest version first.
     */
    public static ProtocolVersion[] sortHighestFirst(ProtocolVersion[] versions) {
        ProtocolVersion[] sorted = versions.clone();
        Arrays.sort(sorted, protocolComparator);
        return sorted;
    }

    /**
     * setEnabled* rejects names the socket does not support, so a typo fails at the call instead of
     * silently leaving the enabled set unchanged. A null list means nothing is enabled.
     */
    public static String[] requireSupported(String[] requested, String[] supported, String kind) {
        if (requested == null) {
            return new String[0];
        }
        String[] result = requested.clone();
        for (String name : result) {
            boolean found = false;
            for (String candidate : supported) {
                if (candidate.equals(name)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new IllegalArgumentException("'" + name + "' is not a supported " + kind);
            }
        }
        return result;
    }

    /**
     * The negotiated-state accessors, shared by BcPskTlsServerProtocol and BcPskTlsClientProtocol:
     * both ends read the same thing out of the Bouncy Castle context they were given, and report
     * null until that state exists.
     */
    public static String getCipherSuite(TlsContext context) {
        if (context == null) {
            return null;
        }
        return toCipherSuiteString(context.getSecurityParameters().getCipherSuite());
    }

    public static String getProtocol(TlsContext context) {
        if (context == null) {
            return null;
        }
        return toJavaName(context.getSecurityParameters().getNegotiatedVersion());
    }

    public static byte[] getSessionId(TlsContext context) {
        if (context == null) {
            return null;
        }
        TlsSession session = context.getSession();
        if (session == null) {
            return null;
        }
        return session.getSessionID();
    }

    /**
     * The ALPN outcome, with the JDK's three states: null while it is still unknown whether
     * application protocols will be used (no context yet, or the server's hello has not been read),
     * "" once the connection decided not to use one, and the negotiated name when the server
     * answered the client's offer. Callers that only ask "was a protocol chosen" should test for a
     * non-empty string rather than comparing against null.
     */
    public static String getApplicationProtocol(TlsContext context) {
        if (context == null) {
            return null;
        }
        SecurityParameters securityParameters = context.getSecurityParametersConnection();
        if (null == securityParameters || !securityParameters.isApplicationProtocolSet()) {
            return null;
        }
        ProtocolName applicationProtocol = securityParameters.getApplicationProtocol();
        if (null == applicationProtocol) {
            return "";
        }
        return applicationProtocol.getUtf8Decoding();
    }

    /**
     * What a socket reports as its SSLParameters: the three knobs a PSK handshake actually reads —
     * the enabled cipher suites, the enabled protocol versions, and the ALPN names the socket offers.
     * The remaining SSLParameters fields (peer/host identification, retransmissions, ticket bits)
     * describe connections authenticated by certificates, so they are left unset here.
     */
    public static SSLParameters fromEnabledState(String[] enabledCipherSuites, String[] enabledProtocols,
                                                 String[] applicationProtocols, boolean useCipherSuitesOrder) {
        SSLParameters sslParameters = new SSLParameters();
        sslParameters.setCipherSuites(enabledCipherSuites);
        sslParameters.setProtocols(enabledProtocols);
        sslParameters.setApplicationProtocols(applicationProtocols);
        sslParameters.setUseCipherSuitesOrder(useCipherSuitesOrder);
        return sslParameters;
    }
}
