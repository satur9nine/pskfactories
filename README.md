# PSK JSSE Socket Factories powered by Bouncy Castle

As of version 1.78 the Bouncy Castle JSSE provider supplies only an SSLSocketFactory and SSLServerSocketFactory with support for authentication via certificates. There is, however, an alternative mode of authentication available in the TLS standard which is supplied through the use of pre-shared keys (see https://datatracker.ietf.org/doc/html/rfc4279).

Bouncy Castle supports TLS PSK client and server connections but only through a non-standardized API and not through its JSSE implementation. The classes in this project bridge the gap, offerring developers JSSE standard SSLSocketFactory and SSLServerSocketFactory classes that support PSK cipher suites powered by Bouncy Castle.

At this time only OkHttp (client) and NanoHTTPD (server) have been lightly tested with this implementation.

Only TLS 1.2 and TLS 1.3 are supported.

This project is written in standard Java, and supports Java 1.8+.

# Usage

To use one or both of these factories in your project do the following:

## Include Dependencies

Include the Bouncy Castle bctls library and transitive dependencies in your project. If you are using Gradle with an Android project for example you would add the following to your dependencies:

    implementation "org.bouncycastle:bctls-jdk18on:1.78"

See https://www.bouncycastle.org/latest_releases.html for other packaging options.

## Copy Implementation

This project is not distributed via Maven Central.

To use this implementation copy the org.bchateau.pskfactories source code from this repository into your project.

## Use

- See the `TestServerClientIntegration#runPskClient()` method for example client use
- See the `TestServerClientIntegration#startPskServer()` method for example server use

## Behaviour worth knowing

- Handshaking is lazy: the TLS handshake runs on the first call to `getInputStream()`,
  `getOutputStream()`, or `startHandshake()`, on whichever side reaches it first. Handshake-completed
  listeners fire at that point; a listener that throws fails neither that call nor the handshake it
  follows, and the listeners behind it still run. `startHandshake()` is idempotent — a second call after a
  handshake does nothing. A failed handshake closes the socket and every later call rethrows that
  IOException; the connection is consumed, as javax.net.ssl.SSLSocket documents.
- Exactly one handshake runs per socket, and `close()` stays callable while another thread is blocked
  in a stalled handshake. It also stays quiet: it reports no error where `javax.net.ssl.Socket.close()`
  reports none, so the with-scope cleanup that calls it cannot replace an exception the body was
  already raising. Concurrent reads and writes on the streams are the caller's job, as with
  `java.net.Socket`.
- `createSocket(Socket, host, port, autoClose)` layers TLS-PSK onto a socket you already connected, and
  `autoClose` carries `javax.net.ssl.SSLSocketFactory`'s meaning: closing the SSL socket closes that raw
  socket when the flag is `true` (every other `createSocket` overload here passes `true`), and leaves it
  open for the caller — tunneling, a proxy hand-off — when it is `false`. A socket that is not connected
  yet is rejected with `java.net.SocketException`, an `IOException`, so the declared `throws IOException`
  covers that rejection; a handshake that fails on a protocol error closes the raw connection either way,
  as `javax.net.ssl.SSLSocketFactory`'s layered constructor documents.
- The SSL layer keeps javadir `javax.net.ssl.SSLSocket`'s answer to `java.net.Socket`'s escape
  hatches: `connect()`/`bind()` cannot re-point it (javadir's `java/net/Socket.java#connect()` and
  `java/net/Socket.java#bind()` refuse an already-connected/already-bound socket with
  `java.net.SocketException`), `getChannel()` is `null` because `java/net/Socket.java#getChannel()` names a
  channel only for a socket opened through `java.nio.channels.SocketChannel`, and TCP urgent data is
  refused with `java.net.SocketException("Urgent data not supported")` - javadir's
  `java/net/Socket.java#sendUrgentData()` uses that class for an absent out-of-band channel, and
  `java/net/Socket.java#setOOBInline()`/`java/net/Socket.java#getOOBInline()` declare it for the option,
  so nothing escapes outside the declared types; a TCP urgent byte would reach the peer's record
  parser as record bytes. Each half of the connection shuts down once, quietly, the way JDK's layered
  socket does, so a repeat never leaks the "already shutdown" refusals `java/net/Socket.java#shutdownInput()`
  and `java/net/Socket.java#shutdownOutput()` name out of the raw socket, and `setSoTimeout()` reaches the
  record layer's reads, not the decrypted stream's. A TLS-clean hang-up is `close()`, which sends close_notify;
  `shutdownOutput()` half-closes TCP without the alert, as javadir says.
- `setEnabledCipherSuites()`/`setEnabledProtocols()` narrow what the next handshake may negotiate, on
  either side; the handshake is built from the enabled sets when it starts, so call them before
  `getInputStream()`/`getOutputStream()`/`startHandshake()`. An accepted socket inherits its server
  socket's sets. Names outside `getSupportedCipherSuites()`/`getSupportedProtocols()` throw
  `IllegalArgumentException` on every socket; a null list enables nothing.
- Only TLS 1.2 and TLS 1.3 are configurable. SSLv3, TLS 1.0 and TLS 1.1 are refused with
  `IllegalArgumentException` when the params object is built, so no socket here can ever negotiate them:
  their CBC + HMAC record path carries the BEAST/BREACH/RFC 44782 attacks this library cannot switch off,
  and javadir's `javax/net/ssl/SSLSocket.java#getSupportedProtocols()` table calling them supported is
  not this library's. A DTLS version is refused too - it belongs to `java.dtls.*` and has no
  `javax/net/ssl/SSLSocket.java` name. Protocol names on `getSupportedProtocols()`,
  `getEnabledProtocols()` and `setEnabledProtocols()` are javadir's own spellings from that table, and the
  negotiated name comes from `javax/net/ssl/SSLSession.java#getProtocol()` - javadir declares no
  `getProtocol()` on a socket, so nothing here reports the OpenSSL-style "TLSv1.0" spelling.
- `BcPskTlsParams` names the protocol versions, cipher suites, session timeout, and ALPN protocols both
  sides may use. The positional constructor takes four arguments; the named builders read better where
  two ints or two arrays would sit side by side:

      BcPskTlsParams params = new BcPskTlsParams()
              .withSupportedProtocolVersions(new ProtocolVersion[] { ProtocolVersion.TLSv13 })
              .withSupportedCipherSuites(new int[] { CipherSuite.TLS_AES_128_GCM_SHA256 })
              .withSessionTimeout(300000)
              .withApplicationProtocols(new String[] { "h2" });

- ALPN names are validated when the params object is built (1-255 printable ASCII octets, unique); the TLS
  1.2-or-later rule needs no check because only TLS 1.2 and TLS 1.3 are configurable. A bad name fails at
  construction rather than surfacing later as a
  `no_application_protocol` alert from the peer. Read the outcome with `getApplicationProtocol()`: `null`
  while it is still unknown whether application protocols will be used, `""` when the connection uses
  none, and the negotiated name (e.g. `"h2"`) when one was agreed.

- `setHandshakeApplicationProtocolSelector(selector)`/`getHandshakeApplicationProtocolSelector()` sit on
  every socket. A server-end socket consults its selector when the handshake builds the ALPN offer: the
  name it returns from the socket's names is the name offered (returning nothing offers none, so a peer
  that asked for ALPN gets `no_application_protocol`). On a client socket the selector is stored and
  reported only, which is what `javax.net.ssl.SSLSocket` documents.
- `getHandshakeSession()` is null until a handshake completes and the session itself afterwards;
  `getHandshakeApplicationProtocol()` on the socket carries the same three ALPN states as the session's
  `getApplicationProtocol()`. `getSSLParameters()` reports what the handshake actually reads — the
  socket's enabled cipher suites, enabled protocol versions, and ALPN names, with the suite-order flag
  set on a server end — never the empty JDK default. `setSSLParameters(params)` follows one policy on
  the client socket, the server socket, and the accepted socket: a non-null bundle installs the cipher
  suites and protocol versions it sets into the enabled sets (names this socket does not support throw
  `IllegalArgumentException`, like `setEnabledCipherSuites()`/`setEnabledProtocols()` do), a component
  the bundle leaves unset leaves that set alone, and the fields that describe certificate-authenticated
  connections have no meaning for a PSK connection. A null bundle throws `IllegalArgumentException`.

- `SSLSession.getSessionContext()` answers `null` on both ends of a connection: TLS-PSK handshakes negotiate
  no D-H or DSA group, so there is no session context to report, and `javax.net.ssl.SSLSession` documents
  an unavailable context as `null` (it throws only `SecurityException`). A resumption/KDF consumer that
  calls it unguarded gets `null`, not `UnsupportedOperationException`. These factories never hand out
  group parameters, so a caller that installs a D-H PSK suite through
  `BcPskTlsParams.withSupportedCipherSuites()` — which validates nothing — also gets `null`.
- Session timeout: the session clock starts when the handshake completes, so `SSLSession.isValid()` is false
  until a handshake has run and becomes false once the session has lived longer than the configured
  timeout (0 or negative means no timeout). The timeout is measured from
  `SSLSession.getLastAccessedTime()`, which only moves when a new connection is established on the session
  — reading or setting a session value never moves it — and these factories run one connection per
  session, so it reports the handshake-completion time.
- The factories copy the pre-shared key and identity bytes they hand to Bouncy Castle, because Bouncy
  Castle zeroes the buffers it is given. Your own `getPSK()`/`getPSKIdentity()` arrays are never written
  to — zeroizing them is your code's job, not the library's. Each is read once per handshake, and the
  copies Bouncy Castle receives are throwaways, so a manager that returns fresh arrays per call still
  gets one consistent key per connection.
- `logWarnings` and `throwIOExceptionOnFatalAlert` are per-factory-instance flags, not statics: set them
  on the factory (`factory.throwIOExceptionOnFatalAlert = true`) to control alert logging and whether a
  fatal TLS alert surfaces as an `IOException`.

## Build & Test

    ./gradlew jar
    ./gradlew test

# License

Copyright (C) 2024 Clover Network, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
