

package org.bchateau.pskfactories;

import org.bouncycastle.tls.TlsPSKIdentityManager;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.Arrays;
import java.util.Locale;

public class TesterSupport {

    static final byte[] KEY_1 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    static final String ID_1 = "identity1";

    static final byte[] KEY_2 = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1 };
    static final String ID_2 = "identity2";

    static final byte[] testPskKey = new byte[] {
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
            0x1a, 0x2b, 0x3c, 0x4d, 0x1a, 0x2b, 0x3c, 0x4d,
    };

    static final TlsPSKIdentityManager testIdentityMgr = new TlsPSKIdentityManager() {
        @Override
        public byte[] getHint() {
            return new byte[0];
        }

        @Override
        public byte[] getPSK(byte[] identity) {
            if (Arrays.equals("test".getBytes(), identity)) {
                return testPskKey;
            } else {
                return null;
            }
        }
    };

    static TlsPSKIdentityManager createTestTlsPSKIdentityManager() {
        return new TlsPSKIdentityManager() {
            @Override
            public byte[] getHint() { return new byte[0]; }
            @Override
            public byte[] getPSK(byte[] identity) {
                if (Arrays.equals(ID_1.getBytes(), identity)) return KEY_1;
                throw new IllegalArgumentException("Unknown identity");
            }
        };
    }

    public static void log(String s) {
        RuntimeMXBean rb = ManagementFactory.getRuntimeMXBean();
        System.out.println(String.format(Locale.US, "%08d", rb.getUptime()) + ": " + s +
                " (" + Thread.currentThread() + ")");
    }

}
