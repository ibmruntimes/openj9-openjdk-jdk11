/*
 * Copyright (c) 2003, 2014, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2025 All Rights Reserved
 * ===========================================================================
 */

package sun.security.provider;

import jdk.crypto.jniprovider.NativeCrypto;

abstract class NativeSHA5 {

    /**
     * Native SHA-512-224 implementation class.
     */
    public static final class SHA512_224 extends NativeDigest {

        public SHA512_224() {
            super("SHA-512-224", 28, NativeCrypto.SHA5_512_224);
        }
    }

    /**
     * Native SHA-512-256 implementation class.
     */
    public static final class SHA512_256 extends NativeDigest {

        public SHA512_256() {
            super("SHA-512-256", 32, NativeCrypto.SHA5_512_256);
        }
    }

    /**
     * Native SHA-512 implementation class.
     */
    public static final class SHA512 extends NativeDigest {

        public SHA512() {
            super("SHA-512", 64, NativeCrypto.SHA5_512);
        }
    }

    /**
     * Native SHA-384 implementation class.
     */
    public static final class SHA384 extends NativeDigest {

        public SHA384() {
            super("SHA-384", 48, NativeCrypto.SHA5_384);
        }
    }
}
