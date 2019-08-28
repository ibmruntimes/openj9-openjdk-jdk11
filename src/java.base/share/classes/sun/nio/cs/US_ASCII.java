/*
 * Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2018, 2019 All Rights Reserved
 * ===========================================================================
 */
package sun.nio.cs;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;

public class US_ASCII
    extends Charset
    implements HistoricallyNamedCharset
{
    public static final US_ASCII INSTANCE = new US_ASCII();

    public US_ASCII() {
        super("US-ASCII", StandardCharsets.aliases_US_ASCII());
    }

    public String historicalName() {
        return "ASCII";
    }

    public boolean contains(Charset cs) {
        return (cs instanceof US_ASCII);
    }

    public CharsetDecoder newDecoder() {
        return new Decoder(this);
    }

    public CharsetEncoder newEncoder() {
        return new Encoder(this);
    }

    private static class Decoder extends CharsetDecoder {

        private Decoder(Charset cs) {
            super(cs, 1.0f, 1.0f);
        }

        private CoderResult decodeArrayLoop(ByteBuffer src,
                                            CharBuffer dst)
        {
            byte[] sa = src.array();
            int sp = src.arrayOffset() + src.position();
            int sl = src.arrayOffset() + src.limit();
            assert (sp <= sl);
            sp = (sp <= sl ? sp : sl);
            char[] da = dst.array();
            int dp = dst.arrayOffset() + dst.position();
            int dl = dst.arrayOffset() + dst.limit();
            assert (dp <= dl);
            dp = (dp <= dl ? dp : dl);

            try {
            	
                if((dl-dp) >= (sl-sp)) {                                             //OpenJ9-perf_converter
                    
                    int n = decodeASCII(sa, sp, sl-sp, da, dp);
                    sp = sp + n;
                    dp = dp + n;
                    if (sp<sl)
                     	return CoderResult.malformedForLength(1);
                    return CoderResult.UNDERFLOW;                            //OpenJ9-perf_converter
                }                                                               //OpenJ9-perf_converter
                else {                                                           //OpenJ9-perf_converter
                    int n = decodeASCII(sa, sp, dl-dp, da, dp);
                    sp = sp + n;
                    dp = dp + n;
                    if (dp<dl)
                    	return CoderResult.malformedForLength(1);
                    return CoderResult.OVERFLOW;                         //OpenJ9-perf_converter
                }                                                                //OpenJ9-perf_converter
            } finally {
                src.position(sp - src.arrayOffset());
                dst.position(dp - dst.arrayOffset());
            }
        }

        private CoderResult decodeBufferLoop(ByteBuffer src,
                                             CharBuffer dst)
        {
            int mark = src.position();
            try {
                while (src.hasRemaining()) {
                    byte b = src.get();
                    if (b >= 0) {
                        if (!dst.hasRemaining())
                            return CoderResult.OVERFLOW;
                        dst.put((char)b);
                        mark++;
                        continue;
                    }
                    return CoderResult.malformedForLength(1);
                }
                return CoderResult.UNDERFLOW;
            } finally {
                src.position(mark);
            }
        }

        protected CoderResult decodeLoop(ByteBuffer src,
                                         CharBuffer dst)
        {
            if (src.hasArray() && dst.hasArray())
                return decodeArrayLoop(src, dst);
            else
                return decodeBufferLoop(src, dst);
        }
 	public final int decodeASCII(byte[] src, int sp, int len, char[] dst, int dp) {
            int n = 0;
            while (n < len) 
               {
                byte b = src[sp++];

                if (b >= 0){
            
                    dst[dp++] = (char)b;
                    n++;
                    continue;
                       }
                break;   
                
               }
            
            return n;
        }
    }

    private static class Encoder extends CharsetEncoder {

        private Encoder(Charset cs) {
            super(cs, 1.0f, 1.0f);
        }

        public boolean canEncode(char c) {
            return c < 0x80;
        }

        public boolean isLegalReplacement(byte[] repl) {
            return (repl.length == 1 && repl[0] >= 0) ||
                   super.isLegalReplacement(repl);
        }

        private final Surrogate.Parser sgp = new Surrogate.Parser();
        private CoderResult encodeArrayLoop(CharBuffer src,
                                            ByteBuffer dst)
        {
            char[] sa = src.array();
            int sp = src.arrayOffset() + src.position();
            int sl = src.arrayOffset() + src.limit();
            assert (sp <= sl);
            sp = (sp <= sl ? sp : sl);
            byte[] da = dst.array();
            int dp = dst.arrayOffset() + dst.position();
            int dl = dst.arrayOffset() + dst.limit();
            assert (dp <= dl);
            dp = (dp <= dl ? dp : dl);

            try {
                if((dl-dp) >= (sl-sp)) {                                             //OpenJ9-perf_converter
                    
                    int n = encodeASCII(sa,sp,sl-sp,da,dp);
                    sp = sp+n;
                    dp = dp+n;

                    if (sp<sl)
                    {
                        char c = sa[sp];
                        if (sgp.parse(c, sa, sp, sl) < 0) {                 //OpenJ9-perf_converter
                            return sgp.error();                                  //OpenJ9-perf_converter
                        }                                                //OpenJ9-perf_converter
                        else return sgp.unmappableResult();              //OpenJ9-perf_converter
                    }

                    return CoderResult.UNDERFLOW;                            //OpenJ9-perf_converter
                }                                                                        //OpenJ9-perf_converter
                else {                                                               //OpenJ9-perf_converter
                    int n = encodeASCII(sa,sp,dl-dp,da,dp);
                    sp = sp+n;
                    dp = dp+n;
                    if (dp<dl)
                    {
                        char c = sa[sp];
                        if (sgp.parse(c, sa, sp, sl) < 0) {                 //OpenJ9-perf_converter
                               return sgp.error();                              //OpenJ9-perf_converter
                           }                                                        //OpenJ9-perf_converter
                        else return sgp.unmappableResult();                  //OpenJ9-perf_converter
                    }

                    return CoderResult.OVERFLOW;                                     //OpenJ9-perf_converter
                }
            } finally {
                src.position(sp - src.arrayOffset());
                dst.position(dp - dst.arrayOffset());
            }
        }

        private CoderResult encodeBufferLoop(CharBuffer src,
                                             ByteBuffer dst)
        {
            int mark = src.position();
            try {
                while (src.hasRemaining()) {
                    char c = src.get();
                    if (c < 0x80) {
                        if (!dst.hasRemaining())
                            return CoderResult.OVERFLOW;
                        dst.put((byte)c);
                        mark++;
                        continue;
                    }
                    if (sgp.parse(c, src) < 0)
                        return sgp.error();
                    return sgp.unmappableResult();
                }
                return CoderResult.UNDERFLOW;
            } finally {
                src.position(mark);
            }
        }

        protected CoderResult encodeLoop(CharBuffer src,
                                         ByteBuffer dst)
        {
            if (src.hasArray() && dst.hasArray())
                return encodeArrayLoop(src, dst);
            else
                return encodeBufferLoop(src, dst);
        }

        public final int encodeASCII(char[] src, int sp, int len, byte[] dst, int dp) {
            int n = 0;
            while (n < len) {
               char c = src[sp++];
               if (c < 0x80) {
                   dst[dp++] = (byte)c;
                   n++;
                   continue;
               }
               break;
            }
           return n;
         }
    }
}
