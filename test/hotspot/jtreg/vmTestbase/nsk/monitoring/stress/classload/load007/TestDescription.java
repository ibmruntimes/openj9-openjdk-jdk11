/*
 * Copyright (c) 2017, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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
 * @test
 * @key stress
 *
 * @summary converted from VM Testbase nsk/monitoring/stress/classload/load007.
 * VM Testbase keywords: [stress, monitoring, nonconcurrent]
 * VM Testbase readme:
 * DESCRIPTION
 *     The test checks up getAllClasses(), getLoadedClassCount(),
 *     getTotalLoadedClassCount(), getUnloadedClassCount() methods when 100
 *     classes are loaded by 100 loaders, which are the instances of two
 *     custom ClassLoader classes.
 *     Access to the management metrics is accomplished by directly calling
 *     the methods in the MBean.
 *     Executable class of the test is the same as for the load001 test.
 *     In contrast to the load001 test, the load007 test is performed for
 *     the case when 100 loaders execute loading.
 * COMMENTS
 *     Fixed the bug
 *     4976274 Regression: "OutOfMemoryError: Java heap space" when -XX:+UseParallelGC
 *
 * @library /vmTestbase
 *          /test/lib
 * @run driver jdk.test.lib.FileInstaller . .
 * @comment generate and compile LoadableClassXXX classes
 * @run driver nsk.monitoring.stress.classload.GenClassesBuilder
 * @run main/othervm/timeout=180
 *      -XX:-UseGCOverheadLimit
 *      nsk.monitoring.stress.classload.load001
 *      classes
 *      -loadableClassCount=100
 *      -loadersCount=100
 */

