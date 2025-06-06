/*
 * Copyright (c) 2004, 2018, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2025, 2025 All Rights Reserved
 * ===========================================================================
 */

#include "jni.h"
#include "jni_util.h"
#include "jvm.h"
#include "jdk_util.h"

#include "jdk_internal_misc_VM.h"

#if defined(WIN32)
#include "j9access.h"
/* tracehelp.c defines getTraceInterfaceFromVM(), used by J9_UTINTERFACE_FROM_VM(). */
#include "tracehelp.c"
#include "ut_jcl_java.c"
#endif /* defined(WIN32) */

/* Only register the performance-critical methods */
static JNINativeMethod methods[] = {
    {"getNanoTimeAdjustment", "(J)J", (void *)&JVM_GetNanoTimeAdjustment}
};

JNIEXPORT jobject JNICALL
Java_jdk_internal_misc_VM_latestUserDefinedLoader0(JNIEnv *env, jclass cls) {
    return JVM_LatestUserDefinedLoader(env);
}

JNIEXPORT void JNICALL
Java_jdk_internal_misc_VM_initialize(JNIEnv *env, jclass cls) {
#if defined(WIN32)
    /* Other platforms do this in check_version.c JNI_OnLoad. */
    UT_JCL_JAVA_MODULE_LOADED(J9_UTINTERFACE_FROM_VM(((J9VMThread *) env)->javaVM));
#endif /* defined(WIN32) */

    if (!JDK_InitJvmHandle()) {
        JNU_ThrowInternalError(env, "Handle for JVM not found for symbol lookup");
        return;
    }

    // Registers implementations of native methods described in methods[]
    // above.
    // In particular, registers JVM_GetNanoTimeAdjustment as the implementation
    // of the native VM.getNanoTimeAdjustment - avoiding the cost of
    // introducing a Java_jdk_internal_misc_VM_getNanoTimeAdjustment wrapper
    (*env)->RegisterNatives(env, cls,
                            methods, sizeof(methods)/sizeof(methods[0]));
}

JNIEXPORT jobjectArray JNICALL
Java_jdk_internal_misc_VM_getRuntimeArguments(JNIEnv *env, jclass cls) {
    return JVM_GetVmArguments(env);
}

JNIEXPORT void JNICALL
Java_jdk_internal_misc_VM_initializeFromArchive(JNIEnv *env, jclass ignore,
                                                jclass c) {
    JVM_InitializeFromArchive(env, c);
}
