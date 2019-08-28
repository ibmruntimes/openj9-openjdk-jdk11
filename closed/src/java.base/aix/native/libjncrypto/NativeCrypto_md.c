/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2019, 2019 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include "NativeCrypto_md.h"

/* Load the crypto library (return NULL on error) */
void * load_crypto_library() {
    void * result = NULL;
    const char *libname111 = "libcrypto.a(libcrypto64.so.1.1)";
    const char *libname110 = "libcrypto.so.1.1";
    const char *libname102 = "libcrypto.so.1.0.0";
    const char *symlink = "libcrypto.a(libcrypto64.so)";

    result = dlopen (libname111, RTLD_NOW | RTLD_MEMBER);
    if (result == NULL) {
        result = dlopen (libname110, RTLD_NOW);
        if (result == NULL) {
            result = dlopen (libname102, RTLD_NOW);
            if (result == NULL) {
                result = dlopen (symlink, RTLD_NOW | RTLD_MEMBER);
            }
        }
    }
    return result;
}

/* Unload the crypto library */
void unload_crypto_library(void *handle) {
    (void)dlclose(handle);
}

/* Find the symbol in the crypto library (return NULL if not found) */
void * find_crypto_symbol(void *handle, const char *symname) {
    return  dlsym(handle, symname);
}
