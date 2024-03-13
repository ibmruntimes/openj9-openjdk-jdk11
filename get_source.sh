#!/bin/bash
# ===========================================================================
# (c) Copyright IBM Corp. 2017, 2024 All Rights Reserved
# ===========================================================================
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.
#
# IBM designates this particular file as subject to the "Classpath" exception
# as provided by IBM in the LICENSE file that accompanied this code.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
#
# ===========================================================================
#

# exit immediately if any unexpected error occurs
set -e

usage() {
	echo "Usage: $0 [-h|--help] [... other j9 options] [-parallel=<true|false>] [--openssl-version=<openssl version to download>]"
	echo "where:"
	echo "  -h|--help         print this help, then exit"
	echo " "
	echo "  -openj9-repo      the OpenJ9 repository url: https://github.com/eclipse-openj9/openj9.git"
	echo "                    or git@github.com:<namespace>/openj9.git"
	echo "  -openj9-branch    the OpenJ9 git branch: master"
	echo "  -openj9-sha       a commit SHA for the OpenJ9 repository"
	echo "  -openj9-reference a local repo to use as a clone reference"
	echo "  -omr-repo         the OpenJ9/omr repository url: https://github.com/eclipse-openj9/openj9-omr.git"
	echo "                    or git@github.com:<namespace>/openj9-omr.git"
	echo "  -omr-branch       the OpenJ9/omr git branch: openj9"
	echo "  -omr-sha          a commit SHA for the omr repository"
	echo "  -omr-reference    a local repo to use as a clone reference"
	echo "  -openjceplus-repo the OpenJCEPlus repository url"
	echo "  -openjceplus-branch the OpenJCEPlus git branch"
	echo "  -openjceplus-sha  a commit SHA for the OpenJCEPlus repository"
	echo "  -openjceplus-reference a local repo to use as a clone reference"
	echo "  -gskit-bin        the GSKit binary url"
	echo "  -gskit-sdk-bin    the GSKIT SDK binary url"
	echo "  -gskit-credential the credential for downloading the GSKit and GSKit SDK"
	echo "  -parallel         (boolean) if 'true' then the clone j9 repository commands run in parallel, default is false"
	echo "  --openssl-repo    Specify the OpenSSL repository to download from"
	echo "  --openssl-version Specify the version of OpenSSL source to download"
	echo ""
	exit 1
}

j9options=""
openssloptions=""
DOWNLOAD_OPENSSL=false

for i in "$@" ; do
	case $i in
		-h | --help )
			usage
			;;

		  -gskit-bin=* \
		| -gskit-credential=* \
		| -gskit-sdk-bin=* \
		| -omr-branch=* \
		| -omr-reference=* \
		| -omr-repo=* \
		| -omr-sha=* \
		| -openj9-branch=* \
		| -openj9-reference=* \
		| -openj9-repo=* \
		| -openj9-sha=* \
		| -openjceplus-branch=* \
		| -openjceplus-reference=* \
		| -openjceplus-repo=* \
		| -openjceplus-sha=* \
		| -parallel=* \
		)
			j9options="${j9options} ${i}"
			;;

		--openssl-repo=* )
			openssloptions="${openssloptions} ${i}"
			;;

		--openssl-version=* )
			DOWNLOAD_OPENSSL=true
			openssloptions="${openssloptions} ${i}"
			;;

		'--' ) # no more options
			break
			;;

		-*) # bad option
			usage
			;;

		*) # bad option
			usage
			;;
	esac
done

# Get clones of OpenJ9 absent repositories
bash closed/get_j9_source.sh ${j9options}

# Download source of OpenSSL if asked
if $DOWNLOAD_OPENSSL; then
	bash closed/get_openssl_source.sh ${openssloptions}
fi
