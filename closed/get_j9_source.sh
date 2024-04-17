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

# exit immediately if any unexpected error occurs
set -e

usage() {
	echo "Usage: $0 [-h|--help] [-openj9-repo=<j9vm repo url>] [-openj9-branch=<branch>] [-openj9-sha=<commit sha>] [... other OpenJ9 repositories and branches options] [-parallel=<true|false>]"
	echo "where:"
	echo "  -h|--help         print this help, then exit"
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
	echo "  -gskit-credential the credential for downloading the GSKit binaries"
	echo "  -parallel         (boolean) if 'true' then the clone j9 repository commands run in parallel, default is false"
	echo ""
	exit 1
}

# require bash 4.0 or later to support associative arrays
if [ "0${BASH_VERSINFO[0]}" -lt 4 ] ; then
	echo "Bash version 4.0 or later is required!"
	exit 1
fi

declare -A branches
declare -A commands
declare -A git_urls
declare -A shas
declare -A references

git_urls[openj9]=https://github.com/eclipse-openj9/openj9
git_urls[omr]=https://github.com/eclipse-openj9/openj9-omr

branches[openj9]=v0.44.0-release
branches[omr]=v0.44.0-release

pflag=false

for i in "$@" ; do
	case $i in
		-h | --help )
			usage
			;;

		-openj9-repo=* )
			git_urls[openj9]="${i#*=}"
			;;

		-openj9-branch=* )
			branches[openj9]="${i#*=}"
			;;

		-openj9-sha=* )
			shas[openj9]="${i#*=}"
			;;

		-openj9-reference=* )
			references[openj9]="${i#*=}"
			;;

		-omr-repo=* )
			git_urls[omr]="${i#*=}"
			;;

		-omr-branch=* )
			branches[omr]="${i#*=}"
			;;

		-omr-sha=* )
			shas[omr]="${i#*=}"
			;;

		-omr-reference=* )
			references[omr]="${i#*=}"
			;;

		-openjceplus-repo=* )
			git_urls[OpenJCEPlus]="${i#*=}"
			;;

		-openjceplus-branch=* )
			branches[OpenJCEPlus]="${i#*=}"
			;;

		-openjceplus-sha=* )
			shas[OpenJCEPlus]="${i#*=}"
			;;

		-openjceplus-reference=* )
			references[OpenJCEPlus]="${i#*=}"
			;;

		-gskit-bin=* )
			gskit_bin="${i#*=}"
			;;

		-gskit-sdk-bin=* )
			gskit_sdk_bin="${i#*=}"
			;;

		-gskit-credential=* )
			gskit_credential="${i#*=}"
			;;

		-parallel=* )
			pflag="${i#*=}"
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

# clone OpenJ9 repos
date '+[%F %T] Get OpenJ9 sources'
START_TIME=$(date +%s)

for i in "${!git_urls[@]}" ; do
	branch=${branches[$i]}

	if [ -d ${i} ] ; then
		echo
		echo "Update ${i} source"
		echo

		cd ${i}
		git pull --rebase origin ${branch}

		if [ -f .gitmodules ] ; then
			git pull --rebase --recurse-submodules=yes
			git submodule update --rebase --recursive
		fi
		cd - > /dev/null
	else
		if [ -n "${references[$i]+_}" ] ; then
			reference=" --reference ${references[$i]}"
		else
			reference=""
		fi
		git_clone_command="git clone${reference} --recursive -b ${branch} ${git_urls[$i]} ${i}"
		commands[$i]=$git_clone_command

		echo
		echo "Clone repository: ${i}"
		echo

		if [ ${pflag} = true ] ; then
			# run git clone in parallel
			( if $git_clone_command ; then echo 0 ; else echo $? ; fi ) > /tmp/${i}.pid.rc 2>&1 &
		else
			$git_clone_command
		fi
	fi
done

if [ ${pflag} = true ] ; then
	# wait for all subprocesses to complete
	wait
fi

# Download OCK binaries and create Java module folder.
openjceplus_source=OpenJCEPlus
if [ -n "${git_urls[$openjceplus_source]}" ] ; then

	echo
	echo "$openjceplus_source exists, download OCK binaries"
	echo

	cd $openjceplus_source
	mkdir -p ock/jgsk_sdk/lib64

	if [ -n "$gskit_credential" ] ; then
		curl -u "$gskit_credential" $gskit_bin > ock/jgsk_crypto.tar
		curl -u "$gskit_credential" $gskit_sdk_bin > ock/jgsk_crypto_sdk.tar
	else
		echo
		echo "GSKit binaries are needed for compiling $openjceplus_source"
		echo "Please set -gskit-bin, -gskit-sdk-bin, and -gskit-credential"
		exit 1
	fi

	tar -xf ock/jgsk_crypto_sdk.tar -C ock
	tar -xf ock/jgsk_crypto.tar -C ock/jgsk_sdk/lib64

	# Create OpenJCEPlus Java module folder.
	mkdir -p src/main/openjceplus/share/classes
	cp -r src/main/java/* src/main/openjceplus/share/classes/

	cd ..
fi

END_TIME=$(date +%s)
date "+[%F %T] OpenJ9 clone repositories finished in $(($END_TIME - $START_TIME)) seconds"

for i in "${!git_urls[@]}" ; do
	if [ -e /tmp/${i}.pid.rc ] ; then
		# check if the git clone repository command failed
		rc=$(cat /tmp/${i}.pid.rc | tr -d ' \n\r')

		if [ "$rc" != 0 ] ; then
			echo "ERROR: repository ${i} exited abnormally!"
			cat /tmp/${i}.pid.rc
			echo "Re-run: ${commands[$i]}"

			# clean up sources
			if [ -d ${i} ] ; then
				rm -fdr ${i}
			fi

			# clean up pid file
			rm -f /tmp/${i}.pid.rc
			exit 1
		fi
	fi

	if [ "x${shas[$i]}" != x ] ; then
		echo
		echo "Update ${i} to commit ID: ${shas[$i]}"
		echo

		cd ${i}
		git checkout -B ${branches[$i]} ${shas[$i]}
		cd - > /dev/null
	fi
done
