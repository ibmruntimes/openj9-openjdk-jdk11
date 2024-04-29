#!/bin/bash
# ===========================================================================
# (c) Copyright IBM Corp. 2017, 2024 All Rights Reserved
# ===========================================================================
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
# ===========================================================================

# exit immediately if any unexpected error occurs
set -e

# These maps are keyed by the prefix of option names (e.g. openj9, omr).
declare -A source_branch    # branch or tag
declare -A source_folder    # local working directory
declare -A source_options   # extra clone options
declare -A source_ref       # local reference repository
declare -A source_sha       # commit SHA
declare -A source_url       # URL

# Print a message to stderr and exit.
#
fail() {
	echo "$*" >&2
	exit 1
}

# Define a single possible source repository.
# $1 - The local working directory. The value converted to lowercase is used
#      to form the related option names. For example, the key "OpenJCEPlus"
#      means options "-openjceplus-repo=", "-openjceplus-branch=",
#      "-openjceplus-sha=", and "-openjceplus-reference=" will be recognized.
# $2 - The source URL; default empty.
# $3 - The source branch or tag; default empty.
# $4 - Extra options for git clone; default empty.
# $5 - The local reference repository; default empty.
#
add_source() {
	if [ $# -lt 1 ] ; then
		fail "add_source requires at least one argument"
	fi

	local key="${1,,}"
	local folder="$1"
	local url="${2:-}"
	local branch="${3:-}"
	local options="${4:-}"
	local sha="${5:-}"

	source_folder[$key]="$folder"
	source_url[$key]="$url"
	source_branch[$key]="$branch"
	source_options[$key]="$options"
	source_sha[$key]="$sha"
	source_ref[$key]=""
}

# Configure the known source repositories.
#
configure_defaults() {
	local current_branch="$(git rev-parse --abbrev-ref HEAD)"
	local openj9_branch=master
	local omr_branch=openj9

	# If this repository is on a release branch, use the same branch names
	# for OpenJ9 and OMR.
	if [[ "$current_branch" =~ (ibm-)?(v[0-9]+\.[0-9]+(\.[0-9]+)?-release) ]] ; then
		openj9_branch="${BASH_REMATCH[2]}"
		omr_branch="${BASH_REMATCH[2]}"
	fi

	#          folder       URL                                               branch          options
	#          ------       ---                                               ------          -------
	add_source openj9       https://github.com/eclipse-openj9/openj9.git      $openj9_branch
	add_source omr          https://github.com/eclipse-openj9/openj9-omr.git  $omr_branch

	add_source OpenJCEPlus  https://github.com/ibmruntimes/OpenJCEPlus.git
	add_source openssl      https://github.com/openssl/openssl.git            ""              "--depth=1"
}

# Show the usage of a single option.
# $1 - The option name.
# $2 - The option description.
# $3 - The default value of the option; default none.
#
show_option() {
	local option="$1"
	local description="$2"
	local default="${3:+ [$3]}"

	printf "    %-22s  %s%s\n" "$option" "$description" "$default"
}

# Print help for this script and exit.
#
usage() {
	local key

	echo "Usage: $0 [options ...]"
	echo "  where:"
	show_option "-h|--help"  "print this help, then exit"

	for key in "${!source_folder[@]}" ; do
		local folder="${source_folder[$key]}"

		show_option "-$key-repo"       "the repository URL for $folder"            "${source_url[$key]}"
		show_option "-$key-branch"     "the git branch for $folder"                "${source_branch[$key]}"
		show_option "-$key-sha"        "a commit SHA for the $folder repository"   "${source_sha[$key]}"
		show_option "-$key-reference"  "a local repository to use as a reference"  "${source_ref[$key]}"
	done

	show_option "-gskit-bin"         "the GSKit binary URL"
	show_option "-gskit-sdk-bin"     "the GSKIT SDK binary URL"
	show_option "-gskit-credential"  "the credential for downloading the GSKit and GSKit SDK"
	show_option "--openssl-repo"     "equivalent to -openssl-repo"
	show_option "--openssl-version"  "specify the version of OpenSSL source to download"
	show_option "-parallel"          "(ignored)"
	exit 1
}

# Process and validate the command-line arguments.
#
process_options() {
	local arg=""
	local version=""

	for arg in "$@" ; do
		# temporarily handle openssl options that don't follow the general pattern
		case "$arg" in
			--openssl-repo=*)
				# remove leading '-'
				arg="${arg/--/-}"
				;;
			--openssl-version=*)
				# map to -openssl-branch
				version="${arg#*=}"
				case "$version" in
					1.0.2* | 1.1.*)
						version="OpenSSL_${version//./_}"
						;;
					3.*)
						version="openssl-$version"
						;;
					*)
						;;
				esac
				arg=-openssl-branch=$version
				;;
			*)
				;;
		esac

		if [[ "$arg" =~ -([A-Za-z0-9]+)-(branch|reference|repo|sha)=.* ]] ; then
			local key="${BASH_REMATCH[1]}"
			if [ -z "${source_folder[${key}]}" ] ; then
				fail "Unknown option: '$arg'"
			fi

			local value="${arg#*=}"
			case "${BASH_REMATCH[2]}" in
				branch)    source_branch[$key]="$value" ;;
				reference) source_ref[$key]="$value" ;;
				repo)      source_url[$key]="$value" ;;
				sha)       source_sha[$key]="$value" ;;
			esac
		else
			case "$arg" in
				-gskit-bin=*)
					gskit_bin="${arg#*=}"
					;;
				-gskit-sdk-bin=*)
					gskit_sdk_bin="${arg#*=}"
					;;
				-gskit-credential=*)
					gskit_credential="${arg#*=}"
					;;
				-h | --help)
					usage
					;;
				--)
					# end of options
					break
					;;
				*)
					fail "Unknown option: '$arg'"
					usage
					;;
			esac
		fi
	done
}

# The main body which does the actual cloning or updating of sources.
#
clone_or_update_repos() {
	local key

	for key in "${!source_folder[@]}" ; do
		local url="${source_url[$key]}"
		local branch="${source_branch[$key]}"

		if [ -n "$url" ] && [ -n "$branch" ] ; then
			local folder="${source_folder[$key]}"
			local sha="${source_sha[$key]}"
			local reference="${source_ref[$key]}"

			if [ -d "$folder" ] ; then
				echo
				echo "Update $folder source"
				echo

				cd "$folder"
				git pull --rebase origin "$branch"

				if [ -f .gitmodules ] ; then
					git pull --rebase --recurse-submodules=yes
					git submodule update --rebase --recursive
				fi
				cd - > /dev/null
			else
				echo
				echo "Cloning $folder version $branch from $url"
				echo

				git clone \
					${reference:+--reference "$reference"} \
					${source_options[$key]} \
					-b "$branch" \
					"$url" \
					"$folder"
			fi

			if [ -n "$sha" ] ; then
				echo
				echo "Update $folder to commit ID: $sha"
				echo

				cd $folder
				git checkout -B "$branch" "$sha"
				cd - > /dev/null
			fi
		fi
	done
}

# If OpenJCEPlus is present and the necessary URLs were provided, download OCK
# binaries and create Java module folder.
#
maybe_get_gskit() {
	if [ -d OpenJCEPlus ] && [ ! -d OpenJCEPlus/ock ] && [ -n "$gskit_bin" ] && [ -n "$gskit_sdk_bin" ] ; then
		echo
		echo "Downloading OCK binaries for OpenJCEPlus"
		echo

		cd OpenJCEPlus
		mkdir -p ock/jgsk_sdk/lib64

		if [ -n "$gskit_credential" ] ; then
			curl -u "$gskit_credential" "$gskit_bin"     > ock/jgsk_crypto.tar
			curl -u "$gskit_credential" "$gskit_sdk_bin" > ock/jgsk_crypto_sdk.tar
		else
			echo "GSKit binaries are needed for compiling OpenJCEPlus."
			fail "Please specify the -gskit-credential option."
		fi

		tar -xf ock/jgsk_crypto_sdk.tar -C ock
		tar -xf ock/jgsk_crypto.tar     -C ock/jgsk_sdk/lib64

		# Create OpenJCEPlus Java module folder.
		mkdir -p src/main/openjceplus/share/classes
		cp -r src/main/java/* src/main/openjceplus/share/classes/

		cd - > /dev/null
	fi
}

# ===========================================================================

configure_defaults
process_options "$@"
clone_or_update_repos
maybe_get_gskit
