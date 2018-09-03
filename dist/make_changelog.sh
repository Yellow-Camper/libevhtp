#!/usr/bin/env bash

old_tag=
new_tag=
regen=0

usage() {
cat << EOF
Usage: $0 [opts]

OPTS:
  -h This help text
  -F Regenerate the entire ChangeLog
  -o Old git tag (default action is to automagically find your last tag)
  -n New git tag (default action is to use git-flow release to find your new tag name)
EOF
}

while getopts "hFo:n:" OPTION
do
	case $OPTION in
		h)
			usage
			exit 0
			;;
		F)
			regen=1
			;;
		o)
			old_tag=$OPTARG
			;;
		n)
			new_tag=$OPTARG
			;;
		?)
			echo "No such option $OPTARG"
			usage
			exit -1
			;;
	esac
done

function generate_changelog() {
	old=$1
	new=$2

	git --no-pager log --no-merges --reverse --pretty='format: o %s (%h %an)' $old..$new
	echo ""
	echo ""
}

use_head=0

if [ -z $old_tag ]
then
	l_sha=`git rev-list --tags --max-count=1..HEAD`
	old_tag=`git describe --tags $l_sha`
fi

if [ -z $new_tag ]
then
	new_tag=`git flow release | awk '{print $2}'`
	use_head=1
fi

echo v$new_tag

if [ $use_head -eq 1 ]
then
	generate_changelog $old_tag HEAD
fi

if [ $regen -eq 1 ]
then
	tags=()

	for tag in `git for-each-ref --sort='*authordate' --format='%(refname)' refs/tags | awk -F/ '{print $3}'` ; do
		tags+=("$tag")
	done

	last_tag=

	for ((i=${#tags[@]-1}; i>=0; i--)); do
		if [ -z $last_tag ]
		then
			last_tag=${tags[$i]}
			continue
		fi

		echo v${tags[$i]}

		generate_changelog ${tags[$i]} $last_tag

		last_tag=${tags[$i]}
	done
fi
