#!/bin/bash

mv ChangeLog bak.ChangeLog

rev_list=`git rev-list --tags --max-count=1..HEAD`
tag_desc=`git describe --tags $rev_list`
cur_desc=`git flow release | awk '{print $2}'`

echo v$cur_desc > ChangeLog
git log --no-merges --reverse --pretty='format: o %s (%h %an)' $tag_desc..HEAD >> ChangeLog
echo "" >> ChangeLog
echo "" >> ChangeLog

cat bak.ChangeLog >> ChangeLog
