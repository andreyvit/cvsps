##################################################
# utility bash functions to help with merging    #
##################################################
# copyright 2003 David Mansfield                 #
##################################################
# usage:  . merge_utils.sh                       #
##################################################

#
# show patchset
#
function sps() { 
less $PATCHSETDIR/$1.patch
}

#
# test apply patchset
#
function tps() { 
cat $PATCHSETDIR/$1.patch | patch -p1 --dry-run
}

#
# apply patchset
#
function aps() { 
cat $PATCHSETDIR/$1.patch | patch -p1
}

#
# commit changes as merge of patchset.
#
function cps() {
LOGMSG=`cat $PATCHSETDIR/$1.patch | perl -e '$line = 0; while(<>) {
    if ($line == 1) { if (/PatchSet ([[:digit:]]*)/) { $ps = $1; }}
    if ($line == 2) { if (/Date: (.*)/) { $dt = $1; }}
    if ($line == 4) { if (/Branch: (.*)/) { $br = $1; }}
    if ($line == 7) { $lg = $_; chop($lg) }
    $line++;
}
print "Merge ps:$ps date:$dt branch:$br log:$lg\n";
'`
echo Committing with log message "'$LOGMSG'"
if [ "$2" != "-n" ]
then 
    cvs commit -m"$LOGMSG"
fi
}

echo "Don't forget to set \$PATCHSETDIR to the directory where you patchset diffs are"
