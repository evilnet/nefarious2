#!/bin/sh
# gitysnc.sh, Copyright (c) 2015 Rubin
# based on linesync.sh (c) 2002 Arjen Wolfs
#
# The code contained is in this file is licenced under the terms
# and conditions as specified in the GNU General Public License.
#
# This program should be run from crontab, i.e something like:
# 0 0 * * * /home/irc/bin/linesync.sh /home/irc/lib/ircd.conf /home/irc/lib/ircd.pid
#

# This checks for the presence of an executable file in $PATH
locate_program() {
        if [ ! -x "`which $1 2>&1`" ]; then
                echo "You don't seem to have $1. Sorry."
                exit 1
        fi
}

# This checks for the presence of any file
check_file() {
        if [ ! -f "$1" ]; then
                echo "There doesn't appear to be a $1. Sorry."
                exit 1
        fi
}

# Try to find programs we will need
locate_program openssl 
locate_program git
locate_program egrep
locate_program diff
locate_program chmod
locate_program readlink

# try to find GNU awk
awk_cmd=`which gawk`
if [ $? -ne 0 ]; then
        awk_cmd=""
fi

if [ -z "$awk_cmd" ]; then
	locate_program awk
	is_gawk=`echo | awk --version | head -1 | egrep '^GNU.+$'`
	if [ -z "$is_gawk" ]; then
		echo "Your version of awk is not GNU awk. Sorry."
		exit 1
	fi
	awk_cmd="awk"	
fi

# Check for required command line parameters
if [ -z "$1" -o -z "$2" ]; then
        echo "Usage: $0 <conf_path> <pid_path>"
        echo "      <conf_path>     Full path to ircd.conf (/home/irc/lib/ircd.conf)"
        echo "      <pid_path>      Full path to ircd.pid (/home/irc/lib/ircd.pid)"
        exit 1
fi

# check and set up stuff
diff_cmd="diff"
cpath=$1
ppath=$2
check_file $cpath
dpath=`dirname $cpath`
dpath=`readlink -f $dpath`
lpath="$dpath/linesync"
kpath="$dpath/ircd.pem"
#check_file $lpath
save_dir=$PWD; cd $dpath
tpath=$PWD; cd $save_dir
tmp_path="$dpath/tmp"
ipath="$tmp_path/ssh.pem"
mkdir $tmp_path > /dev/null 2>&1

# Not all versions of date support %s, work around it
TS=`date +%Y%m%d%H%M%S`
TMPFILE="$tmp_path/linesync.$TS"

#Check for the git repository
if [ ! -d "$lpath/.git" ]; then
    echo "Cannot find a git repository at $lpath."
    exit 10
fi
# TODO: check it out if its missing?

#Generate ssh identity from ircd.pem
# first get the private key by just grabbing the lines that match...
awk '/BEGIN .*PRIVATE KEY/,/END .*PRIVATE KEY/' $kpath > $tmp_path/ssh.pem
# Then we'll get the public key more properly..
openssl x509 -in $kpath -pubkey -noout >> $tmp_path/ssh.pem

chmod 600 $tmp_path/ssh.pem

# To get the public key for use in authorize_keys you'd do this:
#     ssh-keygen -i -m PKCS8 -f $tmp_path/ssh.pem >ssh.pub
# but we dont need it ...

#Override git's ssh command so we can force our custom identity
echo '#!/bin/bash' > $tmp_path/git.sh
echo "ssh -i $tmp_path/ssh.pem \$1 \$2\n" >> $tmp_path/git.sh
chmod a+x $tmp_path/git.sh
export GIT_SSH="$tmp_path/git.sh"

#update the repository from upstream
prevdir=`pwd`
cd $lpath
git reset -q --hard origin/master
git pull --quiet
cd $prevdir

#Copy the data to the temp file
cp $lpath/linesync.data $TMPFILE

if [ ! -s "$TMPFILE" ]; then
        echo "Unable find retrieve $lpath/linesync.data, Sorry."
	rm $TMPFILE > /dev/null 2>&1
        exit 1
fi

# check our ircd.conf
ircd_setup=`egrep '^# (BEGIN|END) LINESYNC$' $cpath|wc -l`
if [ $ircd_setup != 2 ]; then
	cp $cpath $cpath.orig
	echo "Performing initial merge on $cpath, original file saved as $cpath.orig."
	
        echo "# Do NOT remove the following line, linesync.sh depends on it!" >> $cpath
        echo "# BEGIN LINESYNC" >> $cpath
        echo "# END LINESYNC" >> $cpath
        echo "# Do not remove the previous line, linesync.sh depends on it!" >> $cpath

	# Do an initial merge to remove duplicates
	inpath="$tmp_path/linesync.tmp.$TS"
	$awk_cmd '
	{
                if (!loaded_template) {
                        command="cat " tempfile; tlines=0;
                        while ((command | getline avar) > 0) { template[tlines]=avar; tlines++ }
                        close(command)
                        loaded_template++
                }
		dup_line=0
                for (i=0; i<tlines; i++) {
                        if (tolower($0)==tolower(template[i])) { dup_line++; break }
                }
		if (!dup_line) print $0
        } ' tempfile=$TMPFILE < $cpath > $inpath
else
	inpath=$cpath
fi

# Replace the marked block in ircd.conf with the new version

$awk_cmd ' 
$0=="# BEGIN LINESYNC" { chop++; print; next }
$0=="# END LINESYNC" {
        command="cat " syncfile
        while ((command | getline avar) > 0) { print avar }
        close(command)
        chop--
}
{ if (!chop) print $0 }
' syncfile=$TMPFILE < $inpath > $tmp_path/linesync.new.$TS

# run a diff between current and new confs to see if we updated anything
# no point sending the ircd a -HUP if this is not needed, especially on a
# busy network, such as Undernet.
diff=`$diff_cmd $cpath $tmp_path/linesync.new.$TS`
if [ ! -z "$diff" ]; then
	# Changes were detected

	# Back up the current ircd.conf and replace it with the new one
	cp $cpath  $dpath/ircd.conf.bk
	cp $tmp_path/linesync.new.$TS $cpath

	# Rehash ircd (without caring wether or not it succeeds)
	kill -HUP `cat $ppath 2>/dev/null` > /dev/null 2>&1
fi

# (Try to) clean up
rm -rf $tmp_path > /dev/null 2>&1

# That's it...
