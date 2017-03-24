#!/bin/bash
# gitysnc.sh, Copyright (c) 2015 Rubin
# based on linesync.sh (c) 2002 Arjen Wolfs
#
# The code contained is in this file is licenced under the terms
# and conditions as specified in the GNU General Public License.
#
# This program should be run from crontab, i.e something like:
# 0 0 * * * /home/irc/bin/linesync.sh /home/irc/lib/ircd.conf /home/irc/lib/ircd.pid
#

usage() {
    echo "Help: "
    echo "  $0 [-h|-i repository] <-p ircd.pem|-s id_rsa> <ircd.conf> <ircd.pid>"
    echo ""
    echo " -h                - this help"
    echo " -p ircd.pem       - convert this ircd.pem certificate to an ssh key and use that instead of the default ~/.ssh/id_rsa"
    echo " -s id_rsa         - Full path to your ssh private key to use for git access (defaults to ~/.ssh/id_rsa)"
    echo " -i repository-url - Perform initial setup, needed only once to set up. Provide git URL as argument"
    echo " <ircd.conf>       - Full path to your ircd.conf file"
    echo " <ircd.pid>        - Full path to your ircd.pid file"
    echo ""
}

#Handle argument parsing
while getopts "hi:p:s:" opt; do
    case $opt in
     h)
        usage
        exit
        ;;
     i)
         dosetup="yes"
         repository="$OPTARG"

         ;;
     p)
        ircdkey="yes"
        kpath="$OPTARG"
        ;;
     s)
        skey="$OPTARG"
        ;;
    \?)
        echo "Unknown option: -$OPTARG" >&2
        exit 1
        ;;
    :)
        echo "Option -$OPTARG requires an argument." >&2
        exit 1
    esac
done
shift $((OPTIND-1))

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
        echo "Try: # sudo apt-get install gawk"
		exit 1
	fi
	awk_cmd="awk"	
fi

# Check for required command line parameters
if [ -z "$1" ] || [ -z "$2" ] ; then
    echo "Error: No ircd.conf or ircd.pid specified"
    usage
    exit 1
fi

if [ -n "$skey" ] && [ -n "$ircdkey" ]; then
    echo "Error: You cannot use -s and -p together. Pick one method to authenicate."
    usage
    exit;
fi

if [ -z "$skey" ] && [ -z "$ircdkey" ]; then
    echo "Error: You must provide -s or -p. Pick one method to authenicate."
    usage
    exit;
fi


if [ -z "$skey" ]; then
    skey="$HOME/.ssh/id_rsa"
fi

# check and set up stuff
diff_cmd="diff"
cpath="$1"
ppath="$2"
check_file "$cpath"
dpath=`dirname "$cpath"`
dpath=`readlink -f "$dpath"`
lpath="$dpath/linesync"
#check_file $lpath
save_dir="$PWD"; cd "$dpath"
tpath="$PWD"; cd "$save_dir"
tmp_path="$dpath/tmp"
ipath="$tmp_path/ssh.pem"
mkdir "$tmp_path" > /dev/null 2>&1

# Not all versions of date support %s, work around it
TS=`date +%Y%m%d%H%M%S`
TMPFILE="$tmp_path/linesync.$TS"

echo '#!/bin/bash' > "$tmp_path/git.sh"

#If they specified -p, we generate the git ssh key from ircd.pem
if [ -n "$ircdkey" ]; then

    check_file "$kpath"
    # first get the private key by just grabbing the lines that match...
    awk '/BEGIN .*PRIVATE KEY/,/END .*PRIVATE KEY/' "$kpath" > "$ipath"
    # Then we'll get the public key more properly..
    if ! openssl x509 -in "$kpath" -pubkey -noout >> "$ipath"; then
        echo "Error: I could not use $kpath as a key for some reason. Stopping!"
        exit
    fi

    chmod 600 "$tmp_path/ssh.pem"

    #Override git's ssh command so we can force our custom identity and no password
    echo "ssh -oPasswordAuthentication=no -i \"$ipath\" \"\$1\" \"\$2\"\n" >> "$tmp_path/git.sh"
else 
    #Override git's ssh command so we can force our custom identity and no password
    echo "ssh -oPasswordAuthentication=no -i \"$skey\" \"\$1\" \"\$2\"\n" >> "$tmp_path/git.sh"
fi

chmod a+x "$tmp_path/git.sh"
export GIT_SSH="$tmp_path/git.sh"


if [ "$dosetup" = "yes" ]; then
    echo "Doing initial setup with repository $repository" >&2

    #Creating ssh keys if they don't exist
    ssh-keygen -A
    if [ -d "$lpath" ]; then
        echo "Doing setup.. but destination directory $lpath already exists. Move it out of the way and try again"
        exit 2
    fi
    echo "Note: your public key (linesync admin will have added this to keydir):"

    if [ -n "$ircdkey" ]; then
        ssh-keygen -i -m PKCS8 -f "$tmp_path/ssh.pem"
        #cat $ipath
    else 
        cat "$skey".pub
    fi

    prevdir=`pwd`
    cd "$dpath"
    git clone "$repository" "$lpath"
    if [ -d "$lpath"/.git ]; then
        echo "Initial setup success"
        exit 0
    else
        echo "Problem with initial setup. See above"
        exit 5
    fi
fi

#Check for the git repository
if [ ! -d "$lpath" ]; then
    echo "Cannot find a git repository at $lpath."
    echo "check ircd.conf path argument, or re-run with -i <repository> to perform initial setup"
    usage
    exit 6
fi

if [ ! -d "$lpath"/.git ]; then
    echo "Error: $lpath is not a git repository. ?!"
    usage
    exit 10
fi

#update the repository from upstream
prevdir=`pwd`
cd "$lpath"
git reset -q --hard origin/master
git pull --quiet
cd "$prevdir"

#Copy the data to the temp file
cp "$lpath/linesync.data" "$TMPFILE"

if [ ! -s "$TMPFILE" ]; then
        echo "Unable find retrieve $lpath/linesync.data, Sorry."
	rm "$TMPFILE" > /dev/null 2>&1
        exit 1
fi

# check our ircd.conf
ircd_setup=`egrep '^# (BEGIN|END) LINESYNC$' "$cpath"|wc -l`
if [ $ircd_setup != 2 ]; then
	cp "$cpath" "$cpath.orig"
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
        } ' "tempfile='$TMPFILE'" < "$cpath" > "$inpath"
else
	inpath="$cpath"
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
' "syncfile='$TMPFILE'" < "$inpath" > "$tmp_path/linesync.new.$TS"

# run a diff between current and new confs to see if we updated anything
# no point sending the ircd a -HUP if this is not needed, especially on a
# busy network, such as Undernet.
diff=`"$diff_cmd" "$cpath" "$tmp_path/linesync.new.$TS"`
if [ ! -z "$diff" ]; then
	# Changes were detected

	# Back up the current ircd.conf and replace it with the new one
	cp "$cpath"  "$dpath/ircd.conf.bk"
	cp "$tmp_path/linesync.new.$TS" "$cpath"

	# Rehash ircd (without caring wether or not it succeeds)
	kill -HUP `cat "$ppath" 2>/dev/null` > /dev/null 2>&1

    #todo: kill iauthd?
fi

# (Try to) clean up
if [ -n "$tmp_path" ] && [ -d "$tmp_path" ]; then
    rm -rf "$tmp_path" > /dev/null 2>&1
fi

# That's it...
