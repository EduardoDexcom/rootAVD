#!/usr/bin/env bash
##########################################################################################
#
# Magisk Boot Image Patcher - original created by topjohnwu and modded by shakalaca's and NewBit
# modded by Eduardo Mejia for Android Studio AVD as a cleaner version
##########################################################################################

###################
# Logging Functions
###################

# Color codes
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Get current timestamp
get_timestamp() {
  date +"%Y-%m-%d %H:%M:%S"
}

# Log with info level (blue)
log_info() {
  echo -e "${BLUE}[$(get_timestamp) INFO]${NC} $1"
}

# Log with warning level (yellow)
log_warning() {
  echo -e "${YELLOW}[$(get_timestamp) WARNING]${NC} $1"
}

# Log with error level (red)
log_error() {
  echo -e "${RED}[$(get_timestamp) ERROR]${NC} $1" >&2
}

# Log with debug level (cyan) - only shown if DEBUG=true
log_debug() {
  if $DEBUG; then
    echo -e "${CYAN}[$(get_timestamp) DEBUG]${NC} $1"
  fi
}

# Log with success level (green)
log_success() {
  echo -e "${GREEN}[$(get_timestamp) SUCCESS]${NC} $1"
}

# Log with a bold highlight
log_highlight() {
  echo -e "${BOLD}[$(get_timestamp) INFO]${NC} $1"
}

# Trace execution (for debug mode)
enable_trace() {
  if $DEBUG; then
    log_debug "Enabling execution tracing"
    set -x
  fi
}

disable_trace() {
  if $DEBUG; then
    log_debug "Disabling execution tracing"
    set +x
  fi
}

###################
# Helper Functions
###################

# Copied 1 to 1 from topjohnwu
getdir() {
  case "$1" in
    */*) dir=${1%/*}; [ -z $dir ] && echo "/" || echo $dir ;;
    *) echo "." ;;
  esac
}

get_flags() {
	log_info "Get Flags"
	if [ -f /system/init -o -L /system/init ]; then
    	SYSTEM_ROOT=true
  	else
    	SYSTEM_ROOT=false
    	grep ' / ' /proc/mounts | grep -qv 'rootfs' || grep -q ' /system_root ' /proc/mounts && SYSTEM_ROOT=true
  	fi

	if [ -z $KEEPVERITY ]; then
		if $SYSTEM_ROOT; then
			KEEPVERITY=true
			log_info "System-as-root, keep dm/avb-verity"
		else
			KEEPVERITY=false
		fi
	fi

	ISENCRYPTED=false
	grep ' /data ' /proc/mounts | grep -q 'dm-' && ISENCRYPTED=true
	[ "$(getprop ro.crypto.state)" = "encrypted" ] && ISENCRYPTED=true

	if [ -z $KEEPFORCEENCRYPT ]; then
		# No data access means unable to decrypt in recovery
		if $ISENCRYPTED || ! $DATA; then
			KEEPFORCEENCRYPT=true
			log_info "Encrypted data, keep forceencrypt"
		else
			KEEPFORCEENCRYPT=false
		fi
	fi

	RECOVERYMODE=false

	if [[ $API -eq 28 ]]; then
		RECOVERYMODE=true
	fi

	export RECOVERYMODE
	export KEEPVERITY
	export KEEPFORCEENCRYPT
	log_info "RECOVERYMODE=$RECOVERYMODE"
	log_debug "KEEPVERITY=$KEEPVERITY"
	log_info "KEEPFORCEENCRYPT=$KEEPFORCEENCRYPT"
}

copyARCHfiles() {
	BINDIR=$BASEDIR/lib/$ABI
	ASSETSDIR=$BASEDIR/assets
	STUBAPK=false

	if [ -e $BINDIR/libstub.so ]; then
		ABI=$ARCH32
		BINDIR=$BASEDIR/lib/$ABI
		log_warning "No 64-Bit Binaries found, please consider Magisk Alpha"
	elif $IS64BIT && ! $IS64BITONLY; then
		log_info "Copy $ARCH32 files to $BINDIR"
		cp $BASEDIR/lib/$ARCH32/lib*32.so $BINDIR 2>/dev/null
	fi

	cd $BINDIR
		for file in lib*.so; do mv "$file" "${file:3:${#file}-6}"; done
	cd $BASEDIR
	log_info "Copy all $ABI files from $BINDIR to $BASEDIR"
	cp $BINDIR/* $BASEDIR 2>/dev/null

	if [ -e $ASSETSDIR/stub.apk ]; then
 		log_info "Copy 'stub.apk' from $ASSETSDIR to $BASEDIR"
 		cp $ASSETSDIR/stub.apk $BASEDIR 2>/dev/null
 		STUBAPK=true
 	fi

	chmod -R 755 $BASEDIR
	export STUBAPK
}

api_level_arch_detect() {
	log_info "API Level and Architecture Detection"
	# Detect version and architecture
	# To select the right files for the patching

	ABI=$(getprop ro.product.cpu.abi)
	ABILIST32=$(getprop ro.product.cpu.abilist32)
	ABILIST64=$(getprop ro.product.cpu.abilist64)

	API=$(getprop ro.build.version.sdk)
	FIRSTAPI=$(getprop ro.product.first_api_level)

	AVERSION=$(getprop ro.build.version.release)

	IS64BIT=false
	IS64BITONLY=false
	IS32BITONLY=false

	if [ "$ABI" = "x86" ]; then
		ARCH=x86
		ARCH32=x86
	elif [ "$ABI" = "arm64-v8a" ]; then
		ARCH=arm64
		ARCH32=armeabi-v7a
		IS64BIT=true
	elif [ "$ABI" = "x86_64" ]; then
		ARCH=x64
		ARCH32=x86
		IS64BIT=true
	else
		ARCH=arm
		ABI=armeabi-v7a
		ABI32=armeabi-v7a
		IS64BIT=false
	fi

	if [ -z "$ABILIST32" ]; then
		IS64BITONLY=true
	fi

	if [ -z "$ABILIST64" ]; then
		IS32BITONLY=true
	fi

	if $IS64BITONLY || $IS32BITONLY ; then
		log_info "Device Platform is ${BOLD}$ARCH only${NC}"
	else
		log_info "Device Platform: ${BOLD}$ARCH${NC}"
		log_info "ARCH32: ${BOLD}$ARCH32${NC}"
	fi

	log_info "Device SDK API: ${BOLD}$API${NC}"
	log_info "First API Level: ${BOLD}$FIRSTAPI${NC}"
	log_highlight "The AVD runs on Android ${BOLD}$AVERSION${NC}"

	[ -d /system/lib64 ] && IS64BIT=true || IS64BIT=false

	export ARCH
  	export ARCH32
	export IS64BIT
	export IS64BITONLY
	export IS32BITONLY
	export ABI
	export API
	export FIRSTAPI
	export AVERSION
}

abort_script() {
	log_error "Aborting the script"
	disable_trace
	exit 1
}

compression_method() {
	local FILE="$1"
	local FIRSTFILEBYTES
	local METHOD_LZ4="02214c18"
	local METHOD_GZ="1f8b0800"
	local ENDG=""
	FIRSTFILEBYTES=$(xxd -p -c8 -l8 "$FILE")
	FIRSTFILEBYTES="${FIRSTFILEBYTES:0:8}"

	if [ "$FIRSTFILEBYTES" == "$METHOD_LZ4" ]; then
		ENDG=".lz4"
	elif [ "$FIRSTFILEBYTES" == "$METHOD_GZ" ]; then
		ENDG=".gz"
	fi
	echo "$ENDG"
}

detect_ramdisk_compression_method() {
	log_info "Detecting ramdisk.img compression"
	RDF=$BASEDIR/ramdisk.img
	CPIO=$BASEDIR/ramdisk.cpio
	CPIOORIG=$BASEDIR/ramdisk.cpio.orig

	local FIRSTFILEBYTES
	local METHOD_LZ4="02214c18"
	local METHOD_GZ="1f8b0800"
	COMPRESS_SIGN=""
	FIRSTFILEBYTES=$(xxd -p -c8 -l8 "$RDF")
	FIRSTFILEBYTES="${FIRSTFILEBYTES:0:8}"
	RAMDISK_LZ4=false
	RAMDISK_GZ=false
	ENDG=""
	METHOD=""

	if [ "$FIRSTFILEBYTES" == "$METHOD_LZ4" ]; then
		ENDG=".lz4"
		METHOD="lz4_legacy"
		RAMDISK_LZ4=true
		log_debug "Found LZ4 compression signature: ${CYAN}$FIRSTFILEBYTES${NC}"
		mv $RDF $RDF$ENDG
		RDF=$RDF$ENDG
		COMPRESS_SIGN="$METHOD_LZ4"
	elif [ "$FIRSTFILEBYTES" == "$METHOD_GZ" ]; then
		ENDG=".gz"
		METHOD="gzip"
		RAMDISK_GZ=true
		log_debug "Found GZIP compression signature: ${CYAN}$FIRSTFILEBYTES${NC}"
		mv $RDF $RDF$ENDG
		#cp $RDF $RDF$ENDG
		COMPRESS_SIGN="$METHOD_GZ"
	fi

	if [ "$ENDG" == "" ]; then
		log_error "Ramdisk.img uses UNKNOWN compression $FIRSTFILEBYTES"
		abort_script
	fi

	log_success "Ramdisk.img uses ${BOLD}$METHOD${NC} compression"
}

runMagisk_to_Patch_fake_boot_img() {
	am force-stop $PKG_NAME
	log_info "Starting Magisk application"
	monkey -p $PKG_NAME -c android.intent.category.LAUNCHER 1 > /dev/null 2>&1
	log_highlight "Install/Patch ${BOLD}$FBI${NC} and hit Enter when done (max. 60s)"
	read -t 60 proceed
	case $proceed in
		*)
		;;
	esac
}

detecting_users() {
	local userID=""
	local userZero=0
	log_info "Detecting current user"
	userID=$(am get-current-user)
	log_info "Current user ${BOLD}$userID${NC}"
	if [ "$userID" != "$userZero" ]; then
		log_info "Switching to user ${BOLD}$userZero${NC}"
		am switch-user $userZero
		userID=$(am get-current-user)
		log_info "Current user ${BOLD}$userID${NC}"
	fi
}

generate_build_prop() {
	log_info "Generating Build.prop"
	local BPR=$BASEDIR/build.prop
	local recfstab=$BASEDIR/recovery.fstab
	getprop > $BPR
	sed -i -e 's/: /=/g' -e 's/\[//g' -e 's/\]//g' $BPR

	log_info "Generating recovery.fstab from fstab.ranchu"
	cp /system/vendor/etc/fstab.ranchu $recfstab

	log_info "Adding Build.prop and recovery.fstab to Stock Ramdisk"
	$BASEDIR/magiskboot cpio $CPIO \
		"add 0644 system/build.prop build.prop" \
		"add 0644 system/etc/recovery.fstab recovery.fstab"
	#BASEDIR=$(pwd)
}

writeLittleEndian() {
	printf "\x${1:6:2}\x${1:4:2}\x${1:2:2}\x${1:0:2}"
}

create_fake_boot_img() {

	if $DEBUG; then
		generate_build_prop
	fi

	log_info "Creating a fake Boot.img"
	FBHI=$BASEDIR/fakebootheader.img
	FBI=$SDCARD/fakeboot.img
	RAMDISK_SZ="$(printf '%08x' $(stat -c%s $CPIO))"
	PAGESIZE=2048
	PAGESIZE_HEX="$(printf '%08x' $PAGESIZE)"

	log_info "Removing old $FBI if exists"
	rm -f $FBI $RDF

	log_debug "Creating boot image header with ANDROID! magic"
	printf "\x41\x4E\x44\x52\x4F\x49\x44\x21" > $FBHI  # ANDROID!
	printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> $FBHI # HEADER_VER KERNEL_SZ
	writeLittleEndian $RAMDISK_SZ >> $FBHI # RAMDISK_SZ

	printf "\x00\x00\x00\x00" >> $FBHI # SECOND_SZ
	printf "\x00\x00\x00\x00\x00\x00\x00\x00" >> $FBHI # EXTRA_SZ
	printf "\x00\x00\x00\x00" >> $FBHI
	writeLittleEndian $PAGESIZE_HEX >> $FBHI # PAGESIZE_HEX

	log_info "Only a minimal header is required for Magisk to repack the ramdisk"
	#mv $RDF $CPIO

	log_info "Repacking ramdisk.img into $FBI"
	$BASEDIR/magiskboot repack $FBHI $FBI > /dev/null 2>&1

	test -f "$FBI"
	RESULT="$?"
	if [[ "$RESULT" != "0" ]]; then
		log_warning "$FBI could not be created with minimal header"
		log_info "Magisk expects a more complete boot.img header as source"

		# fill 00 (to Pagesize 2048)
		log_debug "Filling header to full pagesize (${BOLD}$PAGESIZE${NC} bytes)"
		truncate -s $PAGESIZE $FBHI

		log_info "Adding $CPIO to fakeboot.img header"
		cat $CPIO >> $FBHI

		log_info "Checking filesize padding for Pagesize 2048"

		FBHI_SZ=$(stat -c%s $FBHI)
		FBHI_PAD_SZ=$(( FBHI_SZ / $PAGESIZE ))
		FBHI_PAD_SZ=$(( FBHI_PAD_SZ * $PAGESIZE ))

		if [[ ! $FBHI_PAD_SZ -eq $FBHI_SZ ]]; then
			log_info "Padding filesize to match Pagesize of 2048 Bytes"
			FBHI_PAD_SZ=$(( FBHI_SZ / $PAGESIZE +1))
			FBHI_PAD_SZ=$(( FBHI_PAD_SZ * $PAGESIZE ))
			truncate -s $FBHI_PAD_SZ $FBHI
		fi

		log_info "Repacking ramdisk.img into $FBI with the more complete header"
		$BASEDIR/magiskboot repack $FBHI $FBI > /dev/null 2>&1

		test -f "$FBI"
		RESULT="$?"
		if [[ "$RESULT" != "0" ]]; then
			log_error "$FBI could not be created"
			abort_script
		fi
	fi
	log_success "$FBI created successfully"

	InstallMagiskTemporarily
	detecting_users
	runMagisk_to_Patch_fake_boot_img
	RemoveTemporarilyMagisk
}

unpack_patched_ramdisk_from_fake_boot_img() {

	if [ "$MagiskPatchedFiles" != "" ]; then
		log_success "Magisk patched file(s) found!"
		for file in `ls -tu $SDCARD/*magisk_patched*`; do
			MagiskPatched=$file
			break
		done
		log_info "Unpacking latest ${BOLD}$MagiskPatched${NC}"
		$BASEDIR/magiskboot unpack $MagiskPatched > /dev/null 2>&1
		log_info "Deleting all magisk_patched files"
		for file in `ls -tu $SDCARD/*magisk_patched*`; do
			rm -f $file
		done
	else
		log_error "No magisk_patched file could be found!"
		abort_script
	fi
}

process_fake_boot_img() {

	SDCARD=/sdcard/Download

	log_info "Processing fake Boot.img"
	MagiskPatchedFiles=$(ls "$SDCARD"/*magisk_patched* 2>/dev/null)
	if [ "$MagiskPatchedFiles" != "" ]; then
		log_success "External magisk_patched file(s) found!"
		unpack_patched_ramdisk_from_fake_boot_img
	else
		log_info "No existing magisk_patched files found, creating fake boot image"
		create_fake_boot_img
		MagiskPatchedFiles=$(ls "$SDCARD"/*magisk_patched* 2>/dev/null)
		unpack_patched_ramdisk_from_fake_boot_img
	fi
}

# requires additional setup
construct_environment() {
	ROOT=`su -c "id -u"` 2>/dev/null

	if [[ "$ROOT" == "" ]]; then
		ROOT=$(id -u)
	fi

	log_highlight "Constructing environment - ${BOLD}PAY ATTENTION to the AVDs Screen${NC}"
	if [[ $ROOT -eq 0 ]]; then
		log_success "We are root!"
		local BBBIN=$BB
		local COMMONDIR=$BASEDIR/assets
		local NVBASE=/data/adb
		local MAGISKBIN=$NVBASE/magisk

		log_debug "Setting up Magisk directory at $MAGISKBIN"
		`su -c "rm -rf $MAGISKBIN/* 2>/dev/null && \
				mkdir -p $MAGISKBIN 2>/dev/null && \
				cp -af $BINDIR/. $COMMONDIR/. $BBBIN $MAGISKBIN && \
				chown root.root -R $MAGISKBIN && \
				chmod -R 755 $MAGISKBIN && \
				rm -rf $BASEDIR 2>/dev/null && \
				reboot \
				"`
	fi

	log_error "Not root yet"
	log_error "Couldn't construct environment"
	log_warning "Double Check Root Access"
	log_warning "Re-Run Script with clean ramdisk.img and try again"
	abort_script
}

checkfile() {
	#echo "checkfile $1"
	if [ -r "$1" ]; then
		#echo "File exists and is readable"
		if [ -s "$1" ]; then
			#echo "and has a size greater than zero"
			if [ -w "$1" ]; then
				#echo "and is writable"
				if [ -f "$1" ]; then
					#echo "and is a regular file."
					return 1
				fi
			fi
		fi
	fi
	return 0
}

# If all is done well so far, you can install some APK's to the AVD
# every APK file in the Apps DIR will be (re)installed
# Like magisk.apk etc.
install_apps() {
	local ADBECHO=""
  	APPS="Apps/*"
	log_info "Install all APKs placed in the Apps folder"
	FILES=$APPS

	for f in $FILES; do
		log_highlight "Trying to install $f"
		ADBECHO=""
		while [[ "$ADBECHO" != *"Success"* ]]; do
			ADBECHO=$(adb -s "$EMUDEVICEID" install -r -d "$f" 2>&1)
			if [[ "$ADBECHO" == *"INSTALL_FAILED_UPDATE_INCOMPATIBLE"* ]]; then
				echo "$ADBECHO" | while read I; do log_highlight "$I"; done
				Package=
				for I in $ADBECHO; do
					if [[ "$Package" == *"Package"* ]]; then
						log_highlight "Need to uninstall $I first"
						ADBECHO=$(adb -s "$EMUDEVICEID" uninstall $I 2>&1)
						echo "$ADBECHO" | while read I; do log_highlight "$I"; done
						ADBECHO=$(adb -s "$EMUDEVICEID" install -r -d "$f" 2>&1)
						break
					fi
					Package=$I
				done
			fi
		done
		echo "$ADBECHO" | while read I; do log_highlight "$I"; done
	done
}

pushtoAVD() {
	local SRC=""
	local DST="$2"
	local ADBPUSHECHO=""
	SRC=${1##*/}

	if [[ "$DST" == "" ]]; then
		log_highlight "Push $SRC into $ADBBASEDIR"
		ADBPUSHECHO=$(adb -s "$EMUDEVICEID" push "$1" $ADBBASEDIR 2>/dev/null)
	else
		log_highlight "Push $SRC into $ADBBASEDIR/$DST"
		ADBPUSHECHO=$(adb -s "$EMUDEVICEID" push "$1" $ADBBASEDIR/$DST 2>/dev/null)
	fi

	log_info "$ADBPUSHECHO"
}

pullfromAVD() {
	local SRC=""
	local DST=""
	local ADBPULLECHO=""
	SRC=${1##*/}
	DST=${2##*/}
	ADBPULLECHO=$(adb -s "$EMUDEVICEID" pull $ADBBASEDIR/$SRC "$2" 2>/dev/null)
	if [[ ! "$ADBPULLECHO" == *"error"* ]]; then
		log_highlight "Pull $SRC into $DST"
  		log_info "$ADBPULLECHO"
	fi
}

create_backup() {
	local FILE=""
	local FILEPATH=""
	local FILENAME=""
	local BACKUPFILE=""
	FILE="$1"
	FILEPATH=${FILE%/*}
	FILENAME=${FILE##*/}
	BACKUPFILE="$FILENAME.backup"

	cd "$FILEPATH" > /dev/null
		# If no backup file exist, create one
		if ( checkfile $BACKUPFILE -eq 0 ); then
			log_highlight "create Backup File of $FILENAME"
			cp $FILENAME $BACKUPFILE
		else
			log_info "$FILENAME Backup exists already"
		fi
	cd - > /dev/null
}

restore_backups() {
	local BACKUPFILE=""
	local RESTOREFILE=""

	cd "$1" > /dev/null
		for f in $(find . -type f -name '*.backup'); do
			BACKUPFILE="$f"
			RESTOREFILE="${BACKUPFILE%.backup}"
			log_info "Restoring ${BACKUPFILE##*/} to ${RESTOREFILE##*/}"
			cp $BACKUPFILE $RESTOREFILE
		done
	cd - > /dev/null

	if [ "$f" == "" ]; then
		log_highlight "No Backup(s) to restore"
	else
		log_highlight "Backups still remain in place"
	fi
	exit 0
}

toggle_Ramdisk() {

	#AVDPATHWITHRDFFILE="$1"
	#AVDPATH=${AVDPATHWITHRDFFILE%/*}
	#RDFFILE=${AVDPATHWITHRDFFILE##*/}
	#RESTOREPATH=$AVDPATH

	local RamdiskFile="$AVDPATHWITHRDFFILE"
	local PatchedFile="$AVDPATHWITHRDFFILE.patched"
	local BackupFile="$AVDPATHWITHRDFFILE.backup"

	local hasBackup=false
	local hasPatched=false

	if ( checkfile "$BackupFile" -eq 0 ); then
		log_info "we need a valid backup file to proceed"
		exit 0
	fi

	log_info "Toggle Ramdisk"
	if ( checkfile "$PatchedFile" -eq 0 ); then
		log_highlight "Pushing patched Ramdisk into Stack"
		mv "$RamdiskFile" "$PatchedFile"
		log_highlight "Popping original Ramdisk from Backup"
		cp "$BackupFile" "$RamdiskFile"
	else
		log_highlight "Popping patched Ramdisk back from Stack"
		mv -f "$PatchedFile" "$RamdiskFile"
	fi
	exit 0
}

TestADB() {

	local ADB_EX=""
	local exportedADB=false

	while true; do
		log_info "Testing if ADB SHELL is working"
		ADBWORKS=$(which adb)
		if [ "$ADBWORKS" == *"not found"* ] || [ "$ADBWORKS" == "" ]; then
			if [ ! -d "$ANDROIDHOME/$ADB_DIR" ]; then
				log_error "ADB not found, please install and add it to your \$PATH"
                abort_script
			fi

			cd "$ANDROIDHOME" > /dev/null
				for adb in $(find "$ADB_DIR" -type f -name adb); do
					ADB_EX="$ANDROIDHOME/$adb"
				done
			cd - > /dev/null

			if [[ "$ADB_EX" == "" ]]; then
				log_error "ADB binary not found in $ENVVAR/$ADB_DIR"
                abort_script
			fi

			log_warning "ADB is not in your Path, try to:"
			log_warning "${BOLD}export PATH=$ENVVAR/$ADB_DIR:\$PATH${NC}"

			if $exportedADB; then
				log_error "Export didn't work"
				break
			fi

			if ( ! checkfile "$ADB_EX" -eq 0 ); then
				log_info "Setting ADB path just during this session for you"
				export "PATH=$ANDROIDHOME/$ADB_DIR:$PATH"
				exportedADB=true
			fi
		else
			break
		fi
	done

	ADBWORKS=$(adb -s "$EMUDEVICEID" shell 'echo true' 2>/dev/null)
	if [ -z "$ADBWORKS" ]; then
		log_error "No ADB connection possible"
        abort_script
	elif [[ "$ADBWORKS" == "true" ]]; then
		log_success "ADB connection established successfully"
	fi
}

ShutDownAVD() {

    log_info "Shut-Down & Reboot (Cold Boot Now) the AVD and see if it worked"
    log_info "Root and Su with Magisk for Android Studio AVDs"

    ADBPULLECHO=$(adb -s "$EMUDEVICEID" shell setprop sys.powerctl shutdown 2>/dev/null)
    if [[ ! "$ADBPULLECHO" == *"error"* ]]; then
        log_info "Trying to shut down the AVD"
    fi
    log_warning "If the AVD doesn't shut down, try it manually!"
	
	log_info "Modded by Eduardo Mejia"
	log_success "Huge Credits and big Thanks to topjohnwu, shakalaca, vvb2060, NewBit and HuskyDG"
	
	# Finalize logging
	disable_trace
}

GetAVDPKGRevision() {
	local sourcepropfile="source.properties"
	if [[ -d "$AVDPATH" ]]; then
		cd "$AVDPATH" > /dev/null
			# If a source.properties file exist, try to find the Pkg.Revision number
			if ( ! checkfile $sourcepropfile -eq 0 ); then
				log_info "source.properties file exist"
				log_highlight "AVD system-image $(grep 'Pkg.Revision=' $sourcepropfile)"
			fi
		cd - > /dev/null
	fi
}

CopyMagiskToAVD() {
    echo "Arguments passed to CopyMagiskToAVD:"
    for arg in "$@"; do
        echo " - [$arg]"
    done
    echo "1- $1"
	# Set Folders and FileNames
    log_info "Set Directorys"
    AVDPATHWITHRDFFILE="$ANDROIDHOME/$1"
    AVDPATH=${AVDPATHWITHRDFFILE%/*}
    RDFFILE=${AVDPATHWITHRDFFILE##*/}
    RESTOREPATH=$AVDPATH

	if ( "$restore" ); then
		restore_backups "$RESTOREPATH"
	fi

	if ( "$toggleRamdisk" ); then
		toggle_Ramdisk "$RESTOREPATH"
	fi

	GetAVDPKGRevision
	TestADB

	# The Folder where the script was called from
	ROOTAVD="`getdir "${BASH_SOURCE:-$0}"`"
	MAGISKZIP=$ROOTAVD/Magisk.zip

	# change to ROOTAVD directory
	cd "$ROOTAVD"

	# Kernel Names
	BZFILE=$ROOTAVD/bzImage
	KRFILE=kernel-ranchu

	if ( "$InstallApps" ); then
		install_apps
		exit
	fi

	ADBWORKDIR=/data/data/com.android.shell
	adb -s "$EMUDEVICEID" shell "cd $ADBWORKDIR" 2>/dev/null

	if [ "$?" != "0" ]; then
    log_warning "$ADBWORKDIR doesn't exist, switching to tmp'"
		ADBWORKDIR=/data/local/tmp
	fi

	ADBBASEDIR=$ADBWORKDIR/Magisk
    log_info "In any AVD via ADB, you can execute code without root in $ADBWORKDIR"

    log_highlight "Cleaning up the ADB working space"
	adb -s "$EMUDEVICEID" shell rm -rf $ADBBASEDIR

    log_highlight "Creating the ADB working space"
	adb -s "$EMUDEVICEID" shell mkdir $ADBBASEDIR

	# If Magisk.zip file doesn't exist, just ignore it
	if ( ! checkfile "$MAGISKZIP" -eq 0 ); then
    log_info "Magisk installer Zip exists already"
		pushtoAVD "$MAGISKZIP"
	fi

	# Proceed with ramdisk
	if "$RAMDISKIMG"; then
		# Is it a ramdisk named img file?
		if [[ "$RDFFILE" != ramdisk*.img ]]; then
        log_warning "Please give a path to a ramdisk file"
            abort_script
		fi

		create_backup "$AVDPATHWITHRDFFILE"
		pushtoAVD "$AVDPATHWITHRDFFILE" "ramdisk.img"

		if ( "$InstallKernelModules" ); then
			INITRAMFS=$ROOTAVD/initramfs.img
			if ( ! checkfile "$INITRAMFS" -eq 0 ); then
				pushtoAVD "$INITRAMFS"
			fi
		fi

		if ( "$AddRCscripts" ); then
			for f in $ROOTAVD/*.rc; do
				pushtoAVD "$f"
			done
			pushtoAVD "$ROOTAVD/sbin"
		fi
	fi

	pushtoAVD "rootAVD.sh"

	if ( "$UpdateBusyBoxScript" ); then
		pushtoAVD "libbusybox*.so"
	fi

    log_info "Run the actually Boot/Ramdisk/Kernel Image Patch Script"
    log_highlight "From Magisk by topjohnwu and NewBit, modded by Eduardo Mejia"

	adb -s "$EMUDEVICEID" shell sh $ADBBASEDIR/rootAVD.sh $@
	if [ "$?" == "0" ]; then

		if ( "$UpdateBusyBoxScript" ); then
			pullfromAVD "bbscript.sh" "rootAVD.sh"
			chmod +x rootAVD.sh
			exit
		fi

		# In Debug-Mode we can skip parts of the script
		if ( ! "$DEBUG" && "$RAMDISKIMG" ); then

			pullfromAVD "ramdiskpatched4AVD.img" "$AVDPATHWITHRDFFILE"
			pullfromAVD "Magisk.apk" "Apps/"
			pullfromAVD "Magisk.zip" "$ROOTAVD"

			if ( "$InstallPrebuiltKernelModules" ); then
				pullfromAVD "$BZFILE" "$ROOTAVD"
				InstallKernelModules=true
			fi

			if ( "$InstallKernelModules" ); then
				if ( ! checkfile "$BZFILE" -eq 0 ); then
					create_backup "$AVDPATH/$KRFILE"
                    log_highlight "Copy $BZFILE (Kernel) into kernel-ranchu"
					cp $BZFILE $AVDPATH/$KRFILE
					if [ "$?" == "0" ]; then
						rm -f $BZFILE $INITRAMFS
					fi
				fi
			fi

            log_info "Clean up the ADB working space"
			adb -s "$EMUDEVICEID" shell rm -rf $ADBBASEDIR

			install_apps
			ShutDownAVD
		fi
	fi
}

###################################################
# Method to extract specified field data from json
# Globals: None
# Arguments: 2
#   ${1} - value of field to fetch from json
#   ${2} - Optional, nth number of value from extracted values, by default shows all.
# Input: file | here string | pipe
#   _json_value "Arguments" < file
#   _json_value "Arguments <<< "${varibale}"
#   echo something | _json_value "Arguments"
# Result: print extracted value
###################################################
json_value() {
    $BB grep -o "\"""${1}""\"\:.*" | $BB sed -e "s/.*\"""${1}""\": //" -e 's/[",]*$//' -e 's/["]*$//' -e 's/[,]*$//' -e "s/\"//" -n -e "${2}"p
}

CheckAVDIsOnline() {
	if [ -z $AVDIsOnline ]; then
    log_info "Checking AVDs Internet connection..."
		AVDIsOnline=false
		$BB timeout 3 $BB wget -q --spider --no-check-certificate http://github.com > /dev/null 2>&1
		if [ $? -eq 0 ]; then
    		AVDIsOnline=true
    	else
        log_info "Checking AVDs Internet connection another way..."
			echo -e "GET http://google.com HTTP/1.0\n\n" | $BB timeout 3 $BB nc -v google.com 80 > /dev/null 2>&1
    		if [ $? -eq 0 ]; then
				AVDIsOnline=true
			fi
		fi
        $AVDIsOnline && log_success "AVD is online" || log_warning "AVD is offline"
	fi
	export AVDIsOnline
}

GetPrettyVer() {
		if echo $1 | $BB grep -q '\.'; then
			PRETTY_VER=$1
		else
			PRETTY_VER="$1($2)"
		fi
		echo "$PRETTY_VER"
}

DownLoadFile() {
	CheckAVDIsOnline
	if ("$AVDIsOnline"); then
		local URL="$1"
		local SRC="$2"
		local DST="$3"

		OF=$BASEDIR/download.tmp
		rm -f $OF
		BS=1024
		CUTOFF=100

		if [ "$DST" == "" ]; then
			DST=$BASEDIR/$SRC
		else
			DST=$BASEDIR/$DST
		fi
        log_highlight "Downloading File $SRC"
		$BB wget -q -O $DST --no-check-certificate $URL$SRC
		RESULT="$?"
		while [ $RESULT != "0" ]
		do
            log_warning "Error while downloading File $SRC"
            log_info "Patching it together"
			FSIZE=$(./busybox stat $DST -c %s)
			if [ $FSIZE -gt $BS ]; then
				COUNT=$(( FSIZE/BS ))
				if [ $COUNT -gt $CUTOFF ]; then
					COUNT=$(( COUNT - $CUTOFF ))
				fi
			fi
			$BB dd if=$DST count=$COUNT bs=$BS of=$OF > /dev/null 2>&1
			mv -f $OF $DST
			$BB wget -q -O $DST --no-check-certificate $URL$SRC -c
			RESULT="$?"
		done
        log_success "Downloading File $SRC complete!"
	fi
}

GetUSBHPmod() {
	USBHPZSDDL="/sdcard/Download/usbhostpermissons.zip"
	USBHPZ="https://github.com/newbit1/usbhostpermissons/releases/download/v1.0/usbhostpermissons.zip"
	if [ ! -e $USBHPZSDDL ]; then
        log_highlight "Downloading USB HOST Permissions Module Zip"
		$BB wget -q -O $USBHPZSDDL --no-check-certificate $USBHPZ
	else
        log_highlight "USB HOST Permissions Module Zip is already present"
	fi
}

FetchMagiskDLData() {
	local SRCURL="$1"
	local CHANNEL="$2"
	local JSON="$CHANNEL.json"
	local VER=""
	local VER_CODE=""
	local DLL=""
	local i=1

	rm -rf *.json > /dev/null 2>&1
	$BB wget -q --no-check-certificate $SRCURL$JSON
	VER=$(json_value "version" < $JSON)
	VER_CODE=$(json_value "versionCode" 1 < $JSON)
	DLL=$(json_value "link" 1 < $JSON)
	VER=$(GetPrettyVer $VER $VER_CODE)

	if ! echo $DLL | $BB grep -q 'https'; then
		DLL=$SRCURL$DLL
	fi

	if [ -e $MAGISK_DL_LINKS ]; then
		echo $DLL >> $MAGISK_DL_LINKS
		echo $VER >> $MAGISK_VERSIONS
		echo $CHANNEL >> $MAGISK_CHANNEL
		i=$($BB sed -n '$=' $MAGISK_DL_LINKS)
		echo "[$i] $CHANNEL $VER" >> $MAGISK_MENU
	else
		if [[ "$MAGISK_LOCL_VER" != "" ]]; then
			echo "local" > $MAGISK_DL_LINKS
			echo $MAGISK_LOCL_VER > $MAGISK_VERSIONS
			echo "local "$CHANNEL > $MAGISK_CHANNEL
			echo "[$i] local $CHANNEL $MAGISK_LOCL_VER (ENTER)" > $MAGISK_MENU
			i=$((i+1))
		fi
		echo $DLL >> $MAGISK_DL_LINKS
		echo $VER >> $MAGISK_VERSIONS
		echo $CHANNEL >> $MAGISK_CHANNEL
		if [[ "$i" == "1" ]]; then

			echo "[$i] $CHANNEL $VER (ENTER)" >> $MAGISK_MENU
		else
			#echo $CHANNEL > $MAGISK_CHANNEL
			echo "[$i] $CHANNEL $VER" >> $MAGISK_MENU
		fi
	fi
	rm -rf *.json > /dev/null 2>&1
}

FetchMagiskRLCommits() {
#$GITHUB $TJWCOMMITSURL $TJWBLOBURL $CHANNEL $TJWREPOURL
	local DOMAIN="$1"
	local COMMITSURL="$2"
	local BLOBURL="$3"
	local CHANNEL="$4"
	local JSON="$CHANNEL.json"
	local REPOURL="$5"
	local COMMITS=""

	rm -rf $JSON
	$BB wget -q --no-check-certificate $DOMAIN$COMMITSURL$JSON

	COMMITS=$($BB grep $BLOBURL $JSON | $BB sed -e 's,.*'"$BLOBURL"',,' -e 's,'"$JSON"'.*,,')

	for commit in $COMMITS;do
		FetchMagiskDLData $RAWGITHUB$REPOURL$commit $CHANNEL
	done
}

CheckAvailableMagisks() {

	MAGISK_VERSIONS=$BASEDIR/magisk_versions.txt
	MAGISK_DL_LINKS=$BASEDIR/magisk_dl_links.txt
	MAGISK_MENU=$BASEDIR/magisk_menu.txt
	MAGISK_CHANNEL=$BASEDIR/magisk_channel.txt

	local GITHUB="https://github.com/"
	RAWGITHUB="https://raw.githubusercontent.com/"
	local TJWREPOURL="topjohnwu/magisk-files/"
	local TJWCOMMITSURL="topjohnwu/magisk-files/commits/master/"
	local TJWBLOBURL="topjohnwu/magisk-files/blob/"

	local VVB2060REPOURL="vvb2060/magisk_files/"
	local VVB2060COMMITSURL="vvb2060/magisk_files/commits/alpha/"
	local VVB2060BLOBURL="vvb2060/magisk_files/blob/"
	local DLL_cnt=0

	if [ -z $MAGISKVERCHOOSEN ]; then

		UFSH=$BASEDIR/assets/util_functions.sh
		OF=$BASEDIR/download.tmp
		BS=1024
		CUTOFF=100

		if [ -e $UFSH ]; then
			MAGISK_LOCL_VER=$($BB grep $UFSH -e "MAGISK_VER" -w | sed 's/^.*=//')
			MAGISK_LOCL_VER_CODE=$($BB grep $UFSH -e "MAGISK_VER_CODE" -w | sed 's/^.*=//')
			MAGISK_LOCL_VER=$(GetPrettyVer $MAGISK_LOCL_VER $MAGISK_LOCL_VER_CODE)
		else
			MAGISK_LOCL_VER=""
			MAGISK_LOCL_VER_CODE=""
		fi

		CheckAVDIsOnline
		if ("$AVDIsOnline"); then
            log_highlight "Checking available Magisk Versions"

			rm *.txt > /dev/null 2>&1

			FetchMagiskDLData $RAWGITHUB$TJWREPOURL"master/" "stable"
			FetchMagiskDLData $RAWGITHUB$TJWREPOURL"master/" "canary"
			FetchMagiskDLData $RAWGITHUB$VVB2060REPOURL"alpha/" "alpha"

			while :
			do
				DLL_cnt=$($BB sed -n '$=' $MAGISK_DL_LINKS)
                log_warning "Choose a Magisk Version to install and make it local"
				echo "[s] (s)how all available Magisk Versions"
				cat $MAGISK_MENU
				read -t 10 choice
				case $choice in
					*)
						if [[ "$choice" == "" ]]; then
							choice=1
						fi

						if [[ $choice -gt 0 && $choice -le $DLL_cnt ]]; then
							MAGISK_VER=$($BB sed "$choice"'!d' $MAGISK_VERSIONS)
							MAGISK_CNL=$($BB sed "$choice"'!d' $MAGISK_CHANNEL)
                            log_info "You choose Magisk $MAGISK_CNL Version $MAGISK_VER"

							MAGISK_DL=$($BB sed "$choice"'!d' $MAGISK_DL_LINKS)
							if [[ "$MAGISK_DL" == "local" ]]; then
								MAGISKVERCHOOSEN=false
							fi
							break
						fi

						if [[ "$choice" == "s" ]]; then
                            log_info "Fetching all available Magisk Versions..."
							rm *.txt > /dev/null 2>&1
							FetchMagiskRLCommits $GITHUB $TJWCOMMITSURL $TJWBLOBURL "stable" $TJWREPOURL
							FetchMagiskRLCommits $GITHUB $TJWCOMMITSURL $TJWBLOBURL "canary" $TJWREPOURL
							FetchMagiskRLCommits $GITHUB $VVB2060COMMITSURL $VVB2060BLOBURL "alpha" $VVB2060REPOURL
						else
                            log_error "Invalid option $choice"
						fi
						;;
 				esac
			done
		else
			MAGISK_VER=$MAGISK_LOCL_VER
			MAGISKVERCHOOSEN=false
		fi

		if [ -z $MAGISKVERCHOOSEN ]; then
            log_highlight "Deleting local Magisk $MAGISK_LOCL_VER"
			rm -rf $MZ
			rm -rf *.apk
            log_highlight "Downloading Magisk $MAGISK_CNL $MAGISK_VER"
			$BB wget -q -O $MZ --no-check-certificate $MAGISK_DL
			RESULT="$?"
			while [ $RESULT != "0" ]; do
                log_warning "[!] Error while downloading Magisk $MAGISK_CNL $MAGISK_VER"
                log_info "Patching it together"
				FSIZE=$(./busybox stat $MZ -c %s)
				if [ $FSIZE -gt $BS ]; then
					COUNT=$(( FSIZE/BS ))
					if [ $COUNT -gt $CUTOFF ]; then
						COUNT=$(( COUNT - $CUTOFF ))
					fi
				fi
				$BB dd if=$MZ count=$COUNT bs=$BS of=$OF > /dev/null 2>&1
				mv -f $OF $MZ
				$BB wget -q -O $MZ --no-check-certificate $MAGISK_DL -c
				RESULT="$?"
			done
            log_success "Downloading Magisk $MAGISK_CNL $MAGISK_VER complete!"
			MAGISKVERCHOOSEN=true
			PrepBusyBoxAndMagisk
		fi

		# Call rootAVD with GetUSBHPmodZ to download the usbhostpermissons module
		$GetUSBHPmodZ && $AVDIsOnline && GetUSBHPmod
	fi
	export MAGISK_VER
	export MAGISKVERCHOOSEN
	export UFSH
}

InstallMagiskTemporarily() {
	magiskispreinstalled=false

    log_highlight "Searching for pre installed Magisk Apps"
	PKG_NAMES=$(pm list packages magisk | cut -f 2 -d ":") > /dev/null 2>&1
	PKG_NAME=""
	local MAGISK_PKG_VER_CODE=""
	local MAGISK_ZIP_VER_CODE=""

	if [[ "$PKG_NAMES" == "" ]]; then
        log_info "Temporarily installing Magisk"
		pm install -r $MZ >/dev/null 2>&1
		PKG_NAME=$(pm list packages magisk | cut -f 2 -d ":") > /dev/null 2>&1
	else
		PKG_NAME=$PKG_NAMES

		$(pm dump --help > /dev/null 2>&1)
		RESULT="$?"

		if [[ "$RESULT" == "0" ]]; then
			MAGISK_PKG_VER_CODE=$(pm dump $PKG_NAME | grep versionCode= | sed 's/.*versionCode=\([0-9]\{1,\}\).*/\1/')
			#echo "MAGISK_PKG_VER_CODE=$MAGISK_PKG_VER_CODE"
			MAGISK_ZIP_VER_CODE=$(grep $UFSH -e "MAGISK_VER_CODE" -w | sed 's/^.*=//')
			#echo "MAGISK_ZIP_VER_CODE=$MAGISK_ZIP_VER_CODE"
			#echo "PKG_NAME=$PKG_NAME"
		fi

		if [[ "$MAGISK_PKG_VER_CODE" != "$MAGISK_ZIP_VER_CODE" ]]; then
            log_info "Magisk Versions differ"
            log_highlight "Exchanging pre installed Magisk App Version $MAGISK_PKG_VER_CODE"
			pm clear $PKG_NAME >/dev/null 2>&1
			pm uninstall $PKG_NAME >/dev/null 2>&1
            log_highlight "With the Magisk App Version $MAGISK_ZIP_VER_CODE"
			pm install -r $MZ >/dev/null 2>&1
			PKG_NAME=$(pm list packages magisk | cut -f 2 -d ":") > /dev/null 2>&1
		fi
		if [[ "$MAGISK_PKG_VER_CODE" == "" ]]; then
            log_info "Found a pre installed Magisk App, use it"
		else
            log_info "Found a pre installed Magisk App Version $MAGISK_PKG_VER_CODE, use it"
		fi
		magiskispreinstalled=true
	fi
}

RemoveTemporarilyMagisk() {

	if ! $magiskispreinstalled; then
        log_info "Removing Temporarily installed Magisk"
		pm clear $PKG_NAME >/dev/null 2>&1
		pm uninstall $PKG_NAME >/dev/null 2>&1
	fi
}

TestingBusyBoxVersion() {

	local busyboxworks=false
	local RESULT=""
    log_highlight "Testing Busybox $1"

	rm -fR $TMP
	mkdir -p $TMP

	cd $TMP > /dev/null
		$(ASH_STANDALONE=1 $1 sh -c 'grep' > /dev/null 2>&1)
		RESULT="$?"
		if [[ "$RESULT" != "255" ]]; then
			$($1 unzip $MZ -oq > /dev/null 2>&1)
			RESULT="$?"
			if [[ "$RESULT" != "0" ]]; then
                log_info "Busybox binary does not support extracting Magisk.zip"
			else
				busyboxworks=true
			fi
		fi
	cd - > /dev/null

	rm -fR $TMP
	$busyboxworks && return 0 || return 1
}

FindWorkingBusyBox() {
    log_highlight "Finding a working Busybox Version"
	local bbversion=""
	local RESULT=""

	for file in $(ls $BASEDIR/lib/*/*busybox*); do
		chmod +x "$file"
		bbversion=$($file | $file head -n 1)>/dev/null 2>&1
		if [[ $bbversion == *"BusyBox"*"Magisk"*"multi-call"* ]]; then
			TestingBusyBoxVersion "$file"
			RESULT="$?"
			if [[ "$RESULT" == "0" ]]; then
                log_info "Found a working Busybox Version"
				log_info "$bbversion"
				export WorkingBusyBox="$file"
				return
			fi
		fi
	done
    log_warning "Can not find any working Busybox Version"
	abort_script
}

ExtractMagiskViaPM() {
	InstallMagiskTemporarily
	PKG_PATH=$(pm path $PKG_NAME)
	PKG_PATH=${PKG_PATH%/*}
	PKG_PATH=${PKG_PATH#*:}
	log_highlight "Copy Magisk Lib Files to workdir"
	cp -Rf $PKG_PATH/lib $BASEDIR/
	RemoveTemporarilyMagisk
}

DownloadUptoDateSript() {
	log_highlight "Trying to Download the Up-To-Date Script Version"

	local DLL_URL="https://github.com/newbit1/rootAVD/raw/master/"
	local DLL_SCRIPT="rootAVD.sh"
	local DLL_ROOTAVD_ZIP="https://github.com/newbit1/rootAVD/archive/refs/heads/master.zip"
	local PKG_PATH=""

	ExtractMagiskViaPM
	FindWorkingBusyBox
	CopyBusyBox
	DownLoadFile $DLL_URL $DLL_SCRIPT
}

ExtractBusyboxFromScript() {
	local BBSCR=$BASEDIR/bbscript.sh
	local bblineoffset=""
	local last_line=""
	local bbline_cnt=""
	cp $0 $BBSCR

	bblineoffset=$(sed -n '/BUSYBOXBINARY/=' $BBSCR | sort -nr)
	bbline_cnt=$(sed -n '/BUSYBOXBINARY/=' $BBSCR | sort -nr | sed -n '$=')

	if [[ "$bbline_cnt" -gt "3" ]]; then
		log_highlight "Extracting busybox from script ..."
		for i in $bblineoffset;do
			cp $BBSCR busybox
			sed -i 1,"$i"'d',"$i"'q' $BB
			$($BB >/dev/null 2>&1)
			if [[ "$?" == "0" ]]; then
				log_info "Found a working busybox Binary: $file"
				log_info "$($BB | $BB head -n 1)"
				break
			fi
		done
	fi

	$($BB >/dev/null 2>&1)
	if [[ ! "$?" == "0" ]]; then
		log_info "There is no busybox behind the script"
		#log_info "Run rootAVD with UpdateBusyBoxScript first"
		DownloadUptoDateSript
	fi
}

UpdateBusyBoxToScript() {
	local BBSCR=$BASEDIR/bbscript.sh
	local FSIZE=""
	local last_line=""
	cp $0 $BBSCR
	chmod +x libbusybox*.so

	# Find the first working busybox binary
	for file in libbusybox*.so; do
		cp -fF $file $BB
		$($BB >/dev/null 2>&1)
		if [[ "$?" == "0" ]]; then
			log_info "Found a working busybox Binary: $file"
			log_info "$($BB | $BB head -n 1)"
			break
		fi
	done

	$($BB >/dev/null 2>&1)
	if [[ ! "$?" == "0" ]]; then
		log_info "Can't find a working busybox Binary"
		exit 0
	fi

	# Add every provided busybox binary behind the script
	for file in libbusybox*.so; do
		echo "" >> $BBSCR
		echo "###BUSYBOXBINARY###" >> $BBSCR
		FSIZE=$(./busybox stat $BBSCR -c %s)
		$BB dd if=$file oflag=seek_bytes seek=$FSIZE of=$BBSCR > /dev/null 2>&1
	done

	#sed -i "$((bblineoffset+1))","$last_line"'d' $BBSCR
}

CopyBusyBox() {
	log_highlight "Copy busybox from lib to workdir"
# 	if [ -e $BASEDIR/lib ]; then
# 		chmod -R 755 $BASEDIR/lib
# 		cp -f $BASEDIR/lib/$ABI/libbusybox.so $BB >/dev/null 2>&1
# 		$BB >/dev/null 2>&1 && return || cp -f $BASEDIR/lib/$ARCH32/libbusybox.so $BB >/dev/null 2>&1
# 		$BB >/dev/null 2>&1 && return || cp -f $BASEDIR/lib/$ARCH/libbusybox.so $BB >/dev/null 2>&1
# 	fi
	cp -fF $WorkingBusyBox $BB >/dev/null 2>&1
	chmod +x $BB
}

MoveBusyBox() {
	log_highlight "Move busybox from lib to workdir"
# 	if [ -e $BASEDIR/lib ]; then
# 		chmod -R 755 $BASEDIR/lib
# 		mv -f $BASEDIR/lib/$ABI/libbusybox.so $BB >/dev/null 2>&1
# 		$BB >/dev/null 2>&1 && return || mv -f $BASEDIR/lib/$ARCH32/libbusybox.so $BB >/dev/null 2>&1
# 		$BB >/dev/null 2>&1 && return || mv -f $BASEDIR/lib/$ARCH/libbusybox.so $BB >/dev/null 2>&1
# 	fi
	mv -f $WorkingBusyBox $BB >/dev/null 2>&1
	chmod +x $BB
}

FindUnzip() {
	local RESULT=""
	if [ -e $MZ ]; then
		log_highlight "Looking for an unzip binary"
		$(which unzip > /dev/null 2>&1)
		RESULT="$?"

		if [[ "$RESULT" == "0" ]]; then
			log_info "unzip binary found"
			log_highlight "Extracting busybox and Magisk.zip via unzip ..."
			$(unzip $MZ -oq > /dev/null 2>&1)
			RESULT="$?"
			if [[ "$RESULT" != "0" ]]; then
				log_info "unzip binary does not support extracting Magisk.zip"
                abort_script
			else
				FindWorkingBusyBox
			fi
		else
			log_info "No unzip binary found"
		fi

		if [[ "$RESULT" != "0" ]]; then
			ExtractMagiskViaPM
			FindWorkingBusyBox
			CopyBusyBox
			log_highlight "Extracting Magisk.zip via Busybox ..."
			$($BB unzip $MZ -oq > /dev/null 2>&1)
			RESULT="$?"
			if [[ "$RESULT" != "0" ]]; then
				log_info "Busybox binary does not support extracting Magisk.zip"
                abort_script
			fi
		fi
	else
		log_info "No Magisk.zip present"
        abort_script
	fi
}

PrepBusyBoxAndMagisk() {
	log_info "Switch to the location of the script file"
	BASEDIR="`getdir "${BASH_SOURCE:-$0}"`"
	if [[ "$BASEDIR" == "." ]]; then
		BASEDIR=$(pwd)
	fi
	TMP=$BASEDIR/tmp
	BB=$BASEDIR/busybox
	MZ=$BASEDIR/Magisk.zip
	cd $BASEDIR

	if ("$UpdateBusyBoxScript"); then
		UpdateBusyBoxToScript $@
        abort_script
	fi

	rm -rf lib assets
	FindUnzip
	MoveBusyBox

	chmod -R 755 $BASEDIR
	CheckAvailableMagisks
}

ExecBusyBoxAsh() {
	export PREPBBMAGISK=1
	export ASH_STANDALONE=1
	export BASEDIR
	export TMP
	export BB
	export MZ

	log_info "Re-Running rootAVD in Magisk Busybox STANDALONE (D)ASH"
	log_debug "BASEDIR=${CYAN}$BASEDIR${NC}"
	log_debug "BB=${CYAN}$BB${NC}"
	log_debug "MZ=${CYAN}$MZ${NC}"
	log_debug "TMP=${CYAN}$TMP${NC}"
	exec $BB sh $0 $@
}

repack_ramdisk() {
	log_highlight "Repacking ramdisk .."
	cd $TMP/ramdisk > /dev/null
		`find . | cpio -H newc -o > $CPIO`
	cd - > /dev/null
}

extract_patched_ramdisk() {
log_info "Clearing $TMP/ramdisk"
rm -fR $TMP/ramdisk
mkdir -p $TMP/ramdisk

cd $TMP/ramdisk > /dev/null
	$BASEDIR/busybox cpio -F $CPIO -i *lib* > /dev/null 2>&1
	../../magiskboot cpio ../../ramdisk.cpio "rm -r /lib/modules/*"
	ls -la
cd - > /dev/null
exit
}

extract_stock_ramdisk() {
log_info "Clearing $TMP/ramdisk"
rm -fR $TMP/ramdisk
mkdir -p $TMP/ramdisk

cd $TMP/ramdisk > /dev/null
	log_highlight "Extracting Stock ramdisk"
	$BASEDIR/busybox cpio -F $CPIO -i > /dev/null 2>&1
cd - > /dev/null
}

decompress_ramdisk(){
	log_info "taken from shakalaca's MagiskOnEmulator/process.sh"
	log_highlight "executing ramdisk splitting / extraction / repacking"
	# extract and check ramdisk
	if [[ $API -ge 30 ]]; then
		$RAMDISK_GZ && gzip -fdk $RDF$ENDG
		log_info "API level greater then 30"
		log_highlight "Check if we need to repack ramdisk before patching .."
		COUNT=`strings -t d $RDF | grep TRAILER\!\! | wc -l`
	  if [[ $COUNT -gt 1 ]]; then
		log_info "Multiple cpio archives detected"
		REPACKRAMDISK=1
	  fi
	fi

	if [[ -n "$REPACKRAMDISK" ]]; then
		$RAMDISK_GZ && rm $RDF$ENDG
	  	log_highlight "Unpacking ramdisk .."
	  	mkdir -p $TMP/ramdisk
	  	LASTINDEX=0
	  	NextArchiveINDEX=0
	  	IBS=1
	  	OBS=4096
	  	OF=$TMP/temp$ENDG

	  	RAMDISKS=`strings -t d $RDF | grep TRAILER | sed 's|TRAILER.*|TRAILER|'`

	  	for OFFSET in $RAMDISKS; do

			# calculate offset to next archive
			if [ `echo "$OFFSET" | grep TRAILER` ]; then
				# find position of end of TRAILER!!! string in image

				if $RAMDISK_GZ; then
					LEN=${#OFFSET}
					START=$((LASTINDEX+LEN))
					# find first occurance of string in image, that will be start of cpio archive
					dd if=$RDF skip=$START count=$OBS ibs=$IBS obs=$OBS of=$OF > /dev/null 2>&1
					HEAD=`strings -t d $OF | head -1`
					# vola
					for i in $HEAD;do
						HEAD=$i
						break
					done
					LASTINDEX=$((START+HEAD))
				fi
		  		continue
			fi

			# number of blocks we'll extract
			$RAMDISK_GZ && BLOCKS=$(((OFFSET+128)/IBS))
			if $RAMDISK_LZ4; then
				if [ $LASTINDEX == "0" ]; then
					log_highlight "Searching for the real End of the 1st Archive"
					while [ $LASTINDEX == "0" ]; do
						FIRSTFILEBYTES=$(xxd -p -c8 -l8 -s "$OFFSET" "$RDF")
						FIRSTFILEBYTES="${FIRSTFILEBYTES:0:8}"
						if [ "$FIRSTFILEBYTES" == "$COMPRESS_SIGN" ]; then
							break
						fi
						OFFSET=$((OFFSET+1))
					done
				fi
				BLOCKS=$((OFFSET/IBS))
			fi

			# extract and dump
			log_info "Dumping from $LASTINDEX to $BLOCKS .."
			dd if=$RDF skip=$LASTINDEX count=$BLOCKS ibs=$IBS obs=$OBS of=$OF > /dev/null 2>&1

			cd $TMP/ramdisk > /dev/null
				$RAMDISK_GZ && cat $OF | $BASEDIR/busybox cpio -i > /dev/null 2>&1
				if $RAMDISK_LZ4; then
					$BASEDIR/magiskboot decompress $OF $OF.cpio
					$BASEDIR/busybox cpio -F $OF.cpio -i > /dev/null 2>&1
				fi
			cd - > /dev/null

			LASTINDEX=$OFFSET
	  	done
		repack_ramdisk
	else
		log_highlight "After decompressing ramdisk.img, magiskboot will work"
		$RAMDISK_GZ && RDF=$RDF$ENDG
		$BASEDIR/magiskboot decompress $RDF $CPIO
	fi
	#update_lib_modules
}

apply_ramdisk_hacks() {

	# Call rootAVD with PATCHFSTAB if you want the RAMDISK merge your modded fstab.ranchu before Magisk Mirror gets mounted

	# cp the read-only fstab.ranchu from vendor partition and add usb:auto for SD devices
	# kernel musst have Mass-Storage + SCSI Support enabled to create /dev/block/sd* nodes

	#log_info "PATCHFSTAB=$PATCHFSTAB"
	if ("$PATCHFSTAB"); then
		log_info "pulling fstab.ranchu from AVD"
		cp /system/vendor/etc/fstab.ranchu $(pwd)
		log_info "adding usb:auto to fstab.ranchu"
		echo "/devices/*/block/sd* auto auto defaults voldmanaged=usb:auto" >> fstab.ranchu
		#echo "/devices/*/block/loop7 auto auto defaults voldmanaged=sdcard:auto" >> fstab.ranchu
		#echo "/devices/1-* auto auto defaults voldmanaged=usb:auto" >> fstab.ranchu
		$BASEDIR/magiskboot cpio ramdisk.cpio \
		"mkdir 0755 overlay.d/vendor" \
		"mkdir 0755 overlay.d/vendor/etc" \
		"add 0644 overlay.d/vendor/etc/fstab.ranchu fstab.ranchu"
		log_info "overlay adding complete"
		#log_info "jumping back to patching ramdisk for magisk init"
	#else
		#log_info "Skipping fstab.ranchu patch with /dev/block/sda"
		#echo "[?] If you want fstab.ranchu patched, Call rootAVD with PATCHFSTAB"
	fi

	#log_info "AddRCscripts=$AddRCscripts"
	if ("$AddRCscripts"); then
		log_highlight "adding *.rc files to ramdisk"
		#for f in *.rc; do
		#	./magiskboot cpio ramdisk.cpio "add 0644 overlay.d/sbin/$f $f"
		#done
		#CSTRC=init.custom.rc
		#touch $CSTRC
		for f in *.rc; do
			#echo "$f" > $CSTRC
			$BASEDIR/magiskboot cpio ramdisk.cpio "add 0755 overlay.d/$f $f"
		done

		if [ -d $BASEDIR/sbin ]; then
			log_highlight "adding sbin files to ramdisk"
			for f in sbin/*; do
			$BASEDIR/magiskboot cpio ramdisk.cpio "add 0755 overlay.d/$f $f"
			done
		fi
		#$BASEDIR/magiskboot cpio ramdisk.cpio "add 0755 overlay.d/$CSTRC $CSTRC"
		log_info "overlay adding complete"
		#log_info "jumping back to patching ramdisk for magisk init"
	#else
		#log_info "Skip adding *.rc scripts into ramdisk.img/sbin/*.rc"
		#echo "[?] If you want *.rc scripts added into ramdisk.img/sbin/*.rc, Call rootAVD with AddRCscripts"
	fi

	#$PATCHFSTAB && SKIPOVERLAYD="#" || SKIPOVERLAYD=""
	update_lib_modules
}

verify_ramdisk_origin() {
	log_highlight "Verifying Boot Image by its Kernel Release number:"
	local KRNAVD=$(uname -r)
	local KRNRDF=""
	log_info "This AVD = $KRNAVD"
	KRNRDF=$(cat $CPIO | strings | grep -m 1 vermagic= | sed 's/vermagic=//;s/ .*$//')

	if [ "$KRNRDF" != "" ]; then
		log_info " Ramdisk = $KRNRDF"
		if [ "$KRNAVD" == "$KRNRDF" ]; then
			log_info "Ramdisk is probably from this AVD"
		else
			log_info "Ramdisk is probably NOT from this AVD"
		fi
	fi
}

test_ramdisk_patch_status(){

	if [ -e ramdisk.cpio ]; then
		$BASEDIR/magiskboot cpio ramdisk.cpio test 2>/dev/null
		STATUS=$?
		log_info "Checking ramdisk STATUS=$STATUS"
	else
		log_info "Stock A only system-as-root"
		STATUS=0
	fi
	PATCHEDBOOTIMAGE=false

	case $((STATUS & 3)) in
	  0 )  # Stock boot
		log_info "Stock boot image detected"
		SHA1=`$BASEDIR/magiskboot sha1 ramdisk.cpio 2>/dev/null`
		cp -af $CPIO $CPIOORIG 2>/dev/null
		;;

	  1 )  # Magisk patched
		log_info "Magisk patched boot image detected"
		#construct_environment
		PATCHEDBOOTIMAGE=true
		;;
	  2 )  # Unsupported
		log_info "Boot image patched by unsupported programs"
		log_info "Please restore back to stock boot image"
		abort_script
		;;
	esac

	if [ $((STATUS & 8)) -ne 0 ]; then
	  log_info "TWOSTAGE INIT image detected - Possibly using 2SI, export env var"
	  export TWOSTAGEINIT=true
	fi
	export PATCHEDBOOTIMAGE
}

patching_ramdisk(){
	##########################################################################################
	# Ramdisk patches
	##########################################################################################

	log_info "Patching ramdisk"

	echo "KEEPVERITY=$KEEPVERITY" > config
	echo "KEEPFORCEENCRYPT=$KEEPFORCEENCRYPT" >> config
	echo "RECOVERYMODE=$RECOVERYMODE" >> config

	# actually here is the SHA of the bootimage generated
	# we only have one file, so it could make sense
	[ ! -z $SHA1 ] && echo "SHA1=$SHA1" >> config

	# Compress to save precious ramdisk space

	if $IS32BITONLY || ! $IS64BITONLY ; then
		$BASEDIR/magiskboot compress=xz magisk32 magisk32.xz
	fi

	if $IS64BITONLY || ! $IS32BITONLY ; then
		$BASEDIR/magiskboot compress=xz magisk64 magisk64.xz
	fi

	$IS64BITONLY && SKIP32="#" || SKIP32=""
	$IS64BIT && SKIP64="" || SKIP64="#"

	if $STUBAPK; then
		log_info "stub.apk is present, compress and add it to ramdisk"
		$BASEDIR/magiskboot compress=xz stub.apk stub.xz
	fi

	$STUBAPK && SKIPSTUB="" || SKIPSTUB="#"

	# Here gets the ramdisk.img patched with the magisk su files and stuff

	log_highlight "adding overlay.d/sbin folders to ramdisk"
	$BASEDIR/magiskboot cpio ramdisk.cpio \
	"mkdir 0750 overlay.d" \
	"mkdir 0750 overlay.d/sbin"

	apply_ramdisk_hacks

	log_info "patching the ramdisk with Magisk Init"
	$BASEDIR/magiskboot cpio ramdisk.cpio \
	"add 0750 init magiskinit" \
	"$SKIP32 add 0644 overlay.d/sbin/magisk32.xz magisk32.xz" \
	"$SKIP64 add 0644 overlay.d/sbin/magisk64.xz magisk64.xz" \
	"$SKIPSTUB add 0644 overlay.d/sbin/stub.xz stub.xz" \
	"patch" \
	"backup ramdisk.cpio.orig" \
	"mkdir 000 .backup" \
	"add 000 .backup/.magisk config"
}


rename_copy_magisk() {
	if ( "$MAGISKVERCHOOSEN" ); then
		log_info "Copy Magisk.zip to Magisk.apk"
		cp Magisk.zip Magisk.apk
	else
		log_info "Rename Magisk.zip to Magisk.apk"
		mv Magisk.zip Magisk.apk
	fi
}

repacking_ramdisk(){
	if [ $((STATUS & 4)) -ne 0 ]; then
		log_info "Compressing ramdisk before repacking it"
	  $BASEDIR/magiskboot cpio ramdisk.cpio compress
	fi

	log_highlight "repacking back to ramdisk.img format"
	# Rename and compress ramdisk.cpio back to ramdiskpatched4AVD.img
	$BASEDIR/magiskboot compress=$METHOD "ramdisk.cpio" "ramdiskpatched4AVD.img"
}

strip_html_links() {
	sed -i -e 's/<a href=/\n<a href=/g;s/<\/a>/<\/a>\n/g' "$1"
}
strip_kernel_builds() {
	sed -i -n '/>Update kernel to builds/p' "$1"
}
strip_next_pages() {
	sed -n '/>Next/p' "$1"
}
find_next_pages() {
	local URL="$2"
	local NEXTPAGESRC=""
	local TMPHTML="tmp.html"
	rm -rf $TMPHTML
	NEXTPAGESRC=$(strip_next_pages $1)

	log_info "Find Next Page(s)"
	while [[ "$NEXTPAGESRC" != "" ]]; do
		NEXTPAGESRC=$(echo $NEXTPAGESRC | sed -e 's/.*href=\"/\1/' -e 's/\">Next.*//')
		#echo $NEXTPAGESRC
		DownLoadFile $URL $NEXTPAGESRC $TMPHTML
		strip_html_links $TMPHTML
		cat $TMPHTML >> $1
		NEXTPAGESRC=$(strip_next_pages $TMPHTML)
	done
}

update_lib_modules() {
	local INITRAMFS=initramfs.img
	if ("$AVDIsOnline"); then
		if ( "$InstallPrebuiltKernelModules" ); then
			local KERNEL_ARCH="x86-64"
			if [[ $ABI == *"arm"* ]]; then
  				KERNEL_ARCH="arm64"
			fi
			local unameR=$(uname -r)
			local majmin=${unameR%.*}
			#majmin=5.15
			local installedbuild=${unameR##*ab}

			log_highlight "Fetching Kernel Data:"
			log_info "             Android: $AVERSION"
			log_info "                Arch: $KERNEL_ARCH"
			log_info "               Uname: $unameR"
			log_info "             Version: $majmin"
			log_info "       Build Version: $installedbuild"

			local URL="https://android.googlesource.com"
			#local TAG="android$AVERSION-mainline-sdkext-release"
			local TAG="android$AVERSION-gsi"
			#local TAG="master"
			local KERSRC="/kernel/prebuilts/$majmin/$KERNEL_ARCH/+log/refs/heads/$TAG"
			#local KERSRC="/platform/prebuilts/qemu-kernel/+log/refs/heads/$TAG"
			#https://android.googlesource.com/platform/prebuilts/qemu-kernel/+log/refs/heads/android11-gsi
			#https://android.googlesource.com/platform/prebuilts/qemu-kernel/+/refs/heads/android11-gsi
			#local KERSRC="/kernel/prebuilts/$majmin/$KERNEL_ARCH/+log/refs/heads/android$AVERSION-mainline-sdkext-release"

			local MODSRC="/kernel/prebuilts/common-modules/virtual-device/$majmin/$KERNEL_ARCH/+log/refs/heads/$TAG"
			#local MODSRC="/kernel/prebuilts/common-modules/virtual-device/$majmin/$KERNEL_ARCH/+log/refs/heads/android$AVERSION-mainline-sdkext-release"
			local KERPREMASHTML="kernelprebuiltsmaster.html"
			local KERDST="prebuiltkernel.tar.gz"
			local MODDST="prebuiltmodules.tar.gz"
			local MODPREMASHTML="moduleprebuiltsmaster.html"
			local TMPSTRIPFILE="tmpstripfile"
			local TMPREADFILE="tmpreadfile"
			local FILETOREAD=""
			local FILETOSTRIP=""

			local BUILDVERCHOOSEN=""
			local CHOOSENLINE=""
			local KERCOMMITID=""
			local MODCOMMITID=""

			local ker_line_cnt=""
			local mod_line_cnt=""
			local i=""


			DownLoadFile $URL $KERSRC $KERPREMASHTML
			strip_html_links $KERPREMASHTML
			find_next_pages $KERPREMASHTML $URL
			strip_kernel_builds $KERPREMASHTML

			DownLoadFile $URL $MODSRC $MODPREMASHTML
			strip_html_links $MODPREMASHTML
			find_next_pages $MODPREMASHTML $URL
			strip_kernel_builds $MODPREMASHTML

			ker_line_cnt=$(sed -n '$=' $KERPREMASHTML)
			mod_line_cnt=$(sed -n '$=' $MODPREMASHTML)

			if [ "$ker_line_cnt" -gt "$mod_line_cnt" ];then
				FILETOREAD="$KERPREMASHTML"
				FILETOSTRIP="$MODPREMASHTML"
			else
				FILETOREAD="$MODPREMASHTML"
				FILETOSTRIP="$KERPREMASHTML"
			fi

			touch $TMPSTRIPFILE
			touch $TMPREADFILE

			log_highlight "Find common Build Versions"
			while read line; do
				BUILDVER=$(echo $line | sed -e 's/<[^>]*>//g')
				grep -e ">$BUILDVER<" -F $FILETOSTRIP >> $TMPSTRIPFILE
				if [[ "$?" == "0" ]]; then
					echo $line >> $TMPREADFILE
				fi
			done < $FILETOREAD

			mv -f $TMPREADFILE $FILETOREAD
			mv -f $TMPSTRIPFILE $FILETOSTRIP

			while :
			do
				i=0
				log_info "Installed Kernel builds $installedbuild"
                log_warning "[?] Choose a Prebuild Kernel/Module Version"
				while read line; do
					i=$(( i + 1 ))
					BUILDVER=$(echo $line | sed -e 's/<[^>]*>//g')
					echo "[$i] $BUILDVER"
				done < $KERPREMASHTML

				read choice
				case $choice in
					*)
						if [[ "$choice" == "" ]]; then
							choice=1
						fi
						if [ "$choice" -le "$i" ];then
							BUILDVERCHOOSEN=$choice
							CHOOSENLINE=$(sed -n "$BUILDVERCHOOSEN"'p' $KERPREMASHTML)
							BUILDVER=$(echo $CHOOSENLINE| sed -e 's/<[^>]*>//g')
							KERCOMMITID=$(echo $CHOOSENLINE | sed -e 's/^[^"]*"\([^"]*\)".*/\1/')
							KERCOMMITID=${KERCOMMITID##*/}".tar.gz"

							CHOOSENLINE=$(sed -n "$BUILDVERCHOOSEN"'p' $MODPREMASHTML)
							MODCOMMITID=$(echo $CHOOSENLINE | sed -e 's/^[^"]*"\([^"]*\)".*/\1/')
							MODCOMMITID=${MODCOMMITID##*/}".tar.gz"

							echo "[$BUILDVERCHOOSEN] You choose: $BUILDVER"
							break
						fi
                        log_warning "Choice is out of range";;
				esac
			done

			log_info "Downloading Kernel and its Modules..."
			# Download Kernel
			DownLoadFile "$URL/kernel/prebuilts/$majmin/$KERNEL_ARCH/+archive/" $KERCOMMITID $KERDST
			# Download Modules
			DownLoadFile "$URL/kernel/prebuilts/common-modules/virtual-device/$majmin/$KERNEL_ARCH/+archive/" $MODCOMMITID $MODDST

			log_highlight "Extracting kernel-$majmin to bzImage"
			tar -xf $KERDST kernel-$majmin -O > bzImage
			log_info "Extracting $INITRAMFS"
			tar -xf $MODDST $INITRAMFS

			InstallKernelModules=true
		fi
	fi

	if ( "$InstallKernelModules" ); then

		if [ -e "$INITRAMFS" ]; then
			log_info "Installing new Kernel Modules"
			log_highlight "Copy initramfs.img $TMP/initramfs"
			mkdir -p $TMP/initramfs
			CMPRMTH=$(compression_method $INITRAMFS)
			cp $INITRAMFS $TMP/initramfs/initramfs.cpio$CMPRMTH
		else
			return 0
		fi

		log_info "Extracting Modules from $INITRAMFS"

		cd $TMP/initramfs > /dev/null
			$BASEDIR/magiskboot decompress initramfs.cpio$CMPRMTH
			$BASEDIR/busybox cpio -F initramfs.cpio -i *lib* > /dev/null 2>&1
		cd - > /dev/null

		if [ ! -d "$TMP/initramfs/lib/modules" ]; then
			log_info "$INITRAMFS has no lib/modules, aborting"
			rm -rf bzImage 2>/dev/null
			return 0
		fi

		# If Stock or patched Status
		if $PATCHEDBOOTIMAGE; then
			# If it is a already patched ramdisk
			if [ ! -e "$TMP/ramdisk" ]; then
				mkdir -p $TMP/ramdisk
			fi

			log_highlight "Extracting Modules from patched ramdisk.img"
			cd $TMP/ramdisk > /dev/null
				$BASEDIR/busybox cpio -F $CPIO -i *lib* > /dev/null 2>&1
			cd - > /dev/null
		else
			# If it is a Stock Ramdisk
			log_highlight "Extracting Modules from Stock ramdisk.img"
			extract_stock_ramdisk
		fi

		OLDVERMAGIC=$(cat $(find $TMP/ramdisk/. -name '*.ko' | head -n 1 2> /dev/null) | strings | grep vermagic= | sed 's/vermagic=//;s/ .*$//' 2> /dev/null)
		OLDANDROID=$(cat $(find $TMP/ramdisk/. -name '*.ko' | head -n 1 2> /dev/null) | strings | grep 'Android (' | sed 's/ c.*$//' 2> /dev/null)

		# If Stock or patched Status
		if $PATCHEDBOOTIMAGE; then
			# If it is a already patched ramdisk
			log_highlight "Removing Modules from patched ramdisk.img"
			$BASEDIR/magiskboot cpio $CPIO "rm -r lib" > /dev/null 2>&1
		else
			# If it is a Stock Ramdisk
			log_highlight "Removing Modules from Stock ramdisk.img"
			rm -f $TMP/ramdisk/lib/modules/*
		fi

		log_info "$OLDVERMAGIC"
		log_info "$OLDANDROID"

		log_info "Installing new Modules into ramdisk.img"
		cd $TMP/initramfs > /dev/null
			find ./lib/modules -type f -name '*' -exec cp {} . \;
			find . -name '*.ko' -exec cp {} $TMP/ramdisk/lib/modules/ \;
			NEWVERMAGIC=$(cat $(find . -name '*.ko' | head -n 1 2> /dev/null) | strings | grep vermagic= | sed 's/vermagic=//;s/ .*$//' 2> /dev/null)
			NEWANDROID=$(cat $(find . -name '*.ko' | head -n 1 2> /dev/null) | strings | grep 'Android (' | sed 's/ c.*$//' 2> /dev/null)
			cp modules.alias modules.dep modules.load modules.softdep $TMP/ramdisk/lib/modules/
		cd - > /dev/null

		log_info "$NEWVERMAGIC"
		log_info "$NEWANDROID"

		log_highlight "Adjusting modules.load and modules.dep"
		cd $TMP/ramdisk/lib/modules > /dev/null
			sed -i -E 's~[^[:blank:]]+/~/lib/modules/~g' modules.load
			sort -s -o modules.load modules.load
			sed -i -E 's~[^[:blank:]]+/~/lib/modules/~g' modules.dep
			sort -s -o modules.dep modules.dep
		cd - > /dev/null

		# If Stock or patched Status
		if $PATCHEDBOOTIMAGE; then
			# If it is a already patched ramdisk
			log_highlight "Adding new Modules into patched ramdisk.img"
			cd $TMP/ramdisk/lib/modules > /dev/null
				$BASEDIR/magiskboot cpio $CPIO \
				"mkdir 0755 lib" \
				"mkdir 0755 lib/modules" > /dev/null 2>&1
				for f in *.*; do
					$BASEDIR/magiskboot cpio $CPIO \
					"add 0644 lib/modules/$f $f" > /dev/null 2>&1
					#echo "$f"
				done
			cd - > /dev/null
		else
			# If it is a Stock Ramdisk
			repack_ramdisk
		fi
	fi
}

### taken from HuskyDG script MagiskOnEmu libbash.so ->

random() {
	VALUE=$1; TYPE=$2; PICK="$3"; PICKC="$4"
	TMPR=""
	HEX="0123456789abcdef"; HEXC=16
	CHAR="qwertyuiopasdfghjklzxcvbnm"; CHARC=26
	NUM="0123456789"; NUMC=10
	COUNT=$(seq 1 1 $VALUE)
	list_pick=$HEX; C=$HEXC
	[ "$TYPE" == "char" ] &&  list_pick=$CHAR && C=$CHARC
	[ "$TYPE" == "number" ] && list_pick=$NUM && C=$NUMC
	[ "$TYPE" == "custom" ] && list_pick="$PICK" && C=$PICKC
		  for i in $COUNT; do
			  random_pick=$(( $RANDOM % $C))
			  echo -n ${list_pick:$random_pick:1}
		  done
}

random_str() {
	random_length=$(random 1 custom 56789 5);
	random $random_length custom "qwertyuiopasdfghjklzxcvbnm0123456789QWERTYUIOPASDFGHJKLZXCVBNM" 63 | base64 | sed "s/=//g"
}
magisk_loader() {
	magisk_overlay=`random_str`
	magisk_postfsdata=`random_str`
	magisk_service=`random_str`
	magisk_daemon=`random_str`
	magisk_boot_complete=`random_str`
	magisk_loadpolicy=`random_str`
	dev_random=`random_str`
    #system-as-root, /sbin is removal
    MAGISKTMP="/dev/$dev_random"
    mount_sbin="mkdir -p \"$MAGISKTMP\"
mnt_tmpfs \"$MAGISKTMP\"
chmod 755 \"$MAGISKTMP\""
     umount_sbin="umount /sbin"


# apply multiple sepolicy at same time

LOAD_MODULES_POLICY="rm -rf \"\$MAGISKTMP/.magisk/sepolicy.rules\"
for module in \$(ls /data/adb/modules); do
              if ! [ -f \"/data/adb/modules/\$module/disable\" ] && [ -f \"/data/adb/modules/\$module/sepolicy.rule\" ]; then
                  echo \"## * module sepolicy: \$module\" >>\"\$MAGISKTMP/.magisk/sepolicy.rules\"
                  cat  \"/data/adb/modules/\$module/sepolicy.rule\" >>\"\$MAGISKTMP/.magisk/sepolicy.rules\"
                  echo \"\" >>\"\$MAGISKTMP/.magisk/sepolicy.rules\"

              fi
          done
\$MAGISKTMP/magiskpolicy --live --apply \"\$MAGISKTMP/.magisk/sepolicy.rules\""

ADDITIONAL_SCRIPT="( # addition script
rm -rf /data/adb/post-fs-data.d/fix_mirror_mount.sh
rm -rf /data/adb/service.d/fix_modules_not_show.sh


# additional script to deal with bullshit faulty design of emulator
# that close built-in root will remove magisk's /system/bin/su

echo \"
export PATH=\\\"\$MAGISKTMP:\\\$PATH\\\"
if [ -f \\\"/system/bin/magisk\\\" ]; then
    umount -l /system/bin/su
    rm -rf /system/bin/su
    ln -fs ./magisk /system/bin/su
    mount -o ro,remount /system/bin
    umount -l /system/bin/magisk
    mount --bind \\\"\$MAGISKTMP/magisk\\\" /system/bin/magisk
fi\" >\$MAGISKTMP/emu/magisksu_survival.sh

# additional script to deal with bullshit faulty design of Android-x86
# that data is a bind mount from $SRC/data on ext4 partition


SRC=\\\"\\\$(cmdline SRC)\\\"
test -z \\\"\\\$SRC\\\" && exit
LIST_TEST=\\\"
/data
/data/adb
/data/adb/magisk
/data/adb/modules
\\\"
count=0
for folder in \\\$LIST_TEST; do
test \\\"\\\$(ls -A \\\$MAGISKTMP/.magisk/mirror/\\\$folder 2>/dev/null)\\\" == \\\"\\\$(ls -A \\\$folder 2>/dev/null)\\\" && count=\\\$((\\\$count + 1))
done
test \\\"\\\$count\\\" == 4 && exit
count=0
for folder in \\\$LIST_TEST; do
test \\\"\\\$(ls -A \\\$MAGISKTMP/.magisk/mirror/data/\\\$SRC/\\\$folder 2>/dev/null)\\\" == \\\"\\\$(ls -A \\\$folder 2>/dev/null)\\\" && count=\\\$((\\\$count + 1))
done
if [ \\\"\\\$count\\\" == 4 ]; then
mount --bind \\\"\\\$MAGISKTMP/.magisk/mirror/data/\\\$SRC/data\\\" \\\"\\\$MAGISKTMP/.magisk/mirror/data\\\"
fi )
rm -rf \\\"\\\$SCRIPT\\\"
\" >/data/adb/post-fs-data.d/fix_mirror_mount.sh
echo \"
SCRIPT=\\\"\\\$0\\\"
MAGISKTMP=\\\$(magisk --path) || MAGISKTMP=/sbin
CHECK=\\\"/data/adb/modules/.mk_\\\$RANDOM\\\$RANDOM\\\"
touch \\\"\\\$CHECK\\\"
test \\\"\\\$(ls -A \\\$MAGISKTMP/.magisk/modules 2>/dev/null)\\\" != \\\"\\\$(ls -A /data/adb/modules 2>/dev/null)\\\" && mount --bind \\\$MAGISKTMP/.magisk/mirror/data/adb/modules \\\$MAGISKTMP/.magisk/modules
rm -rf \\\"\\\$CHECK\\\"
rm -rf \\\"\\\$SCRIPT\\\"\" >/data/adb/service.d/fix_modules_not_show.sh
chmod 755 /data/adb/service.d/fix_modules_not_show.sh
chmod 755 /data/adb/post-fs-data.d/fix_mirror_mount.sh; )"


EXPORT_PATH="export PATH /sbin:/system/bin:/system/xbin:/vendor/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin"


magiskloader="

         on early-init
             $EXPORT_PATH


          on post-fs-data
$RM_RUSTY_MAGISK
              start logd
              start adbd
              rm /dev/.magisk_unblock
              exec u:r:su:s0 root root -- $MAGISKBASE/busybox sh -o standalone $MAGISKBASE/overlay.sh
              exec u:r:magisk:s0 root root -- $MAGISKTMP/magisk --daemon
              start $magisk_postfsdata
              # wait all magisk post-fs-data jobs are completed or 40s  has passed
              wait /dev/.magisk_unblock 40
              rm /dev/.magisk_unblock

          service $magisk_postfsdata $MAGISKTMP/magisk --post-fs-data
              user root
              seclabel u:r:magisk:s0
              oneshot

          service $magisk_service $MAGISKTMP/magisk --service
              class late_start
              user root
              seclabel u:r:magisk:s0
              oneshot

          on property:sys.boot_completed=1
              $umount_sbin
              start $magisk_boot_complete
# remove magisk service traces from some detection
# although detect modified init.rc is not always correct
              exec u:r:magisk:s0 root root -- $MAGISKTMP/magisk resetprop --delete init.svc.$magisk_postfsdata
              exec u:r:magisk:s0 root root -- $MAGISKTMP/magisk resetprop --delete init.svc.$magisk_service
              exec u:r:magisk:s0 root root -- $MAGISKTMP/magisk resetprop --delete init.svc.$magisk_boot_complete
              exec u:r:magisk:s0 root root -- $MAGISKTMP/magisk resetprop --delete init.svc_debug_pid.$magisk_postfsdata
              exec u:r:magisk:s0 root root -- $MAGISKTMP/magisk resetprop --delete init.svc_debug_pid.$magisk_service
              exec u:r:magisk:s0 root root -- $MAGISKTMP/magisk resetprop --delete init.svc_debug_pid.$magisk_boot_complete
              exec u:r:magisk:s0 root root -- $MAGISKTMP/busybox sh -o standalone $MAGISKTMP/emu/magisksu_survival.sh
          service $magisk_boot_complete $MAGISKTMP/magisk --boot-complete
              user root
              seclabel u:r:magisk:s0
              oneshot"


overlay_loader="#!$MAGISKBASE/busybox sh

export PATH=/sbin:/system/bin:/system/xbin


mnt_tmpfs(){ (
# MOUNT TMPFS ON A DIRECTORY
MOUNTPOINT=\"\$1\"
mkdir -p \"\$MOUNTPOINT\"
mount -t tmpfs -o \"mode=0755\" tmpfs \"\$MOUNTPOINT\" 2>/dev/null
) }



mnt_bind(){ (
# SHORTCUT BY BIND MOUNT
FROM=\"\$1\"; TO=\"\$2\"
if [ -L \"\$FROM\" ]; then
SOFTLN=\"\$(readlink \"\$FROM\")\"
ln -s \"\$SOFTLN\" \"\$TO\"
elif [ -d \"\$FROM\" ]; then
mkdir -p \"\$TO\" 2>/dev/null
mount --bind \"\$FROM\" \"\$TO\"
else
echo -n 2>/dev/null >\"\$TO\"
mount --bind \"\$FROM\" \"\$TO\"
fi
) }

clone(){ (
FROM=\"\$1\"; TO=\"\$2\"; IFS=\$\"
\"
[ -d \"\$TO\" ] || exit 1;
( cd \"\$FROM\" && find * -prune ) | while read obj; do
( if [ -d \"\$FROM/\$obj\" ]; then
mnt_tmpfs \"\$TO/\$obj\"
else
mnt_bind \"\$FROM/\$obj\" \"\$TO/\$obj\" 2>/dev/null
fi ) &
sleep 0.05
done
) }

overlay(){ (
# RE-OVERLAY A DIRECTORY
FOLDER=\"\$1\";
TMPFOLDER=\"/dev/vm-overlay\"
#_____
PAYDIR=\"\${TMPFOLDER}_\${RANDOM}_\$(date | base64)\"
mkdir -p \"\$PAYDIR\"
mnt_tmpfs \"\$PAYDIR\"
#_________
clone \"\$FOLDER\" \"\$PAYDIR\"
mount --move \"\$PAYDIR\" \"\$FOLDER\"
rm -rf \"\$PAYDIR\"
#______________
) }

exit_magisk(){
umount -l $MAGISKTMP
echo -n >/dev/.magisk_unblock
}


API=\$(getprop ro.build.version.sdk)
  ABI=\$(getprop ro.product.cpu.abi)
  if [ \"\$ABI\" = \"x86\" ]; then
    ARCH=x86
    ABI32=x86
    IS64BIT=false
  elif [ \"\$ABI\" = \"arm64-v8a\" ]; then
    ARCH=arm64
    ABI32=armeabi-v7a
    IS64BIT=true
  elif [ \"\$ABI\" = \"x86_64\" ]; then
    ARCH=x64
    ABI32=x86
    IS64BIT=true
  else
    ARCH=arm
    ABI=armeabi-v7a
    ABI32=armeabi-v7a
    IS64BIT=false
  fi

magisk_name=\"magisk32\"
[ \"\$IS64BIT\" == true ] && magisk_name=\"magisk64\"

# umount previous /sbin tmpfs overlay

count=0
( magisk --stop ) &

# force umount /sbin tmpfs

until ! mount | grep -q \" /sbin \"; do
[ "$count" -gt "10" ] && break
umount -l /sbin 2>/dev/null
sleep 0.1
count=$(($count+1))
test ! -d /sbin && break
done

# mount magisk tmpfs path

$mount_sbin

MAGISKTMP=$MAGISKTMP
chmod 755 \"\$MAGISKTMP\"
set -x
mkdir -p \$MAGISKTMP/.magisk
mkdir -p \$MAGISKTMP/emu
exec 2>>\$MAGISKTMP/emu/record_logs.txt
exec >>\$MAGISKTMP/emu/record_logs.txt

cd $MAGISKBASE

test ! -f \"./\$magisk_name\" && { echo -n >/dev/.overlay_unblock; exit_magisk; exit 0; }


MAGISKBIN=/data/adb/magisk
mkdir /data/unencrypted
for mdir in modules post-fs-data.d service.d magisk; do
test ! -d /data/adb/\$mdir && rm -rf /data/adb/\$mdir
mkdir /data/adb/\$mdir 2>/dev/null
done
for file in magisk32 magisk64 magiskinit; do
  cp -af ./\$file \$MAGISKTMP/\$file 2>/dev/null
  chmod 755 \$MAGISKTMP/\$file
  cp -af ./\$file \$MAGISKBIN/\$file 2>/dev/null
  chmod 755 \$MAGISKBIN/\$file
done
cp -af ./magiskboot \$MAGISKBIN/magiskboot
cp -af ./busybox \$MAGISKBIN/busybox
cp -af ./busybox \$MAGISKTMP
chmod 755 \$MAGISKTMP/busybox
\$MAGISKTMP/busybox --install -s \$MAGISKTMP
cp -af ./assets/* \$MAGISKBIN

# create symlink / applet

ln -s ./\$magisk_name \$MAGISKTMP/magisk 2>/dev/null
ln -s ./magisk \$MAGISKTMP/su 2>/dev/null
ln -s ./magisk \$MAGISKTMP/resetprop 2>/dev/null
ln -s ./magisk \$MAGISKTMP/magiskhide 2>/dev/null
ln -s ./magiskinit \$MAGISKTMP/magiskpolicy 2>/dev/null

mkdir -p \$MAGISKTMP/.magisk/mirror
mkdir \$MAGISKTMP/.magisk/block

touch \$MAGISKTMP/.magisk/config

cd \$MAGISKTMP
# SELinux stuffs
ln -sf ./magiskinit magiskpolicy
if [ -f /vendor/etc/selinux/precompiled_sepolicy ]; then
  ./magiskpolicy --load /vendor/etc/selinux/precompiled_sepolicy --live --magisk 2>&1
elif [ -f /sepolicy ]; then
  ./magiskpolicy --load /sepolicy --live --magisk 2>&1
else
  ./magiskpolicy --live --magisk 2>&1
fi

#remount system read-only to fix Magisk fail to mount mirror

$remove_backup
mount -o ro,remount /
mount -o ro,remount /system
mount -o ro,remount /vendor
mount -o ro,remount /product
mount -o ro,remount /system_ext

restorecon -R /data/adb/magisk

$ADDITIONAL_SCRIPT
$LOAD_MODULES_POLICY

[ ! -f \"\$MAGISKTMP/magisk\" ] && exit_magisk
# test ! \"\$(pidof magiskd)\" && exit_magisk

[ -d "/oem/.overlay" ] && umount -l /oem
umount -l /system/etc/init
umount -l /init.rc
umount -l /system/etc/init/hw/init.rc
"
}

service(){
	log_info "service Module testing"
}

InstallMagiskToAVD() {

	if [ -z $PREPBBMAGISK ]; then
		ProcessArguments $@
		api_level_arch_detect
		PrepBusyBoxAndMagisk
		ExecBusyBoxAsh $@
	fi

	log_highlight "rootAVD with Magisk ${BOLD}$MAGISK_VER${NC} Installer"

	get_flags
	copyARCHfiles

	if $INEMULATOR; then
		detect_ramdisk_compression_method
		decompress_ramdisk
		if $FAKEBOOTIMG; then
			process_fake_boot_img
		fi

		test_ramdisk_patch_status
		verify_ramdisk_origin

        if $PATCHEDBOOTIMAGE; then
            apply_ramdisk_hacks
        else
            patching_ramdisk
        fi

		## Magisk Module testing
		if $DEBUG; then
			log_debug "Running service module testing"
			service
		fi

		repacking_ramdisk
		rename_copy_magisk
	fi
}

GetANDROIDHOME() {

	#unset ANDROID_HOME
	#export ANDROID_HOME=~/Downloads/sdk
	#export ANDROID_HOME=~"/Downloads/sd k"
	#export ANDROID_HOME="~/Downloads/sd k"

	local HOME=~
	local ANDROIDHOME_M=$HOME/Library/Android/sdk
	local ANDROIDHOME_L=$HOME/Android/Sdk
	defaultHOME_M="~/Library/Android/sdk"
	defaultHOME_L="~/Android/Sdk"
	defaultHOME=""
	local hostarch=""
	SYSIM_DIR=system-images
	ADB_DIR=platform-tools

	NoSystemImages=true

	if [ -d "$ANDROIDHOME_M" ]; then
		ANDROIDHOME=$ANDROIDHOME_M
		ENVVAR=$defaultHOME_M
		defaultHOME=$defaultHOME_M
	elif [ -d "$ANDROIDHOME_L" ]; then
		ANDROIDHOME=$ANDROIDHOME_L
		ENVVAR=$defaultHOME_L
		defaultHOME=$defaultHOME_L
	fi

	if [ ! -z "$ANDROID_HOME" ]; then
		if [[ "$ANDROID_HOME" == *"~"* ]]; then
			ANDROID_HOME="${ANDROID_HOME/#~/~}"
		fi
		ANDROIDHOME="$ANDROID_HOME"
		ENVVAR="\$ANDROID_HOME"
	fi

	if [[ -d "$ANDROIDHOME/$SYSIM_DIR" ]]; then
		NoSystemImages=false
	fi

	if [[ "$defaultHOME" == "" ]]; then
		hostarch=$(uname -a)
		defaultHOME=$defaultHOME_M
		if [[ "$hostarch" == *"Linux"* ]]; then
			defaultHOME=$defaultHOME_L
		elif [[ "$hostarch" == *"linux"* ]]; then
			defaultHOME=$defaultHOME_M
		fi
	fi

	export NoSystemImages
	export ANDROIDHOME
	export ENVVAR
	export SYSIM_DIR
	export ADB_DIR
	export defaultHOME
	export ANDROIDHOME_M
	export ANDROIDHOME_L
}

FindSystemImages() {
	local SYSIM_EX=""

    log_info "Use $ENVVAR to search for AVD system images"
	echo "	"

	if $NoSystemImages ; then
    log_warning "No system-images could be found"
		return 1
	fi

	cd "$ANDROIDHOME" > /dev/null
			for SI in $(find $SYSIM_DIR -type f -iname ramdisk*.img); do
				if ( "$ListAllAVDs" ); then
					if [[ "$SYSIM_EX" == "" ]]; then
						SYSIM_EX+="$SI"
					else
						SYSIM_EX+=" $SI"
					fi
				else
					SYSIM_EX="$SI"
				fi
			done
	cd - > /dev/null

    log_highlight "Command Examples:"
    echo "./rootAVD.sh"
	echo "./rootAVD.sh ListAllAVDs"
	echo "./rootAVD.sh InstallApps"
	echo ""

	for SYSIM in $SYSIM_EX;do
		if [[ ! "$SYSIM" == "" ]]; then
			echo "./rootAVD.sh $SYSIM"
			echo "./rootAVD.sh $SYSIM FAKEBOOTIMG"
			echo "./rootAVD.sh $SYSIM DEBUG PATCHFSTAB GetUSBHPmodZ"
			echo "./rootAVD.sh $SYSIM restore"
			echo "./rootAVD.sh $SYSIM InstallKernelModules"
			echo "./rootAVD.sh $SYSIM InstallPrebuiltKernelModules"
			echo "./rootAVD.sh $SYSIM InstallPrebuiltKernelModules GetUSBHPmodZ PATCHFSTAB DEBUG"
			echo "./rootAVD.sh $SYSIM AddRCscripts"
			echo ""
		else
			echo ""
            log_warning "No ramdisk files could be found"
			echo ""
		fi
	done
}

ShowHelpText() {
bold=$(tput bold)
normal=$(tput sgr0)
echo "${bold}rootAVD A Script to root AVD by Eduardo Mejia${normal}"
echo ""
echo "Usage:	${bold}rootAVD [DIR/ramdisk.img] [OPTIONS] | [EXTRA ARGUMENTS]${normal}"
echo "or:	${bold}rootAVD [ARGUMENTS]${normal}"
echo ""
echo "Arguments:"
echo "	${bold}ListAllAVDs${normal}			Lists Command Examples for ALL installed AVDs"
echo ""
echo "	${bold}InstallApps${normal}			Just install all APKs placed in the Apps folder"
echo ""
echo "Main operation mode:"
echo "	${bold}DIR${normal}				a path to an AVD system-image"
echo "					- must always be the ${bold}1st${normal} Argument after rootAVD"
echo "	"
echo "ADB Path | Ramdisk DIR | ANDROID_HOME:"
echo "	${bold}[M]ac/Darwin:${normal}			export PATH=$defaultHOME_M/platform-tools:\$PATH"
echo "					export PATH=\$ANDROID_HOME/platform-tools:\$PATH"
echo "					system-images/android-\$API/google_apis_playstore/x86_64/"
echo "	"
echo "	${bold}[L]inux:${normal}			export PATH=$defaultHOME_L/platform-tools:\$PATH"
echo "					export PATH=\$ANDROID_HOME/platform-tools:\$PATH"
echo "					system-images/android-\$API/google_apis_playstore/x86_64/"
echo "	"
echo "	${bold}[W]indows:${normal}			set PATH=%LOCALAPPDATA%\Android\Sdk\platform-tools;%PATH%"
echo "					set PATH=%ANDROID_HOME%\platform-tools;%PATH%"
echo "					system-images\android-\$API\google_apis_playstore\x86_64\\"
echo "	"
echo "	${bold}ANDROID_HOME:${normal}			By default, the script uses ${bold}$defaultHOME${normal}, to set its Android Home"
echo "					directory, search for AVD system-images and ADB binarys. This behaviour"
echo "					can be overwritten by setting the ANDROID_HOME variable."
echo "					e.g. ${bold}export ANDROID_HOME=~/Downloads/sdk${normal}"
echo "	"
echo "	${bold}\$API:${normal}				25,29,30,31,32,33,34,UpsideDownCake,etc."
echo "	"
echo "Options:"
echo "	${bold}restore${normal}				restore all existing ${bold}.backup${normal} files, but doesn't delete them"
echo "					- the AVD doesn't need to be running"
echo "					- no other Argument after will be processed"
echo "	"
echo "	${bold}InstallKernelModules${normal}		install ${bold}custom build kernel and its modules${normal} into ramdisk.img"
echo "					- kernel (bzImage) and its modules (initramfs.img) are inside rootAVD"
echo "					- both files will be deleted after installation"
echo "	"
echo "	${bold}InstallPrebuiltKernelModules${normal}	download and install an ${bold}AOSP prebuilt kernel and its modules${normal} into ramdisk.img"
echo "					- similar to ${bold}InstallKernelModules${normal}, but the AVD needs to be online"
echo "	"
echo "	${bold}AddRCscripts${normal}			install all custom *.rc scripts, placed in the rootAVD folder, into ramdisk.img/overlay.d/sbin"
echo "	"
echo "Options are ${bold}exclusive${normal}, only one at the time will be processed."
echo "	"
echo "Extra Arguments:"
echo "	${bold}DEBUG${normal}				${bold}Debugging Mode${normal}, prevents rootAVD to pull back any patched file"
echo "	"
echo "	${bold}PATCHFSTAB${normal}			${bold}fstab.ranchu${normal} will get patched to automount Block Devices like ${bold}/dev/block/sda1${normal}"
echo "					- other entries can be added in the script as well"
echo "					- a custom build Kernel might be necessary"
echo "	"
echo "	${bold}GetUSBHPmodZ${normal}			The ${bold}USB HOST Permissions Module Zip${normal} will be downloaded into ${bold}/sdcard/Download${normal}"
echo "	"
echo "	${bold}FAKEBOOTIMG${normal}			Creates a ${bold}fake Boot.img${normal} file that can directly be patched from the ${bold}Magisk APP${normal}"
echo "					- Magisk will be launched to patch the fake Boot.img ${bold}within 60s${normal}"
echo "					- the fake Boot.img will be placed under ${bold}/sdcard/Download/fakeboot.img${normal}"
echo "	"
echo "Extra Commands can be ${bold}combined${normal}, there is no particular order."
echo "	"
echo "${bold}Notes: rootAVD will${normal}"
echo "- always create ${bold}.backup${normal} files of ${bold}ramdisk.img${normal} and ${bold}kernel-ranchu${normal}"
echo "- ${bold}replace${normal} both when done patching"
echo "- show a ${bold}Menu${normal}, to choose the Magisk Version ${bold}(Stable || Canary || Alpha)${normal}, if the AVD is ${bold}online${normal}"
echo "- make the ${bold}choosen${normal} Magisk Version to its ${bold}local${normal}"
echo "- install all APKs placed in the Apps folder"
FindSystemImages
exit
}

ProcessArguments() {
    DEBUG=false
    PATCHFSTAB=false
    GetUSBHPmodZ=false
    RAMDISKIMG=false
    restore=false
    InstallKernelModules=false
    InstallPrebuiltKernelModules=false
    ListAllAVDs=false
    InstallApps=false
    UpdateBusyBoxScript=false
    AddRCscripts=false
    toggleRamdisk=false
    FAKEBOOTIMG=false
    EMUDEVICEID=""
    RAMDISKPATH=""
    SOURCING=false

    # Check if first argument exists and might be the ramdisk path
    if [ $# -gt 0 ]; then
        # Check if first arg is NOT a known flag
        firstarg="$1"
        if [ "${firstarg#--}" = "$firstarg" ] && \
           [ "$firstarg" != "DEBUG" ] && \
           [ "$firstarg" != "PATCHFSTAB" ] && \
           [ "$firstarg" != "GetUSBHPmodZ" ] && \
           [ "$firstarg" != "ListAllAVDs" ] && \
           [ "$firstarg" != "InstallApps" ] && \
           [ "$firstarg" != "UpdateBusyBoxScript" ] && \
           [ "$firstarg" != "AddRCscripts" ] && \
           [ "$firstarg" != "toggleRamdisk" ] && \
           [ "$firstarg" != "FAKEBOOTIMG" ] && \
           [ "$firstarg" != "restore" ] && \
           [ "$firstarg" != "InstallKernelModules" ] && \
           [ "$firstarg" != "InstallPrebuiltKernelModules" ] && \
           [ "$firstarg" != "SOURCING" ]; then
            # Not a flag, assume it's the ramdisk path
            RAMDISKPATH="$firstarg"
            RAMDISKIMG=true
            shift
        fi
    fi

    # Process remaining arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --EMUDEVICEID)
                EMUDEVICEID="$2"
                shift # past argument
                shift # past value
                ;;
            --RAMDISKPATH)
                if [ $# -gt 1 ]; then
                    RAMDISKPATH="$2"
                    RAMDISKIMG=true
                    shift 2
                else
                    log_error "No value provided for --RAMDISKPATH"
                    ShowHelpText
                    abort_script
                fi
                ;;
            DEBUG)
                DEBUG=true
                shift
                ;;
            PATCHFSTAB)
                PATCHFSTAB=true
                shift
                ;;
            GetUSBHPmodZ)
                GetUSBHPmodZ=true
                shift
                ;;
            ListAllAVDs)
                ListAllAVDs=true
                shift
                ;;
            InstallApps)
                InstallApps=true
                shift
                ;;
            UpdateBusyBoxScript)
                UpdateBusyBoxScript=true
                shift
                ;;
            AddRCscripts)
                AddRCscripts=true
                shift
                ;;
            toggleRamdisk)
                toggleRamdisk=true
                shift
                ;;
            FAKEBOOTIMG)
                FAKEBOOTIMG=true
                shift
                ;;
            restore)
                restore=true
                shift
                ;;
            InstallKernelModules)
                InstallKernelModules=true
                shift
                ;;
            InstallPrebuiltKernelModules)
                InstallPrebuiltKernelModules=true
                shift
                ;;
            SOURCING)
                SOURCING=true
                shift
                ;;
            *)
                # If it's the first argument and matches RAMDISKPATH, skip (already processed)
                if [ "$1" = "$RAMDISKPATH" ] && [ "$RAMDISKIMG" = "true" ]; then
                    shift
                else
                    log_error "Unknown option: $1"
                    ShowHelpText
                    abort_script
                fi
                ;;
        esac
    done

    # Export variables
    export DEBUG
    export PATCHFSTAB
    export GetUSBHPmodZ
    export RAMDISKIMG
    export restore
    export InstallKernelModules
    export InstallPrebuiltKernelModules
    export ListAllAVDs
    export InstallApps
    export UpdateBusyBoxScript
    export AddRCscripts
    export toggleRamdisk
    export SOURCING
    export FAKEBOOTIMG
    export EMUDEVICEID
    export RAMDISKPATH
    
    # Initialize DEBUG value for logging functions if not already set
    if [ -z "$DEBUG" ]; then
        DEBUG=false
    fi
}

# Script Entry Point
# Checking in which shell we are

INEMULATOR=false
SHELLRESULT=$(getprop 2>/dev/null)
SHELLRESULT="$?"
if [[ "$SHELLRESULT" == "0" ]]; then
	INEMULATOR=true
	DERIVATE=$(getprop ro.boot.hardware 2>/dev/null)
	if [[ "$DERIVATE" == "" ]]; then
		$(which /system/xbin/bstk/su > /dev/null 2>&1)
		DERIVATE="$?"
	fi
	if [ ! -z $PREPBBMAGISK ]; then
		# Initialize color variables if this is first output
		BLACK='\033[0;30m'
		RED='\033[0;31m'
		GREEN='\033[0;32m'
		YELLOW='\033[0;33m'
		BLUE='\033[0;34m'
		PURPLE='\033[0;35m'
		CYAN='\033[0;36m'
		WHITE='\033[0;37m'
		BOLD='\033[1m'
		NC='\033[0m' # No Color
		
		echo -e "${BLUE}[$(date +"%Y-%m-%d %H:%M:%S") INFO]${NC} We are now in Magisk Busybox STANDALONE (D)ASH"
		# Don't use $BB from now on
	else
		# Initialize color variables if this is first output
		BLACK='\033[0;30m'
		RED='\033[0;31m'
		GREEN='\033[0;32m'
		YELLOW='\033[0;33m'
		BLUE='\033[0;34m'
		PURPLE='\033[0;35m'
		CYAN='\033[0;36m'
		WHITE='\033[0;37m'
		BOLD='\033[1m'
		NC='\033[0m' # No Color
		
        log_info "We are in a $DERIVATE emulator shell"
	fi
fi

#if [[ $SHELL == "ranchu" ]]; then
#	log_info "We are in an emulator shell"
#	RANCHU=true
#fi
#if [[ $SHELL == "cheets" ]]; then
#	log_info "We are in a ChromeOS shell"
#	RANCHU=true
#fi

export DERIVATE
export INEMULATOR

if $INEMULATOR; then
	InstallMagiskToAVD $@
	return 0
fi

ProcessArguments $@
GetANDROIDHOME

if ( "$SOURCING" ); then
	return
fi

	if ( "$DEBUG" ); then
		log_debug "We are in Debug Mode"
		log_debug "DEBUG: ${CYAN}$DEBUG${NC}"
		log_debug "PATCHFSTAB: ${CYAN}$PATCHFSTAB${NC}"
		log_debug "GetUSBHPmodZ: ${CYAN}$GetUSBHPmodZ${NC}"
		log_debug "RAMDISKIMG: ${CYAN}$RAMDISKIMG${NC}"
		log_debug "restore: ${CYAN}$restore${NC}"
		log_debug "InstallKernelModules: ${CYAN}$InstallKernelModules${NC}"
		log_debug "InstallPrebuiltKernelModules: ${CYAN}$InstallPrebuiltKernelModules${NC}"
		log_debug "ListAllAVDs: ${CYAN}$ListAllAVDs${NC}"
		log_debug "InstallApps: ${CYAN}$InstallApps${NC}"
		log_debug "UpdateBusyBoxScript: ${CYAN}$UpdateBusyBoxScript${NC}"
		log_debug "AddRCscripts: ${CYAN}$AddRCscripts${NC}"
		log_debug "toggleRamdisk: ${CYAN}$toggleRamdisk${NC}"
		log_debug "SOURCING: ${CYAN}$SOURCING${NC}"
		log_debug "FAKEBOOTIMG: ${CYAN}$FAKEBOOTIMG${NC}"
		enable_trace
	fi

if ( "$ListAllAVDs" ); then
    FindSystemImages
    exit 0
    else
        if [ -z "$InstallApps" ] && [ -z "$RAMDISKPATH" ]; then
            if [[ "$1" == "" ]]; then
                ShowHelpText
            fi
                if ( ! "$restore" ); then
                    if (checkfile "$ANDROIDHOME/$1" -eq 0); then
                        ShowHelpText
                    fi
                fi

        fi
fi
# Initialize color variables if this is first output
BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info "We are NOT in an emulator shell"

CopyMagiskToAVD $@
