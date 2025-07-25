#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2020 Joyent, Inc.
# Copyright (c) 2012, 2015 by Delphix. All rights reserved.
# Copyright (c) 2013 DEY Storage Systems, Inc. All rights reserved.
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright 2018 Nexenta Systems, Inc.
# Copyright 2018 Gary Mills
# Copyright 2019 Peter Tribble
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

include ../Makefile.master

#	Commands in the FIRST_SUBDIRS list are built before starting the build
#	of other commands.  Currently this includes only 'isaexec' and
#	'platexec'.  This is necessary because $(ROOT)/usr/lib/isaexec or
#	$(ROOT)/usr/lib/platexec must exist when some other commands are built
#	because their 'make install' creates a hard link to one of them.
#
#	Commands are listed one per line so that most changes can be auto-merged.
#

FIRST_SUBDIRS=		\
	isaexec		\
	platexec

COMMON_SUBDIRS=	\
	allocate	\
	Adm		\
	adbgen		\
	acct		\
	acctadm		\
	arch		\
	asa		\
	ast		\
	audio		\
	auths		\
	autopush	\
	awk		\
	awk_xpg4	\
	backup		\
	banner		\
	bart		\
	basename	\
	bc		\
	bdiff		\
	beadm		\
	boot		\
	busstat		\
	cal		\
	captoinfo	\
	cat		\
	ccidadm		\
	cdrw		\
	cfgadm		\
	checkeq		\
	checknr		\
	chgrp		\
	chmod		\
	chown		\
	chroot		\
	clear		\
	clinfo		\
	cmd-crypto	\
	cmd-inet	\
	col		\
	compress	\
	connstat	\
	consadm		\
	coreadm		\
	cpio		\
	cron		\
	crypt		\
	csplit		\
	ctfconvert	\
	ctfdiff		\
	ctfdump		\
	ctfmerge	\
	ctrun		\
	ctstat		\
	ctwatch		\
	datadm		\
	date		\
	dc		\
	dd		\
	demangle	\
	deroff		\
	devfsadm	\
	syseventd	\
	devctl		\
	devinfo		\
	devmgmt		\
	devprop		\
	dfs.cmds	\
	diff		\
	diff3		\
	diffmk		\
	dircmp		\
	dirname		\
	dis		\
	diskinfo	\
	dispadmin	\
	dladm		\
	dlstat		\
	dlutil		\
	dmesg		\
	dodatadm	\
	dtrace		\
	du		\
	dumpadm		\
	dumpcs		\
	echo		\
	ed		\
	eeprom		\
	eject		\
	emul64ioctl	\
	enhance		\
	env		\
	etdump		\
	expand		\
	expr		\
	exstr		\
	factor		\
	false		\
	fcinfo		\
	fcoesvc		\
	fdetach		\
	fdformat	\
	fdisk		\
	filesync	\
	file		\
	find		\
	flowadm		\
	flowstat	\
	fm		\
	fmt		\
	fmthard		\
	fmtmsg		\
	fold		\
	format		\
	fs.d		\
	fstyp		\
	fuser		\
	fwflash		\
	gcore		\
	gencat		\
	geniconvtbl	\
	genmsg		\
	getconf		\
	getdevpolicy	\
	getent		\
	getfacl		\
	getmajor	\
	getopt		\
	gettext		\
	gettxt		\
	grep		\
	groups		\
	growfs		\
	grpck		\
	hal		\
	halt		\
	head		\
	hostid		\
	hostname	\
	hotplug		\
	hotplugd	\
	ibd_upgrade	\
	iconv		\
	id		\
	idmap		\
	infocmp		\
	init		\
	initpkg		\
	install.d	\
	intrd		\
	intrstat	\
	ipcrm		\
	ipcs		\
	ipdadm		\
	ipf		\
	isainfo		\
	isalist		\
	iscsiadm	\
	iscsid		\
	iscsitsvc	\
	itadm		\
	kbd		\
	keyserv		\
	killall		\
	krb5		\
	ktest		\
	kvmstat		\
	last		\
	lastcomm	\
	ldap		\
	ldapcachemgr	\
	lgrpinfo	\
	line		\
	link		\
	dlmgmtd		\
	listen		\
	loadkeys	\
	locale		\
	localedef	\
	locator		\
	lockstat	\
	lofiadm		\
	logadm		\
	logger		\
	login		\
	logins		\
	logname		\
	lp		\
	look		\
	ls		\
	mach		\
	mail		\
	mailx		\
	mailwrapper	\
	make		\
	makekey		\
	man		\
	mandoc		\
	mdb		\
	mesg		\
	mkdir		\
	mkfifo		\
	mkfile		\
	mkmsgs		\
	mknod		\
	mkpwdict	\
	mktemp		\
	modload		\
	more		\
	mpathadm	\
	msgfmt		\
	msgid		\
	mt		\
	mv		\
	mvdir		\
	ndmpadm		\
	ndmpd		\
	ndmpstat	\
	netadm		\
	netfiles	\
	newform		\
	newgrp		\
	news		\
	newtask		\
	nice		\
	nl		\
	nlsadmin	\
	nohup		\
	nsadmin		\
	nscd		\
	oamuser		\
	od		\
	pack		\
	pagesize	\
	passmgmt	\
	passwd		\
	pathchk		\
	pbind		\
	pcidb		\
	pcidr		\
	pcieadm		\
	pcieb		\
	pcitool		\
	perl		\
	pfexec		\
	pfexecd		\
	pg		\
	pginfo		\
	pgstat		\
	pgrep		\
	picl		\
	plimit		\
	plockstat	\
	policykit	\
	pools		\
	power		\
	ppgsz		\
	pr		\
	prctl		\
	print		\
	printf		\
	priocntl	\
	profiles	\
	projadd		\
	projects	\
	prstat		\
	prtconf		\
	prtvtoc		\
	ps		\
	psradm		\
	psrinfo		\
	psrset		\
	ptools		\
	pwck		\
	pwconv		\
	pwd		\
	raidctl		\
	raidz_test	\
	ramdiskadm	\
	rcap		\
	rcm_daemon	\
	rctladm		\
	regcmp		\
	renice		\
	rm		\
	rmdir		\
	rmmount		\
	rmvolmgr	\
	rmt		\
	roles		\
	rpcbind		\
	rpcgen		\
	rpcinfo		\
	rpcsvc		\
	runat		\
	sa		\
	saf		\
	sasinfo		\
	savecore	\
	sbdadm		\
	script		\
	scsi		\
	sdiff		\
	sed		\
	sendmail	\
	setfacl		\
	setmnt		\
	setpgrp		\
	sgs		\
	sleep		\
	smbios		\
	smbsrv		\
	smserverd	\
	soelim		\
	sort		\
	spd		\
	spell		\
	split		\
	sqlite		\
	srptadm		\
	srptsvc		\
	ssh		\
	stat		\
	stmfadm		\
	stmfproxy	\
	stmfsvc		\
	stmsboot	\
	streams		\
	strings		\
	su		\
	sulogin		\
	sunpc		\
	svc		\
	svr4pkg		\
	swap		\
	sync		\
	sysdef		\
	syseventadm	\
	syslogd		\
	tabs		\
	tail		\
	tar		\
	tcopy		\
	tcpd		\
	th_tools	\
	tic		\
	time		\
	tip		\
	touch		\
	tput		\
	tr		\
	trapstat	\
	true		\
	truss		\
	tty		\
	ttymon		\
	tzreload	\
	uadmin		\
	ul		\
	uname		\
	units		\
	unlink		\
	unpack		\
	userattr	\
	users		\
	utmp_update	\
	utmpd		\
	uuidgen		\
	valtools	\
	varpd		\
	vgrind		\
	volcheck	\
	volrmmount	\
	vrrpadm		\
	vscan		\
	vt		\
	vtfontcvt	\
	w		\
	wall		\
	which		\
	who		\
	whodo		\
	wracct		\
	write		\
	xargs		\
	xstr		\
	yes		\
	ypcmd		\
	yppasswd	\
	zdb		\
	zdump		\
	zfs		\
	zhack		\
	zic		\
	zinject		\
	zlogin		\
	zoneadm		\
	zoneadmd	\
	zonecfg		\
	zonename	\
	zonestat	\
	zlook		\
	zpool		\
	zstreamdump	\
	ztest

JAVA_SUBDIRS = availdevs	# Uses libzfs_jni, for some reason

$(ENABLE_JAVA)COMMON_SUBDIRS += $(JAVA_SUBDIRS)

# XXXARM: Things not built on AArch64 yet
# abi - not interesting
# bnu - uses FILE internals not available to LP64
# latencytop - needs glib
# powertop - not ported
# rmformat - not ported (or useful?)
#
# cpc - not ported (nor libcpc)
# csh - not 64bit clean
# eqn - not 64bit clean
# gss - not 64bit clean
# isns - not 64bit clean
# luxadm - super confused about platforms, and probably needs libs
# oawk - not 64bit clean?
# prtdiag - not ported
# refer - not 64bit clean
# sh - not 64bit clean
# srchtxt - not 64bit clean
# tbl - not 64bit clean
# troff - not 64bit clean
# tsol - not ported (or 64bit clean)
# vi - not 64bit clean / not ported
$(NOT_AARCH64_BLD)COMMON_SUBDIRS +=	\
	abi		\
	bnu		\
	cpc		\
	csh		\
	eqn		\
	gss		\
	isns		\
	latencytop	\
	luxadm		\
	oawk		\
	powertop	\
	prtdiag		\
	refer		\
	rmformat	\
	sh		\
	srchtxt		\
	tbl		\
	troff		\
	tsol		\
	vi		\

$(HAVE_CLOSED_BINS)COMMON_SUBDIRS += sdpadm

aarch64_SUBDIRS=	\
	ahciem		\
	ficl		\
	xhci

i386_SUBDIRS=		\
	acpi		\
	acpihpd		\
	addbadsec	\
	ahciem		\
	amdzen		\
	bhyve		\
	bhyvectl	\
	biosdev		\
	cxgbetool	\
	diskscan	\
	ficl		\
	nvmeadm		\
	pptadm		\
	rdmsr		\
	rsrvrctl	\
	rtc		\
	ucodeadm	\
	xhci		\
	xvm

sparc_SUBDIRS=		\
	dcs		\
	device_remap	\
	drd		\
	fruadm		\
	ldmad		\
	oplhpd		\
	prtdscp		\
	prtfru		\
	scadm		\
	sckmd		\
	sf880drd	\
	virtinfo	\
	vntsd

#
# Commands that are messaged.  Note that 'lp' comes first
# (see previous comment about 'lp'.)
#
MSGSUBDIRS=		\
	lp		\
	abi		\
	acctadm		\
	allocate	\
	asa		\
	ast		\
	audio		\
	audit		\
	auditconfig	\
	auditd		\
	auditrecord	\
	auditset	\
	auths		\
	autopush	\
	awk		\
	awk_xpg4	\
	backup		\
	banner		\
	bart		\
	basename	\
	bdiff		\
	beadm		\
	bnu		\
	busstat		\
	cal		\
	cat		\
	cdrw		\
	cfgadm		\
	checkeq		\
	checknr		\
	chgrp		\
	chmod		\
	chown		\
	cmd-crypto	\
	cmd-inet	\
	col		\
	compress	\
	connstat	\
	consadm		\
	coreadm		\
	cpio		\
	cpc		\
	cron		\
	csh		\
	csplit		\
	ctrun		\
	ctstat		\
	ctwatch		\
	datadm		\
	date		\
	dc		\
	dcs		\
	dd		\
	deroff		\
	devfsadm	\
	dfs.cmds	\
	diff		\
	diffmk		\
	dladm		\
	dlstat		\
	du		\
	dumpcs		\
	ed		\
	eject		\
	env		\
	eqn		\
	expand		\
	expr		\
	fcinfo		\
	file		\
	filesync	\
	find		\
	flowadm		\
	flowstat	\
	fm		\
	fold		\
	fs.d		\
	fwflash		\
	geniconvtbl	\
	genmsg		\
	getconf		\
	getent		\
	gettext		\
	gettxt		\
	grep		\
	grpck		\
	gss		\
	halt		\
	head		\
	hostname	\
	hotplug		\
	iconv		\
	id		\
	idmap		\
	isaexec		\
	iscsiadm	\
	iscsid		\
	isns		\
	itadm		\
	kbd		\
	krb5		\
	last		\
	ldap		\
	ldapcachemgr	\
	lgrpinfo	\
	locale		\
	lofiadm		\
	logadm		\
	logger		\
	logins		\
	ls		\
	luxadm		\
	mailx		\
	make		\
	man		\
	mesg		\
	mkdir		\
	mkpwdict	\
	mktemp		\
	more		\
	mpathadm	\
	msgfmt		\
	mv		\
	ndmpadm		\
	ndmpstat	\
	newgrp		\
	newtask		\
	nice		\
	nohup		\
	oawk		\
	pack		\
	passwd		\
	passmgmt	\
	pathchk		\
	pfexec		\
	pg		\
	pgrep		\
	picl            \
	pools		\
	power		\
	pr		\
	praudit		\
	print		\
	profiles	\
	projadd		\
	projects	\
	prstat		\
	prtdiag		\
	ps		\
	psrinfo		\
	ptools		\
	pwconv		\
	pwd		\
	raidctl		\
	ramdiskadm	\
	rcap		\
	rcm_daemon	\
	refer		\
	regcmp		\
	renice		\
	roles		\
	rm		\
	rmdir		\
	rmformat	\
	rmmount		\
	rmvolmgr	\
	sasinfo		\
	sbdadm		\
	scadm		\
	script		\
	scsi		\
	sdiff		\
	sgs		\
	sh		\
	smbsrv		\
	sort		\
	split		\
	srptadm		\
	stat		\
	stmfadm		\
	stmsboot	\
	strings		\
	su		\
	svc		\
	svr4pkg		\
	swap		\
	syseventadm	\
	syseventd	\
	tabs		\
	tar		\
	tbl		\
	time		\
	touch		\
	tput		\
	troff		\
	tsol		\
	tty		\
	ttymon		\
	tzreload	\
	ul		\
	uname		\
	units		\
	unlink		\
	unpack		\
	userattr	\
	valtools	\
	vgrind		\
	vi		\
	volcheck	\
	volrmmount	\
	vrrpadm		\
	vscan		\
	w		\
	who		\
	whodo		\
	wracct		\
	write		\
	xargs		\
	yppasswd	\
	zdump		\
	zfs		\
	zic		\
	zlogin		\
	zoneadm		\
	zoneadmd	\
	zonecfg		\
	zonename	\
	zpool		\
	zonestat

$(HAVE_CLOSED_BINS)MSGSUBDIRS += sdpadm

sparc_MSGSUBDIRS=	\
	fruadm		\
	prtdscp		\
	prtfru		\
	virtinfo	\
	vntsd

i386_MSGSUBDIRS=	\
	rdmsr		\
	ucodeadm

#
# commands that use dcgettext for localized time, LC_TIME
#
DCSUBDIRS=		\
	cal		\
	cfgadm		\
	diff		\
	ls		\
	pr		\
	ps		\
	tar		\
	w		\
	who		\
	whodo		\
	write

#
# commands that belong only to audit.
#
AUDITSUBDIRS=		\
	amt		\
	audit		\
	audit_warn	\
	auditconfig	\
	auditd		\
	auditrecord	\
	auditreduce	\
	auditset	\
	auditstat

# XXXARM: not 64bit clean
$(NOT_AARCH64_BLD)AUDITSUBDIRS += praudit

all :=		TARGET = all
install :=	TARGET = install
clean :=	TARGET = clean
clobber :=	TARGET = clobber
_msg :=		TARGET = _msg
_dc :=		TARGET = _dc

.KEEP_STATE:

SUBDIRS = $(COMMON_SUBDIRS) $($(MACH)_SUBDIRS)

.PARALLEL:	$(SUBDIRS) $(MSGSUBDIRS) $(AUDITSUBDIRS)

all install clean clobber: $(FIRST_SUBDIRS) .WAIT $(SUBDIRS) \
	$(AUDITSUBDIRS)

#
# Manifests cannot be checked in parallel, because we are using
# the global repository that is in $(SRC)/cmd/svc/seed/global.db.
# For this reason, to avoid .PARALLEL and .NO_PARALLEL conflicts,
# we spawn off a sub-make to perform the non-parallel 'make check'
#
check:
	$(MAKE) -f Makefile.check check

#
# The .WAIT directive works around an apparent bug in parallel make.
# Evidently make was getting the target _msg vs. _dc confused under
# some level of parallelization, causing some of the _dc objects
# not to be built.
#
_msg: $(MSGSUBDIRS) $($(MACH)_MSGSUBDIRS) .WAIT _dc

_dc: $(DCSUBDIRS)

#
# Dependencies
#
fs.d:	fstyp
ast:	isaexec
print:	lp
fmt:	mailx

$(FIRST_SUBDIRS) $(SUBDIRS) $(AUDITSUBDIRS): FRC
		cd $@; pwd; $(MAKE) $(TARGET)

FRC:
