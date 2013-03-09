piuparts README
---------------

Author: Lars Wirzenius
Email: <liw@iki.fi>

After reading this README you probably also want to have a look
at the piuparts manpage, to learn about the available options.
But read this document first!

== Introduction

piuparts is a tool for testing that .deb packages can be
installed, upgraded, and removed without problems. The
name, a variant of something suggested by Tollef Fog
Heen, is short for "package installation, upgrading, and
removal testing suite".

piuparts is licensed under the GNU General Public License,
version 2, or (at your option) any later version.

http://piuparts.debian.org has been testing the Debian archive
since the Lenny release in 2009, though responsible maintainers
run piuparts locally before uploading packages to the archive.


== How to use piuparts in 5 minutes

=== Basic Usage

Testing your packages with piuparts is as easy as typing at the
console prompt:

----
# piuparts sm_0.6-1_i386.deb
----

Note that in order to work, piuparts has to be executed as user
root, so you need to be logged as root or use 'sudo'.

This will create a sid chroot with debootstrap, where it'll test
your package.

If you want to test your package in another release, for example,
squeeze, you can do so with:

----
# piuparts ./sm_0.6-1_i386.deb -d squeeze
----

By default, this will read the first mirror from your
'/etc/apt/sources.list ' file. If you want to specify a different
mirror you can do it with the option '-m':

----
# piuparts ./sm_0.6-1_i386.deb -m http://ftp.de.debian.org/debian
----

It's possible to use -d more than once. For example, to do a first
installation in stable, then upgrade to testing, then upgrade to
unstable and then upgrade to the local package use this:

----
# piuparts -d stable -d testing -d unstable ./sm_0.6-1_i386.deb
----


=== Some tips

If you use piuparts on a regular basis, waiting for it to create
a chroot every time takes too much time, even if you are using a
local mirror or a caching tool such as approx.

Piuparts has the option of using a tarball as the contents of the
initial chroot, instead of building a new one with debootstrap. A
easy way to use this option is use a tarball created with
pbuilder. If you are not a pbuilder user, you can create this
tarball with the command (again, as root):

----
# pbuilder --create
----

then you only have to remember to update this tarball with:

----
# pbuilder --update
----

To run piuparts using this tarball:

----
# piuparts -p ./sm_0.6-1_i386.deb
----

If you want to use your own pre-made tarball:

----
# piuparts --basetgz=/path/to/my/tarball.tgz ./sm_0.6-1_i386.deb
----

Piuparts also has the option of using a tarball as the contents
of the initial chroot, instead of building a new one with
pbuilder. You can save a tarball for later use with the '-s'
('--save') piuparts option. Some people like this, others prefer
to only have to maintain one tarball. Read the piuparts manpage
about the '-p', '-b' and '-s' options

piuparts has a manpage too.

=== Piuparts tests

By default, piuparts does two tests:

. Installation and purging test.
. Installation, upgrade and purging tests.

The first test installs the package in a minimal chroot, removes
it and purges it. The second test installs the current version in
the archive of the given packages, then upgrades to the new
version (deb files given to piuparts in the input), removes and
purges.

If you only want to perfom the first test, you can use the
option: '--no-upgrade-test'

=== Testing packages in the config-files-remaining state

The --install-remove-install option modifies the three piuparts
tests in order to test package installation while config files
from a previous installation are remaining, but the package itself
was removed inbetween.
This exercises different code paths in the maintainer scripts.

. Installation and purging test: install, remove, install again
 and purge.
. Installation, upgrade and purging test: install the old version,
 remove, install the new version and purge.
. Distupgrade test: install the version from the first
 distribution, remove, distupgrade to the last distribution,
 install the new version.

=== Analyzing piuparts results

When piuparts finishes all the tests satisfactorily, you will get
these lines as final output:

----
0m39.5s INFO: PASS: All tests.
0m39.5s INFO: piuparts run ends.
----

Anyway, it is a good idea to read the whole log in order to
discover possible problems that did not stop the piuparts
execution.

If you do not get those lines, piuparts has failed during a test.
The latest lines should give you a pointer to the problem with
your package.

== Custom scripts with piuparts

You can specify several custom scripts to be run inside piuparts.
You have to store them in a directory and give it as argument to
piuparts: '--scriptsdir=/dir/with/the/scripts'
This option can be given multiple times. The scripts from all
directories will be merged together (and later ones may overwrite
earlier scripts with the same filename).

The script prefix determines in which step it is executed. You
can run several scripts in every step, they are run in
alphabetical order.

The scripts need to be executable and are run *inside* the piuparts
chroot and can only be shell scripts. If you want to run Python or
Perl scripts, you have to install Python or Perl. The chroot where
piuparts is run is minimized and does not include Perl.

The variable PIUPARTS_OBJECTS is set to the packages currently
being tested (seperated by spaces, if applicable) or the .changes
file(s) being used.  So when running in master-slave mode, it
will be set to the (one) package being tested at a time.

Depending on the current test, the variable PIUPARTS_TEST is set
to

. 'install' (installation and purging test),
. 'upgrade' (installation, upgrade and purging tests) or
. 'distupgrade'.

During the 'upgrade' and 'distupgrade' tests, the variable
PIUPARTS_PHASE is set to one of the following values:

. 'install' while initially installing the packages from the
 repository,
. 'upgrade' when upgrading to the .debs,
. 'distupgrade' while reinstalling the packages after
 'apt-get dist-upgrade' to ensure they were not removed accidently
During the 'install' test, the PIUPARTS_PHASE variable is set to
'install'.

The current distribution is available in the variable
PIUPARTS_DISTRIBUTION.

The following prefixes for scripts are recognized:

'post_setup_' - after the *setup* of the chroot is finished.
Before metadata of the chroot is recorded for later comparison.

'pre_test_' - at the beginning of each test. After metadata of
the chroot was recorded for later comparison.

'pre_install_' - before *installing* your package. Depending on
the test, this may be run multiple times. The PIUPARTS_TEST and
PIUPARTS_PHASE variables can be used to distinguish the cases.

'post_install_' - after *installing* your package and its
dependencies.  Depending on the test, this may be run multiple
times. The PIUPARTS_TEST and PIUPARTS_PHASE variables can be used
to distinguish the cases.

'pre_remove_' - before *removing* your package.

'post_remove_' - after *removing* your package.

'post_purge_' - after *purging* your package. Right before
comparing the chroot with the initially recorded metadata.

'pre_distupgrade_' - before *upgrading* the chroot to the *next
distribution*. The next distribution is available in the variable
PIUPARTS_DISTRIBUTION_NEXT.

'post_distupgrade_' - after *upgrading* the chroot to the *next
distribution*. The previous distribution is available in the
variable PIUPARTS_DISTRIBUTION_PREV.


=== Example custom scripts:

'$ cat post_install_numbers'
----
#!/bin/bash

number=`dpkg -l | wc -l`
echo "There are $number packages installed."
exit 0
----

'$ cat post_setup_package'
----
#!/bin/sh

echo "$PIUPARTS_OBJECTS will now get tested."
exit 0
----


== Distributed testing

As part of the quality assurance effort of Debian, piuparts is
run on the Debian package archive. This requires a lot of
processing power, and so the work can be distributed over several
hosts.

There is one central machine, the master, and any number of slave
machines. Each slave machine connects to the master, via ssh, and
runs the piuparts-master program to report results of packages it
has tested already, and to get more work.

To set this up for yourself, the following steps should suffice:

. Pick a machine to run the master. It cannot be a chroot, but
 basically any real (or properly virtualized) Debian system is good
 enough.
. Install piuparts on it.
. Create an account for the master.
. Configure '/etc/piuparts/piuparts.conf' appropriately.
. Pick one or more slaves to run the slave. You can use the machine
 running the master also as a slave. Etch is fine, it can even be
 in a chroot.
. Install piuparts on it.
. Configure '/etc/piuparts/piuparts.conf' appropriately - if master
 and slave share the machine, they also share the config file.
. Create an account for the slave. This must be different from the
 master account.
. Create an ssh keypair for the slave. No passphrase.
. Add the slave's public key to the master's '.ssh/authorized_keys'
. Configure sudo on the slave machine to allow the slave account
 run '/usr/sbin/piuparts' as root without password (otherwise
 you'll be typing in a password all the time).
. Run '/usr/share/piuparts/piuparts-slave' on the slave accounts.
 Packages that are installed want to use '/dev/tty', so you can't
 do this from cron. Also, you'll want to keep an eye on what is
 happening, to catch runaway processes and stuff.
. The logs go into the master account, into subdirectories.

Please note that running piuparts this way is somewhat risky, to
say the least. There are security implications that you want to
consider. It's best to do it on machines that you don't mind
wiping clean at a moment's notice, and preferably so that they
don't have direct network access.


=== Distributed piuparts testing protocol

The slave machine and the piuparts-master program communicate
using a simplistic line based protocol. SSH takes care of
authentication, so there is nothing in the protocol for that. The
protocol is transaction based: the slave gives a command, the
master program responds.  Commands and responses can be simple (a
single line) or long (a status line plus additional data lines).
Simple commands and responses are of the following format:

    'keyword arg1 arg2 arg3 ... argN'

The keyword is a command or status code ("ok"), and it and the
arguments are separated by spaces. An argument may not contain a
space.

A long command or response is deduced from the context: certain
commands always include additional data, and certain commands
always get a long response, if successful (error responses are
always simple). The first line of a long command or response is
the same as for a simple one, the additional lines are prefixed
with a space, and followed by a line containing only a period.

A sample session (">>" indicates what the slave sends, "<<" what
the master responds with):

----
<< hello
>> pass liwc 1.2.3-4
>>  The piuparts
>>  log file comes
>>  here
>> .
<< ok
>> reserve
<< ok vorbisgain 2.3-4
----

Here the slave first reports a successful test of package liwc,
version 1.2.3-4, and sends the piuparts log file for it. Then it
reserves a new package to test and the master gives it
vorbisgain, version 2.3-4.

The communication always starts with the master saying "hello".
The slave shall not speak until the master has spoken.

Commands and responses in this protocol:

----
Command: recycle
Success: ok
Failure: error
----
Slave asks master to enable logfile recycling mode. In this mode
logfiles that have been marked for rechecking will be deleted
and reissued in subsequent "reserve" commands. The "recycle"
command must be issued before the first "reserve" (or "status")
command. It will return "error" if no more logfiles are marked
for rechecking or the command is issued too late.

----
Command: idle
Success: ok <int>
----
Slave asks master whether it remembers having no packages
available at a previous "reserve" command. Returns 0 (not known
to be idle or timeout expired) or the number of seconds until
the master wants to recompute the package state. This command
should be given after "recycle" and logfile submission, but
before "reserve" or "status" commands. If the slave closes the
connection without issuing a "reserve" or "status" command, the
expensive Packages file parsing and status computation will be
skipped.

----
Command: reserve
Success: ok <packagename> <packageversion>
Failure: error
----
Slave asks master to reserve a package (a particular version of
it) for the slave to test.  The slave may reserve any number of
packages to test. If the transaction fails, there are no more
packages to test, and the slave should disconnect, wait some time
and try again.

----
Command: unreserve <packagename> <packageversion>
Success: ok
----

Slave informs master it cannot test the desired version of a
package and the package should be rescheduled by the master.

----
Command: pass <packagename> <packageversion>
          log file contents
         .
Success: ok
----

Slave reports that it has tested a particular version of a
package and that the package passed all tests. Master records
this and stores the log file somewhere suitable.

----
Command: fail <packagename> <packageversion>
          log file contents
         .
Success: ok
----

Same as "pass", but package failed one or more tests.

----
Command: untestable <packagename> <packageversion>
          log file contents
         .
Success: ok
----

Slave informs master it cannot test the desired version of a
package (perhaps it went away from the mirror?).

----
Command: status
Success: ok <package-state>=<count> <package-state>=<count>...
----
Slave asks master to report the number of packages in all
different states. The "status" command should only be issued
after all logs have been transmitted ("pass", "fail", and
"untestable" commands).

In all cases, if the master cannot respond with "ok" (e.g.,
because of a disk error storing a log file), it aborts and the
connection fails. The slave may only assume the command has
succeeded if the master responds with "ok".

The master may likewise abort, without an error message, if the
slave sends garbage, or sends too much data.


=== piuparts.conf configuration file

piuparts-master, piuparts-slave and piuparts-report share the
configuration file '/etc/piuparts/piuparts.conf'. The syntax is
defined by the Python ConfigParser class, and is, briefly, like
this:

----
    [master]
    foo = bar
----

==== global configuration

These settings have to be placed in the [global] section and are
used for all further sections.

* "sections" defaults to sid and defines which sections should be
 processed in master-slave mode. Each section defined here has to
 have a section with the section specific settings explained below.
 The first section defined should always be sid, because the data
 from first section a package is in is used for the source package
 html report.

* "master-host" is the host where the master exists. The slave will
 give this host to ssh. This option is mandatory.

* "master-user" is the username of the master. The slave will log in
 using this username. This option is mandatory.

* "master-directory" is the directory where the master keeps its
 files. Can be relative to the master's home directory.

* "slave-directory" is the directory where the slave keeps its
 files. Can be relative to the slave's home directory.

* "output-directory" is the directory where piuparts-report places
 the logfiles, generated html files, charts, ... that can be
 served by a webserver.

* "backup-directory" is the directory where the prepare_backup
 script will place copies of the history data needed to generate the
 plots. This directory should be included in system backups while
 the logfiles and html pages in 'master-directory' and
 'output-directory' (several GB of data) are regeneratable with some
 effort and can be excluded from backups. By default this is
 undefined meaning that no backups of the history data will be made.

* "doc-root" is the location where the webserver will serve the
 piuparts report from. Default: "/".

* "slave-load-max" specifies the system load limit when
 piuparts-slave will enter sleep mode. Operation will be resumed
 after load drops below 'slave-load-max - 1.0'. Floating point
 value. Defaults to 0 (= disabled).

* "proxy" sets the http_proxy that will be used for fetching
 Packages files etc. (by master/slave/report) and .debs etc. (by
 piuparts). This will override a http_proxy setting in the
 environment. By default (no value being set) the http_proxy
 variable from the environment will be used (and no proxy will be
 used if this is not set). It is highly recommended to use a proxy
 running on localhost (e.g. installing squid and using a setting of
 "http://localhost:3128") due to the high bandwidth consumption of
 piuparts and repeated downloading of the same files.

==== section specific configuration

The section specific settings will be reloaded each time a section
is being run. All these keys can be specified in the [global]
section, too, and will serve as defaults for all other sections
(overriding the builtin defaults).

* "master-command" is the command to run on master-host to start
 the master. When the master has been installed from the Debian
 package, the command is
 '/usr/share/piuparts/piuparts-master'.
 The section name will be given as a command line argument to this
 command.

* "idle-sleep" is the length of time the slave should wait before
 querying the master again if the master didn't have any new
 packages to test. In seconds, so a value of 300 would mean five
 minutes, and that seems to be a good value when there are fairly
 few slaves per master. The default is 300 seconds.

* "max-tgz-age" is used to specify the maximum age (in seconds)
 after which basesystem tarballs will be recreated. If recreation
 fails, the old tarball will be used again. The default is 2592000
 seconds, which is 30 days. A value of 0 disables recreation.

* "min-tgz-retry-delay" is used to specify the minimum time (in
 seconds) between attempts to recreate a tarball which was created
 more than "max-tgz-age" seconds ago. The default is 21600 seconds,
 which is 6h.

* "log-file" is the name of a file to where the master should write
 its log messages. In the default configuration file it is
 "$SECTION/master.log". To disable logging, set it to "/dev/null".

* "piuparts-command" is the command the slave uses to start
 piuparts. It should include 'sudo' if necessary so that piuparts
 runs with sufficient priviledges to do its testing (and that
 means root priviledges). This command should be given in the
 [global] section and include all flags that are common for all
 sections.

* "piuparts-flags" are appended to "piuparts-command" and should
 contain the section-specific flags.

* "tmpdir" is the scratch area where piuparts will create the
 chroots. Note: the filesystem where this is located must not be
 mounted with the nodev or nosuid options. This is a mandatory
 setting with no default. The scripts that are monitoring this
 directory for leftover mountpoints and chroots only evaluate the
 [global] setting.

* "description" is a synopsis of the test used in the report. A
 default description will be generated if this is not set or will
 be prepended (appended) if the description starts (ends) with
 '+'.

* "mirror" tells the slave which mirror it is to use. The slave
 gives this to piuparts when it runs it. The URLs for Packages and
 Sources files will be generated from this setting, too. Default
 (for fetching Packages/Sources): "http://cdn.debian.net/debian".

* "distro" is the distribution the slave should tell piuparts to
 use for basic install/purge testing. It is also possible to use a
 "partial" distribution as defined in distros.conf. No default.
 If 'upgrade-test-distros' is set, this selects the distribution
 that will be used for getting the packages to be tested. Defaults
 to the last entry in 'upgrade-test-distros', but other useful
 settings are the first entry (to test upgrades of "disappearing"
 packages) or the restricted set in a partial distribution (e.g.
 stable to backports to testing).

* "area" is the archive area to use, set to one of main, contrib,
 non-free. Default: "main".

* "arch" is the architecture to use. Default: dpkg
 --print-architecture.

* "chroot-tgz" is the name of the file the slave should use for
 the tarball containing the base chroot. The default name is
 generated automatically from the "distro" or "upgrade-test-distros"
 setting. If the tarball doesn't exist, the slave creates it.

* "basetgz-directory" is the directory where "chroot-tgz" (or the
 automatically selected default name) is located. The default is
 '.'.

* "upgrade-test-distros" is the space delimited list of
 distributions the slave should use for testing upgrades
 between distributions (i.e., Debian versions). Using "partial"
 distributions as defined in distros.conf is possible. Currently,
 "squeeze wheezy sid" is a good choice.
 Setting this switches from doing install/purge tests to
 dist-upgrade tests. Not set by default.

* "max-reserved" is the maximum number of packages the slave will
 reserve at once. It should be large enough that the host that
 runs master is not unduly stressed by frequent ssh logins and
 running master (both of which take quite a bit of CPU cycles),
 yet at the same time it should not be so large that one slave
 grabs so many packages all other slaves just sit idle. The number
 obviously depends on the speed of the slave. A good value seems
 to be enough to let the slave test packages for about an hour
 before reporting results and reserving more. For a contemporary
 AMD64 machine with a reasonably fast disk subsystem the value 50
 seems to work fine. To disable a section set this to 0.

* "keep-sources-list" controls whether the slave runs piuparts
 with the '--keep-sources-list' option.  This option does not
 apply to upgrade tests.  The value should be "yes" or "no", with
 the default being "no".  Use this option for dists that you need
 a custom sources.list for, such as "stable-proposed-updates".

* "precedence" controls the order the sections are being processed
 by the slave. Sections with a larger precedence value will be run
 only if all sections with a smaller precedence value are idle,
 i.e. master does not have any packages that this slave could
 test. Sections with the same precedence value will be processed
 round-robin until they are all idle (or a more important section
 has packages to be tested). The default is 1.

* "depends-sections" lists additional sections that will be
 searched for dependencies that are not available in the current
 section if that describes a partial distro.

* "debug" tells the slave whether to log debug level messages. The
 value should be "yes" or "no", with the default being "no".
 piuparts itself currently always produces debug output and there
 is no way to disable that.

* "PYTHONPATH" (global) sets the search path to the piupartslib
 python modules if they are not installed in their default location
 in /usr.

* "reschedule-untestable-days" (global) sets the rescheduling
 delay for untestable packages (e.g. due to unsatisfied
 dependencies). This is handled by the 'report_untestable_packages'
 script and the default is "7" days.

* "reschedule-old-days" (global, section) and the following five
 settings define the rescheduling scheme that it performed by the
 'reschedule_oldest_logs' script. Passed/failed logs that are
 older than reschedule-(old|fail)-days will be marked for
 rechecking (limited to reschedule-(old|fail)-count). Only packages
 that are actually testable will be reissued by piuparts-master (and
 the "old" log will be deleted at that time).  Logs that are marked
 for recycling but have not been rechecked due to missing/failing
 dependecies will be deleted anyway if they are older than
 expire-(old|fail)-days.

* "reschedule-old-count" (global, section) is the maximum number of
 passed logs that will be marked for recycling. Set to 0 to disable
 rescheduling passed logs.

* "expire-old-days" (global, section) can be set to a value larger
 than 'reschedule-old-days' to delete logs older than the setting
 that are marked for recycling but haven't been rechecked due to
 failing or missing dependecies. Disabled by default ("0").

* "reschedule-fail-days" (global, section) sets the minimum age of
 failing logs (fail/*.log or affected/*.log) before they will be
 rechecked.

* "reschedule-fail-count" (global, section) is the maximum number
 of failed logs that will be marked for recycling. Set to 0 to
 disable rescheduling failed logs.

* "expire-fail-days" (global, section) can be set to a value larger
 than 'reschedule-fail-days' to delete logs older than the setting
 that are marked for recycling but haven't been rechecked due to
 failing or missing dependecies. Disabled by default ("0").

* "auto-reschedule" (section) can be set to "no" to disable
 rescheduling of passed and failed packages. To disable only
 rescheduling one of passed or failed logs, set the corresponding
 -count variable to zero.

Some of the configuration items are not required, but it is best
to set them all to be sure what the configuration actually is.

==== piuparts.debian.org specific configuration

In addition to some of the above settings the following
configuration settings are used by the scripts in '~piuparts?/bin/'
used to run piuparts.debian.org. They are all optional, default
values are set in the scripts.

* "urlbase" (global) is the base url of the webserver serving this
 piuparts instance. Used to provide links to logfiles in email
 reports.


=== Running piuparts in master-slave mode, piuparts-report and the setup on piuparts.debian.org

If you want to run piuparts-report (which is only+very useful if
you run piuparts in master-slave mode), you need to 'apt-get
install python-rpy r-recommended r-base-dev'. For more
information see
link:http://anonscm.debian.org/gitweb/?p=piuparts/piuparts.git;hb=piatti;a=blob;f=README_piatti.txt[http://anonscm.debian.org/gitweb/?p=piuparts/piuparts.git;hb=piatti;a=blob;f=README_piatti.txt].

// vim: set filetype=asciidoc:
