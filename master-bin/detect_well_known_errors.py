#!/usr/bin/python

# Copyright 2013 David Steele (dsteele@gmail.com)
#
# This file is part of Piuparts
#
# Piuparts is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# Piuparts is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.

import ConfigParser
import piupartslib
import os
import time
import re
import subprocess
from collections import namedtuple

CONFIG_FILE = "/etc/piuparts/piuparts.conf"
KPR_DIRS = ( 'pass', 'bugged', 'affected', 'fail' )

KPR_EXT = '.kpr'
BUG_EXT = '.bug'
LOG_EXT = '.log'
TPL_EXT = '.tpl'

PROB_TPL = \
"""<table class="righttable"><tr class="titlerow"><td class="titlecell">
$HEADER in $SECTION, sorted by reverse dependency count.
</td></tr><tr class="normalrow"><td class="contentcell2">
$HELPTEXT
<p>The commandline to find these logs is: <pre>
COMMAND='$COMMAND'
</pre></p>
</td></tr><tr class="titlerow"><td class="alerttitlecell">Please file bugs!</td></tr><tr class="normalrow"><td class="contentcell2" colspan="3">
<ul>
$PACKAGE_LIST</ul>
<p>Affected packages in $SECTION: $COUNT</p></td></tr></table>
"""

UNKNOWN_TPL = \
"""<table class="righttable"><tr class="titlerow"><td class="titlecell">
Packages with unknown failures detected in $SECTION, sorted by reverse dependency count.
</td></tr><tr class="normalrow"><td class="contentcell2">
<p>Please investigate and improve detection of known error types!</p>
</td></tr><tr class="titlerow"><td class="alerttitlecell">Please file bugs!</td></tr><tr class="normalrow"><td class="contentcell2" colspan="3">
<ul>
$PACKAGE_LIST
</ul>
<p>Affected packages in $SECTION: $COUNT</p></td></tr></table>
"""

PKG_ERROR_TPL = \
"""<li>$RDEPS - <a href=\"$LOG\">$LOG</a>
    (<a href=\"http://bugs.debian.org/$PACKAGE?dist=unstable\" target=\"_blank\">BTS</a>)
$BUG</li>
"""

class WKE_Config( piupartslib.conf.Config ):
    """Configuration parameters for Well Known Errors"""

    def __init__( self ):
        self.section = 'global'

        piupartslib.conf.Config.__init__( self, self.section,
            {
                "sections": "sid",
                "master-directory": "/var/lib/piuparts/master/",
                "known-problem-directory": "/usr/share/piuparts/known_problems",
                "output-directory": "/var/lib/piuparts/htdocs/",
            }, "" )

class WKE_Section_Config( piupartslib.conf.Config ):

    def __init__( self, section ):
        self.section = section

        piupartslib.conf.Config.__init__( self, self.section,
            {
                "distro": None,
                "upgrade-test-distros": None,
                "mirror": None,
                "area": None,
                "arch": None,
            }, "",  defaults_section="global" )

class Problem():
    """ Encapsulate a particular known problem """

    def __init__(self, probpath):
        """probpath is the path to the problem definition file"""

        self.probpath = probpath
        self.name = os.path.basename(probpath)
        self.short_name = os.path.splitext( self.name )[0]

        self.init_problem()

    def init_problem(self):
        """Load problem file parameters (HELPTEXT="foo" -> self.HELPTEXT)"""

        pb = open( self.probpath, 'r' )
        probbody = pb.read()
        pb.close()

        tagged = re.sub( "^([A-Z]+=)", "<hdr>\g<0>", probbody, 0, re.MULTILINE)

        for chub in re.split( '<hdr>', tagged )[1:]:

            (name,value) = re.split( "=", chub, 1, re.MULTILINE )

            while value[-1] == '\n':
                value = value[:-1]

            if  re.search( "^\'.+\'$", value, re.MULTILINE|re.DOTALL ) \
             or re.search( '^\".+\"$', value, re.MULTILINE|re.DOTALL ):
                value = value[1:-1]

            self.__dict__[name] = value

        self.WHERE = self.WHERE.split(" ")


class FailureManager():
    """Class to track known failures encountered, by package,
       where (e.g. 'fail'), and known problem type"""

    def __init__(self, logdict):
        """logdict is {pkgspec: fulllogpath} across all log files"""

        self.logdict = logdict
        self.failures = []

        self.load_failures()

    def load_failures(self):
        """Collect failures across all kpr files, as named tuples"""

        for pkgspec in self.logdict:
            logpath = self.logdict[pkgspec]
            try:
                kp = open( get_kpr_path(logpath), 'r' )

                for line in kp.readlines():
                    (where, problem) = self.parse_kpr_line( line )

                    self.failures.append( make_failure(where, problem, pkgspec) )

                kp.close()
            except IOError:
                print "Error processing %s" % get_kpr_path(logpath)

    def parse_kpr_line( self, line ):
        """Parse a line in a kpr file into where (e.g. 'pass') and problem name"""

        m = re.search( "^([a-z]+)/.+ (.+)$", line )
        return( m.group(1), m.group(2) )

    def sort_by_path( self ):
        self.failures.sort(key=lambda x: self.logdict[x.pkgspec])

    def sort_by_rdeps( self, pkgsdb ):
        self.pkgsdb = pkgsdb

        def keyfunc( x, pkgsdb=self.pkgsdb, logdict=self.logdict):
            try:
                rdeps = pkgsdb.get_package(x.pkgspec.split('_')[0]).rrdep_count()
            except KeyError:
                rdeps = 0

            return( (-rdeps, logdict[x.pkgspec]) )

        self.failures.sort( key=keyfunc )

    def filtered( self, problem ):
        return([x for x in self.failures if problem==x.problem])

def make_failure( where, problem, pkgspec ):
    return(namedtuple('Failure', 'where problem pkgspec')(where, problem, pkgspec))

def get_where( logpath ):
    """Convert a path to a log file to the 'where' component (e.g. 'pass')"""
    return( logpath.split('/')[-2] )

def get_kpr_path( logpath ):
    """Return the kpr file path for a particular log path"""
    return( logpath[:-4] + KPR_EXT )

def get_file_dict( workdirs, ext ):
    """For files in [workdirs] with extension 'ext', create a dict of
       <pkgname>_<version>: <path>"""

    filedict = {}

    for dir in workdirs:
        for fl in os.listdir(dir):
            if os.path.splitext(fl)[1] == ext:
                filedict[os.path.splitext(os.path.basename(fl))[0]] \
                    = os.path.join(dir,fl)

    return filedict

def get_pkgspec( logpath ):
    """For a log full file spec, return the pkgspec (<pkg>_<version)"""
    return( logpath.split('/')[-1] )

def replace_ext( fpath, newext ):
    basename = os.path.splitext( os.path.split(fpath)[1] )[0]
    return('/'.join( fpath.split('/')[:-1] + [basename + newext] ))

def get_bug_text(logpath):
    bugpath = replace_ext(logpath, BUG_EXT)

    txt = ""
    if os.path.exists(bugpath):
        bf = open( bugpath, 'r' )
        txt = bf.read()
        bf.close()

    return txt

def section_path( logpath ):
    """Convert a full log path name to one relative to the section directory"""
    return( '/'.join( [get_where(logpath), get_pkgspec(logpath)] ) )

def populate_tpl( tmpl, vals ):

    for key in vals:
        tmpl = re.sub( "\$%s" % key, str(vals[key]), tmpl )

    return tmpl

def update_tpl( basedir, section, problem, failures, logdict, ftpl, ptpl, pkgsdb ):

    pkg_text = ""
    for failure in failures:

            pkg_text += populate_tpl(ftpl, {
                                'LOG': section_path(logdict[failure.pkgspec]),
                                'PACKAGE': failure.pkgspec.split('_')[0],
                                'BUG': get_bug_text(logdict[failure.pkgspec]),
                                'RDEPS': pkgsdb.get_package(failure.pkgspec.split('_')[0]).rrdep_count()
                                   } )

    if len(pkg_text):
        pf = open(os.path.join(basedir, failures[0].problem[:-5] + TPL_EXT),'w')
        tpl_text = populate_tpl( ptpl, {
                                'HEADER': problem.HEADER,
                                'SECTION': section,
                                'HELPTEXT': problem.HELPTEXT,
                                'COMMAND': problem.COMMAND,
                                'PACKAGE_LIST': pkg_text,
                                'COUNT': len(failures),
                                } )

        pf.write( tpl_text )
        pf.close()

def update_html( section, logdict, problem_list, failures, config, pkgsdb ):

    html_dir = os.path.join( config['output-directory'], section )
    if not os.path.exists( html_dir ):
        os.mkdir( html_dir )

    for problem in problem_list:
        update_tpl( html_dir, section, problem,
                    failures.filtered(problem.name),
                    logdict,
                    PKG_ERROR_TPL, PROB_TPL, pkgsdb )

    # Make a failure list of all failed packages that don't show up as known
    failedpkgs = set([x for x in logdict.keys()
                     if get_where(logdict[x]) != 'pass'])
    knownfailpkgs = set([failure.pkgspec for failure in failures.failures])
    unknownsasfailures = [make_failure("","unknown_failures.conf",x)
                         for x in failedpkgs.difference(knownfailpkgs)]

    def keyfunc( x, pkgsdb=pkgsdb, logdict=logdict):
        try:
            rdeps = pkgsdb.get_package(x.pkgspec.split('_')[0]).rrdep_count()
        except KeyError:
            rdeps = 0

        return( (-rdeps, logdict[x.pkgspec]) )

    unknownsasfailures.sort( key=keyfunc )

    update_tpl( html_dir, section, problem_list[0], unknownsasfailures,
                logdict,
                PKG_ERROR_TPL, UNKNOWN_TPL, pkgsdb )

def process_section( section, config, problem_list, pkgsdb=None ):
    """ Update .bug and .kpr files for logs in this section """

    sectiondir = os.path.join( config['master-directory'], section )
    workdirs = [ os.path.join(sectiondir,x) for x in KPR_DIRS ]

    if not os.access( sectiondir, os.F_OK ):
        return

    [os.mkdir(x) for x in workdirs if not os.path.exists(x)]

    (logdict, kprdict, bugdict) = [ get_file_dict(workdirs, x ) \
            for x in [LOG_EXT, KPR_EXT, BUG_EXT] ]

    (kprdict, bugdict) = [get_file_dict(workdirs,x) for x in [KPR_EXT, BUG_EXT]]

    if not pkgsdb:
        oldcwd = os.getcwd()
        os.chdir(config['master-directory'])

        section_config = WKE_Section_Config( section )
        section_config.read( CONFIG_FILE )

        pkgsdb = piupartslib.packagesdb.PackagesDB(prefix=section)

        pkgs_url = section_config.get_packages_url()
        pkg_fl = piupartslib.open_packages_url(pkgs_url)
        pkgsdb.read_packages_file(pkg_fl)
        pkg_fl.close()

        pkgsdb.calc_rrdep_counts()

        os.chdir(oldcwd)

    failures = FailureManager( logdict )
    failures.sort_by_rdeps(pkgsdb)

    update_html( section, logdict, problem_list, failures, config, pkgsdb )

def detect_well_known_errors( config, problem_list ):

    for section in config['sections'].split(" "):
        print time.strftime( "%a %b %2d %H:%M:%S %Z %Y", time.localtime() )
        print "%s:" % section

        process_section( section, config, problem_list )

    print time.strftime( "%a %b %2d %H:%M:%S %Z %Y", time.localtime() )

def create_problem_list( pdir ):

    pfiles = [x for x in sorted(os.listdir(pdir)) if x.endswith(".conf")]
    plist = [Problem(os.path.join(pdir,x)) for x in pfiles]

    return plist

if __name__ == '__main__':

    conf = WKE_Config()
    conf.read( CONFIG_FILE )

    problem_list = create_problem_list( conf['known-problem-directory'] )

    detect_well_known_errors( conf, problem_list )
