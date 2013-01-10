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

CONFIG_FILE = "/etc/piuparts/piuparts.conf"
KPR_DIRS = ( 'pass', 'bugged', 'affected', 'fail' )

KPR_EXT = '.kpr'
BUG_EXT = '.bug'
LOG_EXT = '.log'

class WKE_Config( piupartslib.conf.Config ):
    """Configuration parameters for Well Known Errors"""

    def __init__( self ):
        self.section = 'global'

        piupartslib.conf.Config.__init__( self, self.section,
            {
                "sections": "sid",
                "master-directory": "/var/lib/piuparts/master/",
                "known-problem-directory": "/usr/share/piuparts/known_problems",
            }, "" )

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

def get_where( logpath ):
    """Convert a path to a log file to the 'where' component (e.g. 'pass')"""
    return( logpath.split('/')[-2] )

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

def process_section( section, config, problem_list ):
    """ Update .bug and .kpr files for logs in this section """

    sectiondir = os.path.join( config['master-directory'], section )
    workdirs = [ os.path.join(sectiondir,x) for x in KPR_DIRS ]

    if not os.access( sectiondir, os.F_OK ):
        return

    [os.mkdir(x) for x in workdirs if not os.path.exists(x)]

    (logdict, kprdict, bugdict) = [ get_file_dict(workdirs, x ) \
            for x in [LOG_EXT, KPR_EXT, BUG_EXT] ]

    (kprdict, bugdict) = [get_file_dict(workdirs,x) for x in [KPR_EXT, BUG_EXT]]

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
