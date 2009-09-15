#
# This file is part of fimap.
#
# Copyright(c) 2009 Iman Karim(ikarim2s@smail.inf.fh-brs.de).
# http://fimap.googlecode.com
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#



__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$30.08.2009 20:10:00$"

class globalSettings():

    LOG_ERROR = 99
    LOG_WARN  = 99
    LOG_DEVEL = 1
    LOG_DEBUG = 2
    LOG_INFO  = 3
    LOG_ALWAYS= 4

    def __init__(self, LOG_LVL):
        self.log_lvl = {}
        self.log_lvl[self.LOG_ERROR]   = "ERROR"
        self.log_lvl[self.LOG_WARN]    = "WARN"
        self.log_lvl[self.LOG_DEVEL]   = "DEVEL"
        self.log_lvl[self.LOG_DEBUG]   = "DEBUG"
        self.log_lvl[self.LOG_INFO]    = "INFO"
        self.log_lvl[self.LOG_ALWAYS]  = "OUT"
        self.LOG_LVL = LOG_LVL
        self.Target_URL = None
        self.UserAgent = None

    def getLogLevel(self):
        return(self.LOG_LVL)

    def setTargetURL(self, URL):
        self.Target_URL = URL

    def getTargetURL(self):
        return(self.Target_URL)

    def setUserAgent(self, UA):
        if (UA != self.UserAgent):
            self.UserAgent = UA
            self._log("User-Agent changed to '%s'." %UA, self.LOG_DEVEL)

    def getUserAgent(self):
        return(self.UserAgent)

    def _log(self, txt, LVL):
        if (4-self.getLogLevel() < LVL):
            print "[%s] %s" %(self.log_lvl[LVL], txt)
