#
# This file is part of fimap.
#
# Copyright(c) 2009-2010 Iman Karim(ikarim2s@smail.inf.fh-brs.de).
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

from baseClass import baseClass
from targetScanner import targetScanner
import sys

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$03.09.2009 01:29:37$"

class singleScan(baseClass):

    def _load(self):
        self.URL = None
        self.quite = False

    def setURL(self, URL):
        self.URL = URL

    def setQuite(self, b):
        self.quite = b

    def scan(self):
        try:
            self.localLog("SingleScan is testing URL: '%s'" %self.URL)
            t = targetScanner(self.config)
            t.MonkeyTechnique = self.config["p_monkeymode"]

            idx = 0
            if (t.prepareTarget(self.URL)):
                res = t.testTargetVuln()
                if (len(res) == 0):
                    self.localLog("Target URL isn't affected by any file inclusion bug :(")
                else:
                    for i in res:
                        report = i[0]
                        files = i[1]
                        idx = idx +1
                        boxarr = []
                        header = "[%d] Possible File Injection"%idx
                        boxarr.append("  [URL]      %s"%report.getURL())
                        if (report.getPostData() != None and report.getPostData() != ""): boxarr.append("  [POST]     %s"%report.getPostData())
                        if (report.isPost):
                            boxarr.append("  [POSTPARM] %s"%report.getVulnKey())
                        else:
                            boxarr.append("  [PARAM]    %s"%report.getVulnKey())
                        if (report.isBlindDiscovered()):
                            boxarr.append("  [PATH]     Not received (Blindmode)")
                        else:
                            boxarr.append("  [PATH]     %s"%report.getServerPath())

                        boxarr.append("  [TYPE]     %s"%report.getType())
                        if (not report.isBlindDiscovered()):
                            if (report.isNullbytePossible() == None):
                                boxarr.append("  [NULLBYTE] No Need. It's clean.")
                            else:
                                if (report.isNullbytePossible()):
                                    boxarr.append("  [NULLBYTE] Works. :)")
                                else:
                                    boxarr.append("  [NULLBYTE] Doesn't work. :(")
                        else:
                            if (report.isNullbytePossible()):
                                boxarr.append("  [NULLBYTE] Is needed.")
                            else:
                                boxarr.append("  [NULLBYTE] Not tested.")
                        boxarr.append("  [READABLE FILES]")
                        if (len(files) == 0):
                            boxarr.append("                   No Readable files found :(")
                        else:
                            fidx = 0
                            for file in files:
                                payload = "%s%s%s"%(report.getPrefix(), file, report.getSurfix())
                                if (file != payload):
                                    txt = "                   [%d] %s -> %s"%(fidx, file, payload)
                                    #if (fidx == 0): txt = txt.strip()
                                    boxarr.append(txt)
                                else:
                                    txt = "                   [%d] %s"%(fidx, file)
                                    #if (fidx == 0): txt = txt.strip()
                                    boxarr.append(txt)
                                fidx = fidx +1
                        self.drawBox(header, boxarr)
        except KeyboardInterrupt:
            raise

    def localLog(self, txt):
        if (not self.quite):
            print txt