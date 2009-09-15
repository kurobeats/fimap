import os.path
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

from tempfile import mkstemp
from ftplib import FTP
from config import settings
import xml.dom.minidom

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$30.08.2009 20:02:04$"

import urllib2
import string,random,os,socket

class baseClass (object):

    globSet     = None
    XML_Result  = None
    XML_RootItem = None

    def __init__(self, globSet):
        self.globSet = globSet
        self.logFilePath = None
        self.__init_logfile()
        self.__logfile
        self._load()
        self.xmlfile = os.path.join(os.environ.get('HOME'), "fimap_result.xml")
        self.XML_Result = None
        if (self.XML_Result == None):
            self.XML_RootItem = None
            self.__init_xmlresult()

    def __init_xmlresult(self):
        xmlfile = self.xmlfile
        if (os.path.exists(xmlfile)):
            self.XML_Result = xml.dom.minidom.parse(xmlfile)
            self.XML_RootItem = self.XML_Result.firstChild
        else:
            self.XML_Result = xml.dom.minidom.Document()
            self.XML_RootItem = self.XML_Result.createElement("fimap")
            self.XML_Result.appendChild(self.XML_RootItem)

    def _createXMLElement(self, Key):
        elem = self.XML_Result.createElement(Key)
        return(elem)

    def _setAttrib(self, Node, Key, Value):
        Node.setAttribute(Key, Value)


    def _appendXMLChild(self, Parent, Child):
        Parent.appendChild(Child)

    def _getXML(self):
        return(self.XML_Result.toprettyxml(indent="  "))

    def _load(self):
        raise "Implement this!"

    def _log(self, txt, LVL):
        self.globSet._log(txt, LVL)
        

    def globalSettings(self):
        return(self.globSet)


    def getRandomStr(self):
        chars = string.letters + string.digits
        ret = ""
        for i in range(8):
            if (i==0):
                ret = ret + random.choice(string.letters)
            else:
                ret = ret + random.choice(chars)
        return ret

    def doGetRequest(self, URL, TimeOut=10):
        try:
            try:
                opener = urllib2.build_opener()
                opener.addheaders = [('User-agent', self.globalSettings().getUserAgent())]
                f = opener.open(URL, timeout=TimeOut) # TIMEOUT
                return(f.read())
            except TypeError, err:
                try:
                    # Python 2.5 compatiblity
                    socket.setdefaulttimeout(TimeOut)
                    f = opener.open(URL)
                    return(f.read())
                except Exception, err:
                    raise
            except:
                raise

        except Exception, err:
            self._log("Failed to do request to (%s)" %(URL), self.globSet.LOG_WARN)
            self._log(err, self.globSet.LOG_WARN)
            return(None)

    def doPostRequest(self, url, Post, TimeOut=10):
        self._log("POST Request: %s" %Post , self.globSet.LOG_DEVEL)
        try:
            opener = urllib2.build_opener()
            header = {'User-agent': self.globalSettings().getUserAgent()}
            req = urllib2.Request(url, Post, header)
            response = urllib2.urlopen(req)
            return(response.read())
        except Exception, err:
            self._log("Failed to do request to (%s)" %(url), self.globSet.LOG_WARN)
            self._log(err, self.globSet.LOG_WARN)
            return(None)

    def __init_logfile(self):
        self.logFilePath = os.path.join(os.environ.get('HOME'), "fimap.log")
        self.__logfile = open(self.logFilePath, "a")

    def _writeToLog(self, txt):
        self.__logfile.write("%s\n" %(txt))

    def drawBox(self, header, textarray):
        maxLen = self.__getLongestLine(textarray, header) + 5
        headspacelen = (maxLen/2 - len(header)/2)
        print "#"* (maxLen+1)
        self.__printBoxLine(header, maxLen)
        print "#"* (maxLen+1)
        
        for ln in textarray:
            self.__printBoxLine(ln, maxLen)

        print "#"* (maxLen+1)

    def __printBoxLine(self, txt, maxlen):
        suffix = " " * (maxlen - len(txt)-1)
        print "#" + txt + suffix + "#"

    def __getLongestLine(self, textarray, header):
        maxLen = len(header)
        for ln in textarray:
            if (len(ln) > maxLen):
                maxLen = len(ln)
        return(maxLen)


    def addXMLLog(self, rep, t, f):
        if (not self.existsXMLEntry(rep.getDomain(), f, rep.getPath())):
            elem = self.findDomainNode(rep.getDomain())
            elem_vuln = self._createXMLElement("vuln")
            self._setAttrib(elem_vuln, "file", f)
            self._setAttrib(elem_vuln, "prefix", rep.getPrefix())
            self._setAttrib(elem_vuln, "suffix", rep.getSurfix())
            self._setAttrib(elem_vuln, "appendix", rep.getAppendix())
            self._setAttrib(elem_vuln, "suffix", rep.getSurfix())
            self._setAttrib(elem_vuln, "mode", t)
            self._setAttrib(elem_vuln, "path", rep.getPath())
            self._setAttrib(elem_vuln, "param", rep.getVulnKey())
            self._setAttrib(elem_vuln, "paramvalue", rep.getVulnKeyVal())
            if (rep.isRemoteInjectable()):
                self._setAttrib(elem_vuln, "remote", "1")
            else:
                self._setAttrib(elem_vuln, "remote", "0")
            self._appendXMLChild(elem, elem_vuln)
            self._appendXMLChild(self.XML_RootItem, elem)
            

    def findDomainNode(self, domain):
        elem = None
        for c in self.XML_RootItem.childNodes:
            if (c.nodeName != "#text"):
                c.getAttribute("hostname")
                if (c.getAttribute("hostname") == domain):
                    return(c)

        elem      = self._createXMLElement("URL")
        self._setAttrib(elem, "hostname", domain)
        return elem

    def getDomainNodes(self):
        ret = self.XML_RootItem.getElementsByTagName("URL")
        return(ret)

    def getNodesOfDomain(self, Domain):
        ret = []
        elem = self.findDomainNode(Domain)
        return(elem.getElementsByTagName("vuln"))

    def existsXMLEntry(self, domain, file, path):
        elem = self.findDomainNode(domain)
        for c in elem.childNodes:
            if (c.nodeName != "#text"):
                f = c.getAttribute("file")
                p = c.getAttribute("path")
                if (f == file and p == path):
                    return(True)

    def saveXML(self):
        self._log("Saving results to '%s'..."%self.xmlfile, self.globSet.LOG_DEBUG)
        f = open(self.xmlfile, "w")
        f.write(self.cleanUpLines(self._getXML()))
        f.close()

    def cleanUpLines(self, xml):
        ret = ""
        for ln in xml.split("\n"):
            if (ln.strip() != ""):
                ret = ret + ln + "\n"
        return(ret)

    def FTPuploadFile(self, content, suffix):
        host = settings["dynamic_rfi"]["ftp"]["ftp_host"]
        user = settings["dynamic_rfi"]["ftp"]["ftp_user"]
        pw   = settings["dynamic_rfi"]["ftp"]["ftp_pass"]
        path = settings["dynamic_rfi"]["ftp"]["ftp_path"]
        http = settings["dynamic_rfi"]["ftp"]["http_map"]
        temp = mkstemp()[1]

        f = open(temp, "w")
        f.write(content)
        f.close()
        f = open(temp, "r")
        self._log("Uploading payload to FTP server '%s'..."%(host), self.globSet.LOG_DEBUG)
        ftp = FTP(host, user, pw)
        
        ftp.cwd(os.path.dirname(path))
        ftp.storlines("STOR " + os.path.basename(path) + suffix, f)
        ftp.quit()
        ret = {}
        ret["http"] = http + suffix
        ret["ftp"] = path + suffix
        f.close()
        return(ret)

    def FTPdeleteFile(self, file):
        host = settings["dynamic_rfi"]["ftp"]["ftp_host"]
        user = settings["dynamic_rfi"]["ftp"]["ftp_user"]
        pw   = settings["dynamic_rfi"]["ftp"]["ftp_pass"]
        self._log("Deleting payload from FTP server '%s'..."%(host), self.globSet.LOG_DEBUG)
        ftp = FTP(host, user, pw)
        ftp.delete(file)
        ftp.quit()

    def relpath(self, path, start=os.curdir, sep="/"):
        # Relpath implementation directly ripped and modified from Python 2.6 source.
        if not path:
            raise ValueError("no path specified")
        start_list = os.path.abspath(start).split(sep)
        path_list = os.path.abspath(path).split(sep)
        # Work out how much of the filepath is shared by start and path.
        i = len(self.commonprefix([start_list, path_list]))
        rel_list = [".."] * (len(start_list)-i) + path_list[i:]
        if not rel_list:
            return os.curdir
        return os.path.join(*rel_list)



    def commonprefix(self, m):
        "Given a list of pathnames, returns the longest common leading component"
        # Ripped from Python 2.6 source.
        if not m: return ''
        s1 = min(m)
        s2 = max(m)
        for i, c in enumerate(s1):
            if c != s2[i]:
                return s1[:i]
        return s1