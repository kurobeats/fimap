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
from ftplib import error_perm
from config import settings
import xml.dom.minidom
import shutil
import posixpath
import os.path

DEFAULT_AGENT = "fimap.googlecode.com"
SOCKETTIMEOUT = 30


import urllib, httplib, copy, urllib2
import string,random,os,socket, os.path

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$30.08.2009 20:02:04$"

import urllib2
import string,random,os,socket

new_stuff = {}

class baseClass (object):

    globSet     = None
    XML_Result  = None
    XML_RootItem = None
    homeDir = os.path.expanduser("~")

    def __init__(self, globSet):
        self.globSet = globSet
        self.logFilePath = None
        self.__init_logfile()
        self.__logfile
        self._load()

        self.xmlfile = os.path.join(self.homeDir, "fimap_result.xml")
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

    def __init_logfile(self):
        self.logFilePath = os.path.join(self.homeDir, "fimap.log")
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
            self._setAttrib(elem_vuln, "mode", t)
            self._setAttrib(elem_vuln, "path", rep.getPath())
            self._setAttrib(elem_vuln, "param", rep.getVulnKey())
            self._setAttrib(elem_vuln, "paramvalue", rep.getVulnKeyVal())
            
            if (rep.isRemoteInjectable()):
                self._setAttrib(elem_vuln, "remote", "1")
            else:
                self._setAttrib(elem_vuln, "remote", "0")

            if (rep.isBlindDiscovered()):
                self._setAttrib(elem_vuln, "blind", "1")
            else:
                self._setAttrib(elem_vuln, "blind", "0")
                
            self._appendXMLChild(elem, elem_vuln)
            self._appendXMLChild(self.XML_RootItem, elem)

            if (t.find("x") != -1 or t.find("R") != -1):
                try:
                    new_stuff[rep.getDomain()] += 1
                except:
                    new_stuff[rep.getDomain()] = 1
            

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
        path = os.path.dirname(settings["dynamic_rfi"]["ftp"]["ftp_path"])
        file_= os.path.basename(settings["dynamic_rfi"]["ftp"]["ftp_path"])
        http = settings["dynamic_rfi"]["ftp"]["http_map"]
        temp = mkstemp()[1]
        hasCreatedDirStruct = False
        
        # Default case return values:
        rethttp = http+ suffix
        retftp  = os.path.join(path, file_) + suffix

        directory = None
        # Check if the file needs to be in a directory.
        if (suffix.find("/") != -1):
            http = os.path.dirname(http)
            # Yep it has to be in a directory...
            tmp = self.removeEmptyObjects(suffix.split("/"))
            if suffix.startswith("/"):
                # Directory starts immediatly
                directory = os.path.join(file_, tmp[0]) # Concat the first directory to our path 
                for d in tmp[1:-1]:                     # Join all directorys excluding first and last token.
                    directory = os.path.join(directory, d)
                suffix = suffix[1:]                     # Remove the leading / from the suffix.
                file_ = tmp[-1]                         # The actual file is the last token.
                rethttp = settings["dynamic_rfi"]["ftp"]["http_map"] # Return http path
                retftp  = settings["dynamic_rfi"]["ftp"]["ftp_path"] # and ftp file path.
                hasCreatedDirStruct = True              # Say fimap that he should delete the directory after payloading.
            else:
                # File has a suffix + directory...
                subsuffix = suffix[:suffix.find("/")]   # Get the attachment of the file.
                directory = file_ + subsuffix           # Concat the attachment to the user defined filename.
                for d in tmp[1:-1]:                     # Concat all directorys excluding first and last token.
                    directory = os.path.join(directory, d)
                suffix = suffix[suffix.find("/")+1:]    # Get rest of the path excluding the file attachment.
                file_ = tmp[-1]                         # Get the actual filename.
                rethttp = settings["dynamic_rfi"]["ftp"]["http_map"]
                retftp  = settings["dynamic_rfi"]["ftp"]["ftp_path"] + subsuffix
                hasCreatedDirStruct = True
            
        else:
            file_ = file_ + suffix
        
        # Write payload to local drive
        f = open(temp, "w")
        f.write(content)
        f.close()
        f = open(temp, "r")

        # Now toss it to your ftp server
        self._log("Uploading payload (%s) to FTP server '%s'..."%(temp, host), self.globSet.LOG_DEBUG)
        ftp = FTP(host, user, pw)
        ftp.cwd(path)
        
        # If the path is in a extra directory, we will take care of it now
        if (directory != None):
            self._log("Creating directory structure '%s'..."%(directory), self.globSet.LOG_DEBUG)
            for dir_ in directory.split("/"):
                try:
                    ftp.cwd(dir_)
                except error_perm:
                    self._log("mkdir '%s'..."%(dir_), self.globSet.LOG_DEVEL)
                    ftp.mkd(dir_)
                    ftp.cwd(dir_)
                

        ftp.storlines("STOR " + file_, f)
        ftp.quit()
        ret = {}
        ret["http"] = rethttp
        ret["ftp"] =  retftp
        ret["dirstruct"] = hasCreatedDirStruct
        f.close()
        return(ret)

    def FTPdeleteFile(self, file):
        host = settings["dynamic_rfi"]["ftp"]["ftp_host"]
        user = settings["dynamic_rfi"]["ftp"]["ftp_user"]
        pw   = settings["dynamic_rfi"]["ftp"]["ftp_pass"]
        self._log("Deleting payload (%s) from FTP server '%s'..."%(file, host), self.globSet.LOG_DEBUG)
        ftp = FTP(host, user, pw)
        ftp.delete(file)
        ftp.quit()

    def FTPdeleteDirectory(self, directory, ftp = None):
        host = settings["dynamic_rfi"]["ftp"]["ftp_host"]
        user = settings["dynamic_rfi"]["ftp"]["ftp_user"]
        pw   = settings["dynamic_rfi"]["ftp"]["ftp_pass"]
        if ftp == None: 
            self._log("Deleting directory recursivly from FTP server '%s'..."%(host), self.globSet.LOG_DEBUG)
            ftp = FTP(host, user, pw)
        
        ftp.cwd(directory)
        for i in ftp.nlst(directory):
            try:
                ftp.delete(i)
            except:
                self.FTPdeleteDirectory(i, ftp)
            
        ftp.cwd(directory)
        ftp.rmd(directory)


    def putLocalPayload(self, content, append):
        fl = settings["dynamic_rfi"]["local"]["local_path"] + append
        dirname = os.path.dirname(fl)
        if (not os.path.exists(dirname)):
            os.makedirs(dirname)
        up = {}
        
        up["local"] = settings["dynamic_rfi"]["local"]["local_path"]
        if append.find("/") != -1 and (not append.startswith("/")):
            up["local"] = settings["dynamic_rfi"]["local"]["local_path"] + append[:append.find("/")]
        up["http"] = settings["dynamic_rfi"]["local"]["http_map"]
        f = open(fl, "w")
        f.write(content)
        f.close()
        
        return(up)

    def deleteLocalPayload(self, directory):
        if(os.path.exists(directory)):
            if (os.path.isdir(directory)):
                shutil.rmtree(directory)
            else:
                os.remove(directory)
                

    def removeEmptyObjects(self, array, empty = ""):
        ret = []
        for a in array:
            if a != empty:
                ret.append(a)
        return(ret)

    def relpath(self, path, start=os.curdir, sep="/"):
        # Relpath implementation directly ripped and modified from Python 2.6 source.
        if not path:
            raise ValueError("no path specified")
        start_list = posixpath.abspath(start).split(sep)
        path_list = posixpath.abspath(path).split(sep)
        # Work out how much of the filepath is shared by start and path.
        i = len(self.commonprefix([start_list, path_list]))
        rel_list = [".."] * (len(start_list)-i) + path_list[i:]
        if not rel_list:
            return os.curdir
        return posixpath.join(*rel_list)



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

    def getPHPQuiz(self):
        rnd = self.getRandomStr()
        phpcode = "echo "
        for c in rnd:
            phpcode += "chr(%d)."%(ord(c))

        phpcode = phpcode[:-1] + ";"
        return(phpcode, rnd)


    def doGetRequest(self, URL, TimeOut=10, additionalHeaders=None):
        #self._log("GET Request: '%s'..."%(URL), self.globSet.LOG_DEBUG)
        self._log("TTL: %d"%TimeOut, self.globSet.LOG_DEVEL)
        result, headers = self.doRequest(URL, self.globalSettings().getUserAgent(), additionalHeaders=additionalHeaders)
        self._log("RESULT-HEADER: %s"%headers, self.globSet.LOG_DEVEL)
        self._log("RESULT-HTML: %s"%result, self.globSet.LOG_DEVEL)
        return result

    def doPostRequest(self, URL, Post, TimeOut=10, additionalHeaders=None):
        #self._log("POST Request: '%s' ['%s']..."%(URL, Post), self.globSet.LOG_DEBUG)
        self._log("TTL: %d"%TimeOut, self.globSet.LOG_DEVEL)
        result, headers = self.doRequest(URL, self.globalSettings().getUserAgent(), Post, additionalHeaders)
        self._log("RESULT-HEADER: %s"%headers, self.globSet.LOG_DEVEL)
        self._log("RESULT-HTML: %s"%result, self.globSet.LOG_DEVEL)
        return result

    def doGetRequestWithHeaders(self, URL, agent = None, additionalHeaders = None):
        #self._log("GET+HEADER Request: '%s'..."%(URL), self.globSet.LOG_DEBUG)
        self._log("TTL: %d"%TimeOut, self.globSet.LOG_DEVEL)
        result, headers = self.doRequest(URL, self.globalSettings().getUserAgent(), additionalHeaders=additionalHeaders)
        self._log("RESULT-HEADER: %s"%headers, self.globSet.LOG_DEVEL)
        self._log("RESULT-HTML: %s"%result, self.globSet.LOG_DEVEL)
        return result


    def doRequest(self, URL, agent = None, postData = None, additionalHeaders = None):
        result = None
        headers = None

        try:
            b = Browser(agent or DEFAULT_AGENT)

            try:
                if additionalHeaders:
                    b.headers.update(additionalHeaders)

                if postData:
                    result, headers = b.get_page(URL, postData)
                else:
                    result, headers = b.get_page(URL)

            finally:
                del(b)

        except:
            pass

        return result,headers

    #def doGetRequest(self, URL, TimeOut=10):
    #def doPostRequest(self, url, Post, TimeOut=10):

class BrowserError(Exception):
  def __init__(self, url, error):
    self.url = url
    self.error = error

class PoolHTTPConnection(httplib.HTTPConnection):
    def connect(self):
        msg = "getaddrinfo returns an empty list"
        for res in socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                self.sock = socket.socket(af, socktype, proto)
                self.sock.settimeout(SOCKETTIMEOUT)
                self.sock.connect(sa)
            except socket.error, msg:
                if self.sock:
                    self.sock.close()
                self.sock = None
                continue
            break
        if not self.sock:
            raise socket.error, msg

class PoolHTTPHandler(urllib2.HTTPHandler):
    def http_open(self, req):
        return self.do_open(PoolHTTPConnection, req)

class Browser(object):
    def __init__(self, user_agent=DEFAULT_AGENT, use_pool=False):
        self.headers = {'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-us,en;q=0.5'}

    def get_page(self, url, data=None):
        handlers = [PoolHTTPHandler]
        opener = urllib2.build_opener(*handlers)

        ret = None
        headers = None
        response = None

        request = urllib2.Request(url, data, self.headers)
        try:
            try:
                response = opener.open(request)
                ret = response.read()

                info = response.info()
                headers = copy.deepcopy(info.items())

            finally:
                if response:
                    response.close()

        except:
            pass

        return ret, headers

    def set_random_user_agent(self):
        self.headers['User-Agent'] = DEFAULT_AGENT
        return self.headers['User-Agent']

    def doRequest(self, URL, agent=None, postData=None, additionalHeaders=None):
        result = None
        headers = None

        try:
            b = Browser(agent or DEFAULT_AGENT)

            try:
                if additionalHeaders:
                    b.headers.update(additionalHeaders)

                if postData:
                    result, headers = b.get_page(URL, postData)
                else:
                    result, headers = b.get_page(URL)

            finally:
                del(b)

        except:
            pass

        return result, headers


