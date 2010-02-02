'''
Created on 23.01.2010

@author: Iman Karim (ikarim2s@smail.inf.fh-brs.de)
'''

import xml.dom.minidom
import base64
import sys, os



def getXMLNode(item, nodename):
    for child in item.childNodes:
        if (child.nodeName != "#text"):
            if (child.nodeName == nodename):
                return(child)
    return(None)

def getXMLNodes(item, nodename):
    ret = []
    for child in item.childNodes:
        if (child.nodeName != "#text"):
            if (child.nodeName == nodename):
                ret.append(child)
    return(ret)

def getText(nodelist):
    rc = ""
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc = rc + node.data
    return rc


class XML2Config(object):

    def __init__(self):
        self.langsets = []
        self.xmlfile = os.path.join(sys.path[0], "config", "generic.xml")
        print self.xmlfile
        self.XML_Generic = None
        self.XML_RootItem = None
    
        self.__init_xmlresult()
    
    
        sys.exit(0)
    
    def __init_xmlresult(self):
        xmlfile = self.xmlfile
        if (os.path.exists(xmlfile)):
            self.XML_Generic = xml.dom.minidom.parse(xmlfile)
            self.XML_RootItem = self.XML_Generic.firstChild
            self.loadLanguageSets()
        else:
            print "generic.xml file not found! This file is very important!"
            sys.exit(1)
        
    def loadLanguageSets(self):
        langnodes = getXMLNode(self.XML_RootItem, "languagesets")
        for c in langnodes.childNodes:
            if (c.nodeName == "language"):
                langname = c.getAttribute("name")
                langfile = c.getAttribute("langfile")
                self.langsets.append(baseLanguage(langname, langfile))
    
class baseLanguage():
    
    def __init__(self, langname, langfile):
        langfile = os.path.join(sys.path[0], "config", langfile)
        self.XML_Langfile = None
        self.XML_Rootitem = None
        
        if (os.path.exists(langfile)):
            self.XML_Langfile = xml.dom.minidom.parse(langfile)
            self.XML_Rootitem = self.XML_Langfile.firstChild
        else:
            print "%s file not found!" %(langfile)
            sys.exit(1)
        
        self.LanguageName = langname
        
        self.relative_files = []
        self.absolute_files = []
        self.remote_files   = []
        self.log_files      = []
        
        self.exec_methods   = []
        self.payloads       = []
        
        self.sniper_regex   = None
        
        self.quiz_function  = None
    
        self.__populate()
        
    def getQuiz(self):
        ret = None
        eval(self.quiz_function)
    
    def __populate(self):
        rel_node = getXMLNode(self.XML_Rootitem, "relative_files")
        rel_files = getXMLNodes(rel_node, "file")
        for f in rel_files:
            self.relative_files.append(fiFile(f))
        
        abs_node = getXMLNode(self.XML_Rootitem, "absolute_files")
        abs_files = getXMLNodes(abs_node, "file")
        for f in abs_files:
            self.absolute_files.append(fiFile(f))
        
        rem_node = getXMLNode(self.XML_Rootitem, "remote_files")
        rem_files = getXMLNodes(rem_node, "file")
        for f in rem_files:
            self.remote_files.append(fiFile(f))
        
        log_node = getXMLNode(self.XML_Rootitem, "log_files")
        log_files = getXMLNodes(log_node, "file")
        for f in log_files:
            self.log_files.append(fiFile(f))
        
        exec_methods = getXMLNode(self.XML_Rootitem, "exec_methods")
        exec_nodes = getXMLNodes(exec_methods, "exec")
        for f in exec_nodes:
            self.exec_methods.append(fiExecMethod(f))
            
        payloads = getXMLNode(self.XML_Rootitem, "payloads")
        payload_nodes = getXMLNodes(payloads, "payload")
        for f in payload_nodes:
            self.payloads.append(fiPayload(f))
        
        
        self.sniper_regex = getXMLNode(self.XML_Rootitem, "snipe").getAttribute("regex")
        
        methods_node = getXMLNode(self.XML_Rootitem, "methods")
        quiz_node = getXMLNode(methods_node, "quiz")
        for i in quiz_node.childNodes:
            try:
                print i.data
            except:
                print dir(i)
                print i.nodeValue
        
        
        
        print self.quiz_function
        
class fiPayload:
    def __init__(self, xmlPayload):
        self.name = xmlPayload.getAttribute("name")
        self.doBase64 = (xmlPayload.getAttribute("dobase64") == "1")
        self.inputlist = getXMLNodes(xmlPayload, "input")
        self.source = getXMLNode(xmlPayload, "code").getAttribute("source")
        print "Payload '%s' loaded." %(self.name)
        
    def getName(self):
        return(self.name)
    
    def getSource(self):
        return(self.source)
    
    def generatePayload(self):
        ret = self.source
        for q in self.inputlist:
            type_ = q.getAttribute("type")
            if (type_ == "question"):
                question = q.getAttribute("text")
                placeholder = q.getAttribute("placeholder")
                inp = raw_input(question)
                if (self.doBase64):
                    inp = base64.b64encode(inp)
                ret = self.source.replace(placeholder, inp)
            elif (type_ == "info"):
                info = q.getAttribute("text")
                print info
            elif (type_ == "wait"):
                info = q.getAttribute("text")
                raw_input(info)
        return(ret)
                    

class fiExecMethod:
    def __init__(self, xmlExecMethod):
        self.execname   = xmlExecMethod.getAttribute("name")
        self.execsource = xmlExecMethod.getAttribute("source")
        print "Exec Method '%s' loaded." %(self.execname)
        
    def getSource(self):
        return(self.execsource)
    
    def getName(self):
        return(self.execname)
    
    def generatePayload(self, command, doBase64):
        if (doBase64):
            command = base64.b64encode(command)
        payload = self.getSource().replace("__PAYLOAD__", command)
        return(payload)
        
class fiFile:
    def __init__(self, xmlFile):
        self.filepath = xmlFile.getAttribute("path")
        self.postdata = xmlFile.getAttribute("post")
        self.findstr  = xmlFile.getAttribute("find")
        self.flags    = xmlFile.getAttribute("flags")
        print "fiFile object: %s" %(self.filepath)
        
    def getFilepath(self):
        return(self.filepath)
    
    def getPostData(self):
        return(self.postdata)
    
    def getFindStr(self):
        return(self.findstr)
    
    def getFlags(self):
        return(self.flags)
    
    def containsFlag(self, flag):
        return (flag in self.flags)
    
    def isInjected(self, content):
        return (content.find(findstr) != -1)