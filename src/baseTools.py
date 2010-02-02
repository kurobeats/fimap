import urllib, httplib, copy, urllib2
import string,random,os,socket, os.path

class baseTools(object):
    LOG_ERROR = 99
    LOG_WARN  = 99
    LOG_DEVEL = 1
    LOG_DEBUG = 2
    LOG_INFO  = 3
    LOG_ALWAYS= 4
    
    config = None
    log_lvl = None
    
    def getRandomStr(self):
        chars = string.letters + string.digits
        ret = ""
        for i in range(8):
            if (i==0):
                ret = ret + random.choice(string.letters)
            else:
                ret = ret + random.choice(chars)
        return ret
    
    
    def initLog(self, config):
        self.log_lvl = {}
        self.log_lvl[baseTools.LOG_ERROR]   = "ERROR"
        self.log_lvl[baseTools.LOG_WARN]    = "WARN"
        self.log_lvl[baseTools.LOG_DEVEL]   = "DEVEL"
        self.log_lvl[baseTools.LOG_DEBUG]   = "DEBUG"
        self.log_lvl[baseTools.LOG_INFO]    = "INFO"
        self.log_lvl[baseTools.LOG_ALWAYS]  = "OUT"
        self.LOG_LVL = config["p_verbose"]
        self.config = config
        
    def _log(self, txt, LVL):
        if (4-self.config["p_verbose"] < LVL):
            print "[%s] %s" %(self.log_lvl[LVL], txt)
    
    
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