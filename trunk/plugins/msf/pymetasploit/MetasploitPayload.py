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
from subprocess import *
import re

class MsfPayloadExecErr(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)



class MsfPayload(object):
	msfObj=None


	def __init__(self,msfObj):
		self.msfObj=msfObj

	def msfLoadPayload(self):
		# we have to execute something like this:
		# msfpayload php/reverse_php  LPORT=8080  LHOST=127.0.0.1 R

		#Error handling
		# Unfortunately msfpayload does not return error messages to the parent
		# process. It send a error string to stdout and ends the execution.

		# ERROR MSGS sent msfpayload to stdout
		# Error generating payload:
		# Invalid payload:
		# Framework Payloads (XYZ total)

		errGenPayloadPattern="^Error generating payload:"
		invalidPayloadPattern="^Invalid payload:"
		msfPayloadHelpPattern="Framework Payloads \(\d{1,} total\)"

	
		msfpayload=['msfpayload']
		msfpayload.append(self.msfObj.getRequestedPayload())
		msfpayload.extend(self.msfObj.getParams())
		msfpayload.append(self.msfObj.getMode())
		process=Popen(msfpayload,stdout=PIPE,stderr=PIPE,stdin=None)
		stdOut, stdErr=process.communicate()

		# We have cached and error from MsfPayload :)
		if re.search(errGenPayloadPattern,stdOut,re.MULTILINE)!=None or \
			re.search(invalidPayloadPattern,stdOut,re.MULTILINE)!=None or \
			re.search(msfPayloadHelpPattern,stdOut,re.MULTILINE)!=None:
			
			raise MsfPayloadExecErr("Error trying to generate payload: "+self.msfObj.getRequestedPayload()+" "+' '.join(self.msfObj.getParams()))

		self.msfObj.setPayload(stdOut)
