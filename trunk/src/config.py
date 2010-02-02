#
# This file is part of fimap.
#
# Copyright(c) 2009-2010 Iman Karim(ikarim2s@smail.inf.fh-brs.de).
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

import language

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$01.09.2009 13:56:47$"

settings = {}

settings["dynamic_rfi"] = {}

settings["dynamic_rfi"]["mode"] = "off" # Set to "ftp" or "local" to use Dynamic_RFI. Set it to "off" to disable it and rely on settings["filesrmt"] files.

###############
#!!!# WARNING #
###################################################################################################
# If you use dynamic_rfi make sure that NO file will be interpreted in the directory you define!  #
# Else code (which should be interpreted on the victim server) will be executed on YOUR machine.  #
# If you don't understand what I say then DON'T USE dynamic_rfi!                                  #
###################################################################################################

# FTP Mode
settings["dynamic_rfi"]["ftp"] = {}
settings["dynamic_rfi"]["ftp"]["ftp_host"] = None
settings["dynamic_rfi"]["ftp"]["ftp_user"] = None
settings["dynamic_rfi"]["ftp"]["ftp_pass"] = None
settings["dynamic_rfi"]["ftp"]["ftp_path"] = None # A non existing file without suffix. Example: /home/imax/public_html/payload
settings["dynamic_rfi"]["ftp"]["http_map"] = None # The mapped HTTP path of the file. Example: http://localhost/~imax/payload
                                                  # For best results make sure that no file in this directory will be interpreted!

# Local Mode
settings["dynamic_rfi"]["local"] = {}
settings["dynamic_rfi"]["local"]["local_path"] = None   # A non existing file on your filesystem without prefix which is reachable by http. Example: /var/www/payload
settings["dynamic_rfi"]["local"]["http_map"]   = None   # The http url of the file without prefix where the file is reachable from the web. Example: http://localhost/payload
                                                        # Note that localhost will only work if you are testing local sites. You should define your internet ip - but i believe
                                                        # if you are using this tool you already know it ;)


# Blindmode settings. Only used if you enable blind scanning.
settings["blind"] = {}
settings["blind"]["minlevel"] = 0             # How many ../ are the minimum count to test?
settings["blind"]["maxlevel"] = 15            # How many ../ are the maximum count to test?
# Define here the files which should be tested in blindmode.
# NOTE: This files are NOT the ones you use to inject code. The files here are ONLY used
#       to find out the directory count. Or in other words, this files here are used to find
#       out how many ../ are needed. In best case you should define here files which
#       exists on every unix machine and are readable by every user. No need to be injectable.
# The files here should be all absolute. No need to add Null-Bytes. fimap will it do automaticly.
settings["blind"]["files"] = (
                                ("/etc/passwd", "root:", None),
                             )

xmlsettings = language.XML2Config()