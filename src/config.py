#
# This file is part of fimap.
#
# Copyright(c) 2009-2012 Iman Karim(ikarim2s@smail.inf.fh-brs.de).
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

settings = {}

settings["dynamic_rfi"] = {}

# Set to "ftp" or "local" to use Dynamic_RFI. Set it to "off" to disable it and rely on settings["filesrmt"] files.
settings["dynamic_rfi"]["mode"] = "off"

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
# A non existing file without suffix. Example: /home/imax/public_html/payload
settings["dynamic_rfi"]["ftp"]["ftp_path"] = None
# The mapped HTTP path of the file. Example: http://localhost/~imax/payload
settings["dynamic_rfi"]["ftp"]["http_map"] = None

# Local Mode
settings["dynamic_rfi"]["local"] = {}
# A non existing file on your filesystem without prefix which is reachable by http. Example: /var/www/payload
settings["dynamic_rfi"]["local"]["local_path"] = None
# The http url of the file without prefix where the file is reachable from the web. Example: http://localhost/payload
settings["dynamic_rfi"]["local"]["http_map"] = None
