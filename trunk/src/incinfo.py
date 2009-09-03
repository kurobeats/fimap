#
# This file is part of fimap.
#
# Copyright(c) 2009 Iman Karim(ikarim2s@smail.inf.fh-brs.de).
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



__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$01.09.2009 04:01:22$"

class incinfo():
    
    def __init__(self, URL, Params, VulnKey):
        self.URL = URL
        self.Params = Params
        self.VulnKey = VulnKey
        
    def getURL(self):
        return(self.URL)
    
    def getParams(self):
        return(self.Params)

    def getVulnKey(self):
        return(self.VulnKey)