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

from baseClass import baseClass
import os, sys

class plugininterface(baseClass):
    def _load(self):
        self.plugins = []
        self.plugin_dir = os.path.join(sys.path[0], "plugins")
        
        self.loadPlugins()
        
    def loadPlugins(self):
        x = 0
        for dir in os.listdir(self.plugin_dir):
            dirpath = os.path.join(self.plugin_dir, dir)
            if (os.path.isdir(dirpath)):
                self._log("Trying to load plugin '%s'..." %dir, self.LOG_DEBUG)
                loadedClass = None
                loader  = "from plugins.%s import %s\n" %(dir, dir)
                loader += "loadedClass = %s.%s(self.config)"%(dir, dir)
                try:
                    exec(loader)
                    loadedClass.plugin_init()
                    self.plugins.append(loadedClass)
                    x +=1
                except:
                    raise
        for p in self.plugins:
            p.plugin_loaded()

        self._log("%d plugins loaded." %(x), self.LOG_INFO)
        
    def requestPluginActions(self, langClass, isSystem, isUnix):
        ret = []
        for p in self.plugins:
            modes = p.plugin_exploit_modes_requested(langClass, isSystem, isUnix)
            for m in modes:
                ret.append((p.getPluginName(), m))
        return(ret)
    
    def broadcast_callback(self, attack, haxhelper):
        for p in self.plugins:
            try:
                p.plugin_callback_handler(attack, haxhelper)
            except:
                self._log("Plugin '%s' just crashed!"%(p.getPluginName()), self.LOG_ERROR)
                self._log("Please send a bugreport to the Plugin Developer: %s <%s>"%(p.getPluginAutor(), p.getPluginEmail()), self.LOG_ERROR)
                self._log("Push enter to see the stacktrace.", self.LOG_WARN)
                raw_input()
                print "%<--------------------------------------------"
                raise
            


    def getAllPluginObjects(self):
        return(self.plugins)

class basePlugin(baseClass):
    def _load(self):
        self.name  = None
        self.autor = None
        self.URL   = None
        self.email = None
    
    def setPluginEmail(self, email):
        self.email = email
        
    def getPluginEmail(self):
        return(self.email)
    
    def setPluginName(self, name):
        self.name = name
    
    def getPluginName(self):
        return(self.name)
        
    def setPluginAutor(self, autor):
        self.autor = autor
    
    def getPluginAutor(self):
        return(self.autor)
    
    def setPluginURL(self, URL):
        self.URL = URL
        
    def getPluginURL(self):
        return(self.URL)

    # EVENTS
    
    def plugin_init(self):
        print "IMPLEMENT plugin_init !"
        
    def plugin_loaded(self):
        print "IMPLEMENT plugin_loaded !"
        
    def plugin_exploit_modes_requested(self, langClass, isSystem, isUnix):
        # Returns a tuple which will represent a userchoice for the exploit menu.
        # (Label, Callbackstring)
        print "IMPLEMENT plugin_exploit_modes_requested"
        
    def plugin_callback_handler(self, callbackstring, haxhelper):
        # This function will be launched if the user selected one of your attacks.
        print "IMPLEMENT plugin_callback_handler"
        