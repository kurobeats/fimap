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
            p.plugin_callback_handler(attack, haxhelper)

class basePlugin(baseClass):
    def _load(self):
        self.name  = None
        self.autor = None
        self.URL   = None
    
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
        