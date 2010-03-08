from plugininterface import basePlugin

class test_plugin(basePlugin):
        
    def plugin_init(self):
        # The Constructor of the plugin
        pass
        
    def plugin_loaded(self):
        # This function will be called if all plugins are loaded.
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
            attack = ("Show some info", "example.sysinfo")
            ret.append(attack)
        
        return(ret)
        
    def plugin_callback_handler(self, callbackstring, haxhelper):
        # This function will be launched if the user selected one of your attacks.
        # The two params you receive here are:
        #    * callbackstring - The string you have defined in plugin_exploit_modes_requested.
        #    * haxhelper - A little class which makes it very easy to send an injected command.
        
        if (callbackstring == "example.sysinfo"):
            print haxhelper.isUnix()
            print haxhelper.isWindows()
            print haxhelper.getLangName()
            print haxhelper.canExecuteSystemCommands()
            print haxhelper.concatCommands(("ver", "echo %USERNAME%"))
            
            if (haxhelper.isUnix()):
                # We are in unix
                
                print haxhelper.executeSystemCommand("cat /proc/cpuinfo")
                print haxhelper.executeSystemCommand("uname -a")
            else:
                # We are in Windows
                print haxhelper.executeSystemCommand("ver")
            