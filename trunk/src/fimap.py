#!/usr/bin/python
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



import baseClass
from codeinjector import codeinjector
from crawler import crawler
import getopt
from googleScan import googleScan
from massScan import massScan
from singleScan import singleScan
from globalSettings import globalSettings
import sys,os
# To change this template, choose Tools | Templates
# and open the template in the editor.

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$30.08.2009 19:57:21$"
__version__ = "07_svn"

config = {}

head = "fimap v.%s by Iman Karim - Automatic LFI/RFI scanner and exploiter." %__version__

def show_help(AndQuit=False):
    print "Usage: ./fimap.py [options]"
    print "## Operating Modes:"
    print "   -s , --single                 Mode to scan a single URL for FI errors."
    print "                                 Needs URL (-u). This mode is the default."
    print "   -m , --mass                   Mode for mass scanning. Will check every URL"
    print "                                 from a given list (-l) for FI errors."
    print "   -g , --google                 Mode to use Google to aquire URLs."
    print "                                 Needs a query (-q) as google search query."
    print "   -H , --harvest                Mode to harvest a URL recursivly for new URLs."
    print "                                 Needs a root url (-u) to start crawling there."
    print "                                 Also needs (-w) to write a URL list for mass mode."
    print "   -b , --enable-blind           Enables blind FI-Bug testing when no error messages are printed."
    print "                                 Note that this mode will cause lots of requests (compared to the default method)."
    print "                                 Can be used with -s, -m or -g."
    print "## Variables:"
    print "   -u , --url=URL                The URL you want to test."
    print "                                 Needed in single mode (-s)."
    print "   -l , --list=LIST              The URL-LIST you want to test."
    print "                                 Needed in mass mode (-m)."
    print "   -q , --query=QUERY            The Google Search QUERY."
    print "                                 Example: 'inurl:include.php'"
    print "                                 Needed in Google Mode (-g)"
    print "        --skip-pages=X           Skip the first X pages from the Googlescanner."
    print "   -p , --pages=COUNT            Define the COUNT of pages to search (-g)."
    print "                                 Default is 10."
    print "   -w , --write=LIST             The LIST which will be written if you have choosen"
    print "                                 harvest mode (-H). This file will be opened in APPEND mode."
    print "   -d , --depth=CRAWLDEPTH       The CRAWLDEPTH (recurse level) you want to crawl your target site"
    print "                                 in harvest mode (-H). Default is 1."
    print "## Attack Kit:"
    print "   -x , --exploit                Starts an interactive session where you can"
    print "                                 select an target and do some action."
    #print "   -f , --exploit-filter=GREP    You can define a grep-like filter for your"
    #print "                                 exploit mode (-x)."
    print "## Disguise Kit:"
    print "   -A , --user-agent=UA          The User-Agent which should be sent."
    print "        --show-my-ip             Shows your internet IP, current country and user-agent."
    print "                                 Useful if you want to test your vpn\\proxy config."
    print "## Other:"
    print "        --test-rfi               A quick test to see if you have configured RFI nicely."
    print "   -v , --verbose=LEVEL          Verbose level you want to receive."
    print "                                 LEVEL=3 -> Debug"
    print "                                 LEVEL=2 -> Info(Default)"
    print "                                 LEVEL=1 -> Messages"
    print "                                 LEVEL=0 -> High-Level"
    print "        --credits                Shows some credits."
    print "        --greetings              Some greetings ;)"
    print "   -h , --help                   Shows this cruft."
    print "## Examples:"
    print "  1. Scan a single URL for FI errors:"
    print "        ./fimap.py -u 'http://localhost/test.php?file=bang&id=23'"
    print "  2. Scan a list of URLS for FI errors:"
    print "        ./fimap.py -m -l '/tmp/urllist.txt'"
    print "  3. Scan Google search results for FI errors:"
    print "        ./fimap.py -g -q 'inurl:include.php'"
    print "  4. Harvest all links of a webpage with recurse level of 3 and"
    print "     write the URLs to /tmp/urllist"
    print "        ./fimap.py -H -u 'http://localhost' -d 3 -w /tmp/urllist"
    if (AndQuit):
        sys.exit(0)

def show_credits():
    print "## Credits:"
    print "## Developer: Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
    print "#"
    print "## Project Home: http://fimap.googlecode.com"
    print "#"
    print "## Additional Thanks to:"
    print "   - Peteris Krumins (peter@catonmat.net) for xgoogle python module."
    print "   - Pentestmonkey from www.pentestmonkey.net for php-reverse-shell."
    print "   - Crummy from www.crummy.com for BeautifulSoup."
    sys.exit(0)


def show_greetings():
    print "## Greetings:"
    print " - Rita, because you are the best girl on earth."
    print "## Circle of awesome people:"
    print " - Exorzist"
    print " - Invisible"
    print " - Ruun"
    sys.exit(0)

def show_ip():
    print "Heading to 'http://85.214.27.38/show_my_ip'..."
    print "----------------------------------------------"
    g = globalSettings(config["p_verbose"])
    g.setUserAgent(config["p_useragent"])
    tester = codeinjector(g)
    result = tester.doGetRequest("http://85.214.27.38/show_my_ip")
    print result.strip()
    sys.exit(0)

def list_results(lst = os.path.join(os.path.expanduser("~"), "fimap_result.xml")):
    if (not os.path.exists(lst)):
        print "File not found! ~/fimap_result.xml"
        sys.exit(1)
    g = globalSettings(config["p_verbose"])
    g.setUserAgent(config["p_useragent"])
    c = codeinjector(g)

    c.start()

    sys.exit(0)


def show_report():
    if (len(baseClass.new_stuff.items()) > 0):
        print "New FI Bugs found in this session:"
        for k,v in baseClass.new_stuff.items():
            print "\t- %d (probably) usable FI-Bugs on '%s'."%(v, k)

if __name__ == "__main__":
    config["p_url"] = None
    config["p_mode"] = 0 # 0=single ; 1=mass ; 2=google ; 3=crawl
    config["p_list"] = None
    config["p_verbose"] = 2
    config["p_useragent"] = "fimap.googlecode.com/v%s" %__version__
    config["p_pages"] = 10
    config["p_query"] = None
    config["p_exploit_filter"] = ""
    config["p_write"] = None
    config["p_depth"] = 1
    config["p_maxtries"] = 5
    config["p_skippages"] = 0
    config["p_monkeymode"] = False
    doRFITest = False
    doInternetInfo = False

    print head

    if (len(sys.argv) == 1):
        show_help(True)

    try:
        longSwitches = ['url=', "mass", "single", "list=", "verbose=", "help", "user-agent=", "query=", "google", "pages=", "credits", "exploit" , "harvest", "write=", "depth=", "greetings", "test-rfi", "skip-pages=", "show-my-ip", "enable-blind"]
        optlist, args = getopt.getopt(sys.argv[1:], "u:msl:v:hA:gq:p:sxHw:d:b", longSwitches)

        startExploiter = False

        for k,v in optlist:
            if (k in ("-u", "--url")):
                config["p_url"] = v
            if (k in ("-s", "--single")):
                config["p_mode"] = 0
            if (k in ("-m", "--mass")):
                config["p_mode"] = 1
            if (k in ("-g", "--google")):
                config["p_mode"] = 2
            if (k in ("-H", "--harvest")):
                config["p_mode"] = 3
            if (k in ("-l", "--list")):
                config["p_list"] = v
            if (k in ("-q", "--query")):
                config["p_query"] = v
            if (k in ("-v", "--verbose")):
                config["p_verbose"] = int(v)
            if (k in ("-p", "--pages")):
                config["p_pages"] = int(v)
            if (k in ("-A", "--user-agent")):
                config["p_useragent"] = v
            if (k in ("-w", "--write")):
                config["p_write"] = v
            if (k in ("-d", "--depth")):
                config["p_depth"] = int(v)
            if (k in ("-h", "--help")):
                show_help(True)
            if (k in ("--test-rfi",)):
                doRFITest = True
            if (k in ("-b", "--enable-blind")):
                config["p_monkeymode"] = True
            if (k in ("--skip-pages",)):
                config["p_skippages"] = int(v)
            if (k in("--credits",)):
                show_credits()
            if (k in ("--greetings",)):
                show_greetings()
            if (k in ("--show-my-ip",)):
                doInternetInfo = True
            if (k in("-x", "--exploit")):
                startExploiter = True
            #if (k in("-f", "--exploit-filter")):
            #    config["p_exploit_filter"] = v
                
        if startExploiter:
            list_results()

    except getopt.GetoptError, err:
        print (err)
        sys.exit(1)


    if (doRFITest):
        g = globalSettings(config["p_verbose"])
        g.setUserAgent(config["p_useragent"])
        injector = codeinjector(g)
        injector.testRFI()
        sys.exit(0)


    if (doInternetInfo):
        show_ip()

    if (config["p_url"] == None and config["p_mode"] == 0):
        print "Target URL required. (-u)"
        sys.exit(1)
    if (config["p_list"] == None and config["p_mode"] == 1):
        print "URLList required. (-l)"
        sys.exit(1)
    if (config["p_query"] == None and config["p_mode"] == 2):
        print "Google Query required. (-q)"
        sys.exit(1)
    if (config["p_url"] == None and config["p_mode"] == 3):
        print "Start URL required for harvesting. (-u)"
        sys.exit(1)
    if (config["p_write"] == None and config["p_mode"] == 3):
        print "Output file to write the URLs to is needed in Harvest Mode. (-w)"
        sys.exit(1)


    try:
        if (config["p_mode"] == 0):
            single = singleScan(config["p_verbose"])
            single.setConfig(config, config["p_url"])
            single.scan()

        elif(config["p_mode"] == 1):
            if (not os.path.exists(config["p_list"])):
                print "Your defined URL-List doesn't exist: %s" %config["p_list"]
                sys.exit(1)
            print "MassScanner is loading URLs from file: '%s'" %config["p_list"]
            m = massScan(config)
            m.startMassScan()
            show_report()

        elif(config["p_mode"] == 2):
            print "GoogleScanner is searching for Query: '%s'" %config["p_query"]
            g = googleScan(config)
            g.startGoogleScan()
            show_report()

        elif(config["p_mode"] == 3):
            print "Crawler is harvesting URLs from start URL: '%s' with depth: %d and writing results to: '%s'" %(config["p_url"], config["p_depth"], config["p_write"])
            c = crawler(config)
            c.crawl()

    except KeyboardInterrupt:
        print "\n\nYou have terminated me :("
        
    except:
        print "\n\n========= CONGRATULATIONS! ========="
        print "You have just found a bug!"
        print "If you are cool, send the following stacktrace to the bugtracker on http://fimap.googlecode.com/"
        print "Please also provide the URL where fimap crashed."
        raw_input("Push enter to see the stacktrace...")
        print "cut here %<--------------------------------------------------------------"
        raise