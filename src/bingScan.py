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

from singleScan import singleScan
from targetScanner import targetScanner
from pybing import Bing
import datetime
import sys,time

__author__="Iman Karim(ikarim2s@smail.inf.fh-brs.de)"
__date__ ="$01.09.2009 06:55:16$"

class bingScan:

    def __init__(self, config):
        self.config = config
        self.bs = Bing("YOUR ID")
        self.cooldown = self.config["p_googlesleep"];
        self.results_per_page = int(self.config["p_results_per_query"]);
        if (self.config["p_skippages"] > 0):
            print "Bing Scanner will skip the first %d pages..."%(self.config["p_skippages"])


    def startGoogleScan(self):
        print "Querying Bing Search: '%s' with max pages %d..."%(self.config["p_query"], self.config["p_pages"])

        pagecnt = 0
        curtry = 0
        
        last_request_time = datetime.datetime.now()

        while(pagecnt < self.config["p_pages"]):
            pagecnt = pagecnt +1
            redo = True
            while (redo):
              try:
                current_time = datetime.datetime.now()
                diff = current_time - last_request_time
                diff = int(diff.seconds)

                if (diff <= self.cooldown):
                    if (diff > 0): 
                        print "Commencing %ds bing cooldown..." %(self.cooldown - diff)
                        time.sleep(self.cooldown - diff)
                    
                last_request_time = datetime.datetime.now()
                resp = self.bs.search_web(self.config["p_query"], {'Web.Count':50,'Web.Offset':(pagecnt-1)*self.results_per_page})
                results = resp['SearchResponse']['Web']['Results']
                redo = False
              except KeyboardInterrupt:
                raise
              except Exception, err:
                raise
                redo = True
                sys.stderr.write("[RETRYING PAGE %d]\n" %(pagecnt))
                curtry = curtry +1
                if (curtry > self.config["p_maxtries"]):
                    print "MAXIMUM COUNT OF (RE)TRIES REACHED!"
                    sys.exit(1)
            
              
            curtry = 0
              

            if (len(results) == 0): break
            sys.stderr.write("[PAGE %d]\n" %(pagecnt))
            try:
                for r in results:
                    single = singleScan(self.config)
                    single.setURL(r["Url"])
                    single.setQuite(True)
                    single.scan()
            except KeyboardInterrupt:
                raise
            time.sleep(1)
        print "Bing Scan completed."
