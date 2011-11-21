# This file is part of PyBing (http://pybing.googlecode.com).
# 
# Copyright (C) 2009 JJ Geewax http://geewax.org/
# All rights reserved.
# 
# This software is licensed as described in the file COPYING.txt,
# which you should have received as part of this distribution.

"""
This module holds the Bing class which is used to create and execute queries
against Bing.
"""

import urllib, httplib2

# Issue #1 (http://code.google.com/p/pybing/issues/detail?id=1)
# Python 2.6 has json built in, 2.5 needs simplejson
try: import json
except ImportError: import simplejson as json

from pybing import constants

class Bing(object):
    def __init__(self, app_id):
        self.app_id = app_id
    
    def search(self, query, source_type=None, api_version=None, extra_params=None, **kwargs):
        kwargs.update({
            'AppId':    self.app_id,
            'Version':  api_version or constants.API_VERSION,
            'Query':    query,
            'Sources':  source_type or constants.DEFAULT_SOURCE_TYPE,
        })
        
        if extra_params:
            kwargs.update(extra_params)
        
        query_string = urllib.urlencode(kwargs)
        response, contents = httplib2.Http().request(constants.JSON_ENDPOINT + '?' + query_string)
        return json.loads(contents)
    
    def search_web(self, query, params):
        return self.search(query, source_type=constants.WEB_SOURCE_TYPE, extra_params=params)
    
    def search_image(self, query):
        return self.search(query, source_type=constants.IMAGE_SOURCE_TYPE)
    
    def search_news(self, query):
        return self.search(query, source_type=constants.NEWS_SOURCE_TYPE)
    
    def search_spell(self, query):
        return self.search(query, source_type=constants.SPELL_SOURCE_TYPE)
    
    def search_related(self, query):
        return self.search(query, source_type=constants.RELATED_SOURCE_TYPE)
    
    def search_phonebook(self, query):
        return self.search(query, source_type=constants.PHONEBOOK_SOURCE_TYPE)
    
    def search_answers(self, query):
        return self.search(query, source_type=constants.ANSWERS_SOURCE_TYPE)
