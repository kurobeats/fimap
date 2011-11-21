# This file is part of PyBing (http://pybing.googlecode.com).
# 
# Copyright (C) 2009 JJ Geewax http://geewax.org/
# All rights reserved.
# 
# This software is licensed as described in the file COPYING.txt,
# which you should have received as part of this distribution.

"""
This module holds the base Query class used by the various types of Bing queries.
"""

import copy, urllib, httplib2

# Issue #1 (http://code.google.com/p/pybing/issues/detail?id=1)
# Python 2.6 has json built in, 2.5 needs simplejson
try: import json
except ImportError: import simplejson as json

from pybing import constants
from pybing.query.mixin import QueryMixin

class BingQuery(QueryMixin):
    SOURCE_TYPE = None
    
    def __init__(self, app_id, query=None, version=None, *args, **kwargs):
        self.app_id = app_id
        self.version = version or constants.API_VERSION
        self._query = query
        
        # Needed for mixin's __init__'s to be called.
        super(BingQuery, self).__init__(*args, **kwargs)
    
    def set_query(self, query):
        if not query:
            raise ValueError, 'Query cannot be empty or None'
        
        obj = self._clone()
        obj._query = query
        return obj
    
    @property
    def query(self):
        return self._query
    
    def execute(self):
        if not self.query:
            raise ValueError, 'Query cannot be empty or None'
        
        elif not self.SOURCE_TYPE:
            raise ValueError, 'Source Type cannot be empty or None'
        
        from pybing.resultset import BingResultSet
        return BingResultSet(self)
    
    def get_request_parameters(self):
        params = super(BingQuery, self).get_request_parameters()
        params.update({
            'AppId':    self.app_id,
            'Version':  self.version,
            'Query':    self.query,
            'Sources':  self.SOURCE_TYPE,
        })
        return params
    
    def get_request_url(self):
        query_string = urllib.urlencode(self.get_request_parameters())
        return constants.JSON_ENDPOINT + '?' + query_string
    
    def get_search_response(self):
        contents = self._get_url_contents(self.get_request_url())
        return json.loads(contents)['SearchResponse'][self.SOURCE_TYPE]
    
    def get_search_results(self):
        from pybing.result import BingResult
        response = self.get_search_response()
        return [BingResult(result) for result in response['Results']]
    
    def _get_url_contents(self, url):
        response, contents = httplib2.Http().request(url)
        return contents
    
    def _clone(self):
        """
        Do a deep copy of this object returning a clone that can be
        modified without affecting the old copy.
        """
        return copy.deepcopy(self)
    
    def __unicode__(self):
        return 'BingQuery: %s' % self.get_request_url()
    
    __str__ = __unicode__
    
    def __repr__(self):
        return '<%s>' % unicode(self)
