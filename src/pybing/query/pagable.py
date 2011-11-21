# This file is part of PyBing (http://pybing.googlecode.com).
# 
# Copyright (C) 2009 JJ Geewax http://geewax.org/
# All rights reserved.
# 
# This software is licensed as described in the file COPYING.txt,
# which you should have received as part of this distribution.

"""
This module holds a mixin to specify a query class you can page through
using the count and offset parameter.
"""

from mixin import QueryMixin

class Pagable(QueryMixin):
    """
    This class is a mixin used with BingQuery classes to specify that 
    queries can be paged through using the offset and count parameters.
    
    Some examples of Pagable requests are WebRequests and VideoRequests.
    Some non-Pagable requests are TranslationRequests and SearchRequests with
    the Spell source type.
    
    From the Bing API:
    - Count specifies the number of results to return per Request.
    - Offset specifies the offset requested, from zero, for the starting
      point of the result set to be returned for this Request.
    
    Note: This mixin currently supports only a single Source Type query.
    """
    def __init__(self, *args, **kwargs):
        self._count = None
        self._offset = 0
        super(Pagable, self).__init__(*args, **kwargs)
    
    def execute(self, *args, **kwargs):
        if self.count and self.offset and self.count + self.offset > 1000:
            raise ValueError, "Count + Offset must be less than 1000"
        super(Pagable, self).execute(*args, **kwargs)
    
    def get_request_parameters(self):
        params = super(Pagable, self).get_request_parameters()
        
        if self.count:
            params['%s.Count' % self.SOURCE_TYPE] = self.count
        
        if self.offset:
            params['%s.Offset' % self.SOURCE_TYPE] = self.offset
        
        return params
    
    @property
    def count(self):
        return self._count
    
    def set_count(self, value):
        if value is not None:
            if value < 1:
                raise ValueError, 'Count must be positive'
            
            elif value > 50:
                raise ValueError, 'Count must be less than 50'
        
        obj = self._clone()
        obj._count = value
        return obj
    
    @property
    def offset(self):
        return self._offset
    
    def set_offset(self, value):
        if value < 0:
            raise ValueError, 'Offset must be positive'
        
        elif value > 1000:
            raise ValueError, 'Offset must be less than 1000'
        
        obj = self._clone()
        obj._offset = value
        return obj
