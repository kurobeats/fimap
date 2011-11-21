# This file is part of PyBing (http://pybing.googlecode.com).
# 
# Copyright (C) 2009 JJ Geewax http://geewax.org/
# All rights reserved.
# 
# This software is licensed as described in the file COPYING.txt,
# which you should have received as part of this distribution.

"""
This module holds the QueryMixin base class used for all queries.
"""

class QueryMixin(object):
    """
    Any methods that might be mixed into queries should extend this
    base class. 
    """
    def get_request_parameters(self):
        params = {}
        
        # Since we're mixing in, super() may or may not have the attribute
        sup = super(QueryMixin, self)
        if hasattr(sup, 'get_request_parameters'):
            params = sup.get_request_parameters()
        
        return params
