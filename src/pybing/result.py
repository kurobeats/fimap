# This file is part of PyBing (http://pybing.googlecode.com).
# 
# Copyright (C) 2009 JJ Geewax http://geewax.org/
# All rights reserved.
# 
# This software is licensed as described in the file COPYING.txt,
# which you should have received as part of this distribution.

"""
This module holds the base BingResult class.
"""

class BingResult(object):
    """
    The base BingResult class corresponds to a single result from a Bing
    Query response.
    """
    def __init__(self, result):
        if isinstance(result, dict):
            self.load_from_dict(result)
        
        else:
            raise TypeError, 'Invalid result type'
    
    def load_from_dict(self, data):
        for key, value in data.iteritems():
            setattr(self, key.lower(), value)
    
    def __repr__(self):
        return '<BingResult>'
