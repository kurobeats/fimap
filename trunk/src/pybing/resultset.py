# This file is part of PyBing (http://pybing.googlecode.com).
# 
# Copyright (C) 2009 JJ Geewax http://geewax.org/
# All rights reserved.
# 
# This software is licensed as described in the file COPYING.txt,
# which you should have received as part of this distribution.

"""
This module holds the logic for dealing with a set of results from a query.
"""

from pybing import constants
from pybing.query import BingQuery, Pagable

class BingResultSet(object):
    """
    This class corresponds to a set of results from a BingQuery.
    """
    def __init__(self, query, offset=0, count=None):
        if not isinstance(query, BingQuery):
            raise TypeError, 'query must be a BingQuery instance'
        
        self.query = query
        self.results = {}
        
        # These offset + count are used internally to signify whether or
        # not the query should be cut down (whether they've been sliced).
        self.offset, self.count = offset, count
    
    def get_offset(self, index=0):
        return self.query.offset + self.offset + index
    
    def __getitem__(self, key):
        """
        Allows you to grab an index or slice a query with array notation like
        resultset[4] or resultset[0:4]
        """
        if not isinstance(self.query, Pagable):
            raise TypeError, 'Array access only supported on Pagable Queries'
        
        if isinstance(key, int):
            absolute_index = self.get_offset()
            if absolute_index < 0 or absolute_index >= constants.MAX_RESULTS:
                raise IndexError
            
            if absolute_index not in self.results:
                # Make a copy of the query for only this one result:
                query = self.query.set_offset(absolute_index).set_count(1)
                results = query.get_search_results()
                if results:
                    self.results[absolute_index] = results[0]
            
            return self.results.get(absolute_index)
        
        elif isinstance(key, slice):
            # Return a new result set that is sliced internally (not the query)
            offset = key.start or 0
            if key.stop: count = key.stop - offset
            else: count = None
            return BingResultSet(self.query, self.offset + offset, count)
        
        else: 
            raise TypeError
    
    def __len__(self):
        """
        Returns the number of results if you were to iterate over this result set.
        This is at least 0 and at most 1000.
        """
        count = constants.MAX_RESULTS
        
        if self.count:
            count = self.count
        
        elif self.query.count:
            count = self.query.count
        
        if count > constants.MAX_RESULTS:
            count = constants.MAX_RESULTS
        
        if count == constants.MAX_RESULTS:
            count = count - self.get_offset()
        
        return count
    
    def __iter__(self):
        """
        Allows you to iterate over the search results in the standard Python
        format such as
        for result in my_query.execute():
            print result.title, result.url
        """
        query = self.query.set_offset(self.get_offset())
        end_index = constants.MAX_RESULTS
        
        # If we've internally sliced out items
        if self.count:
            query = query.set_count(self.count if self.count < constants.MAX_PAGE_SIZE else constants.MAX_PAGE_SIZE)
            end_index = self.get_offset() + self.count
            
            if end_index > constants.MAX_RESULTS:
                end_index = constants.MAX_RESULTS
        
        # If we want to just go until the end, grab them the most per page
        if not query.count:
            query.set_count(constants.MAX_PAGE_SIZE)
        
        while query.offset < end_index:
            # If we don't have a full page left, only grab up to the end
            count = end_index - query.offset
            if count and count < constants.MAX_PAGE_SIZE:
                query = query.set_count(count)
            
            # Yield back each result
            for result in query.get_search_results():
                yield result
            
            # Update the offset to move onto the next page
            query = query.set_offset(query.offset + query.count)
    
    def __repr__(self):
        return '<BingResultSet (%s)>' % self.query
