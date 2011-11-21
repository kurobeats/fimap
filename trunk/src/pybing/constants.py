# This file is part of PyBing (http://pybing.googlecode.com).
# 
# Copyright (C) 2009 JJ Geewax http://geewax.org/
# All rights reserved.
# 
# This software is licensed as described in the file COPYING.txt,
# which you should have received as part of this distribution.

"""
This module holds the any constants used when querying Bing.
"""

API_VERSION = '2.0'
JSON_ENDPOINT = 'http://api.search.live.net/json.aspx'
MAX_PAGE_SIZE = 50
MAX_RESULTS = 1000

WEB_SOURCE_TYPE = 'Web'
IMAGE_SOURCE_TYPE = 'Image'
NEWS_SOURCE_TYPE = 'News'
SPELL_SOURCE_TYPE = 'Spell'
RELATED_SOURCE_TYPE = 'RelatedSearch'
PHONEBOOK_SOURCE_TYPE = 'Phonebook'
ANSWERS_SOURCE_TYPE = 'InstanceAnswer'

SOURCE_TYPES = (
    WEB_SOURCE_TYPE,
    IMAGE_SOURCE_TYPE,
    NEWS_SOURCE_TYPE,
    SPELL_SOURCE_TYPE,
    RELATED_SOURCE_TYPE,
    PHONEBOOK_SOURCE_TYPE,
    ANSWERS_SOURCE_TYPE,
)

DEFAULT_SOURCE_TYPE = WEB_SOURCE_TYPE
