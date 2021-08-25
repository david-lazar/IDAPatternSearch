import sys

import IDAPatternSearch_utils.IDAPatternSearch as IDAPatternSearch

def PLUGIN_ENTRY():
    return IDAPatternSearch.IDAPatternSearchPlugin()