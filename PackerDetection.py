import pefile
import sys
import peutils
import os

'''
    Checks if sample is packed
    path -> executable path
    signatures -> PEID signatures database
'''
def check(path, signatures):
    try:
        pe = pefile.PE(path)
        matches = signatures.match_all(pe, ep_only = True)

        if matches:
            return True;
        else:
            return False
    except Exception as e:
        return True