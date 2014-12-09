#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com

import sys 
import mmap
from struct import unpack
from xpress import xpress_decode


XPRESS_SIG = "\x81\x81" + "xpress"

def roundit(num, rnum):
    """
        generic function to round stuff on a certain size
    """
    if (num % rnum) == 0:
        return num
    else:   
        return num + (rnum-(num % rnum))
        
def xpressblock_size(fmm,offset=0):
    fmm.seek(offset)
    if fmm.read(8) != XPRESS_SIG:
        return None
    fmm.read(1)
    xsize = roundit(((unpack('<I',fmm.read(4))[0] / 4) + 1),8)
    fmm.seek(offset) 
    # sig8 + 1 + size4 + 19
    return (32+xsize)
    
if __name__ == "__main__":

    if len(sys.argv) < 2:
        sys.exit()
    
    
    hibfile = sys.argv[1]
    hiboffset = 0
    slackfile = './decompressed.slack'
    if len(sys.argv) > 2:
        hiboffset = int(sys.argv[2])
    
    f = open(hibfile,'r+b')
    fo = open(slackfile,'ab')
    fmm = mmap.mmap(f.fileno(),0)
    fmm.seek(hiboffset)
    print "Advancing to offset %d" % hiboffset
    while True:
        xoff = fmm.find(XPRESS_SIG)
        xsize = xpressblock_size(fmm,xoff)
        print "Xpress block size: %d" % xsize         
        #fmm.read(xsize)
        fo.write(fmm.read(xsize)[32:])
        #sys.exit()
    fo.close()
    fmm.close()
    f.close()
    

