#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com

""" References
http://www.blackhat.com/presentations/bh-usa-08/Suiche/BH_US_08_Suiche_Windows_hibernation.pdf
http://sandman.msuiche.net/docs/SandMan_Project.pdf
http://stoned-vienna.com/downloads/Hibernation%20File%20Attack/Hibernation%20File%20Format.pdf
http://stoned-vienna.com/html/index.php?page=hibernation-file-attack
http://digital-forensics.sans.org/blog/2014/07/01/hibernation-slack-unallocated-data-from-the-deep-past

OS dependant
struct MEMORY_TABLE
{
    DWORD PointerSystemTable;
    UINT32 NextTablePage; #point to next memory table
    DWORD CheckSum;
    UINT32 EntryCount;
    MEMORY_TABLE_ENTRY MemoryTableEntries[EntryCount];
};

struct MEMORY_TABLE_ENTRY
{
    UINT32 PageCompressedData;
    UINT32 PhysicalStartPage;
    UINT32 PhysicalEndPage;
    DWORD CheckSum;
};

struct IMAGE_XPRESS_HEADER
{
    CHAR Signature[8] = 81h, 81h, "xpress";
    BYTE UncompressedPages = 15;
    UINT32 CompressedSize;
    BYTE Reserved[19] = 0;
};
"""

import sys
import os
import mmap
from struct import unpack
from collections import namedtuple

XPRESS_SIG = "\x81\x81" + "xpress"
PAGE_SIZE = 4096
VERBOSE = False

def roundit(num, rnum):
    """
        generic function to round stuff on a certain size
    """
    if (num % rnum) == 0:
        return num
    else:   
        return num + (rnum-(num % rnum))

def verify_memorytable_offset(offset):
    """
        Verify the table pointer to be valid
        valid table pointer should have an Xpress block
        on the next page
    """
    fmm.seek(offset+PAGE_SIZE)
    correct = False
    if fmm.read(8) == XPRESS_SIG:
        correct = True
    fmm.seek(offset)
    return correct

#could go horribly wrong, seems to work though
def find_memorytable_nexttable_offset(data):
    """
        Dynamically find the NextTablePage pointer
        Verification based on verify_memorytable_offset function
    """
    for i in range(len(data)):
        toffset = unpack('<I',data[i:(i+4)])[0]*PAGE_SIZE
        if verify_memorytable_offset(toffset):
            return i
    
def xpressblock_size(fmm,offset):
    fmm.seek(offset)
    if fmm.read(8) != XPRESS_SIG:
        return None
    fmm.read(1)
    xsize = roundit(((unpack('<I',fmm.read(4))[0] / 4) + 1),8)
    fmm.seek(offset) 
    # sig8 + 1 + size4 + 19
    return (32+xsize)
                                  
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print sys.argv[0] + " <hiberfil.sys>"
        sys.exit()

    hibfile = sys.argv[1]
    fsize = os.path.getsize(hibfile)
    f = open(hibfile,'r+b')
    fmm = mmap.mmap(f.fileno(),0)
    
    MEMTABLE_OFFSET = None
    firstxpressblock = fmm.find(XPRESS_SIG)
    print "Found Xpress block @ 0x%x" % firstxpressblock
    firstmemtableoffset = firstxpressblock - PAGE_SIZE
    print "Corresponding MemoryTable @ 0x%x" % firstmemtableoffset
    fmm.seek(firstmemtableoffset)
    firstmemtable = fmm.read(PAGE_SIZE)
    MEMTABLE_OFFSET = find_memorytable_nexttable_offset(firstmemtable)
    print "MemoryTable.NextTablePointer offset %d" % MEMTABLE_OFFSET
    
    nexttable = firstmemtableoffset
    while True:
        fmm.seek(nexttable)
        fmm.seek(MEMTABLE_OFFSET,1)
        ntdata = fmm.read(4)
        noff = unpack('<I',ntdata)[0]*PAGE_SIZE
        if VERBOSE:
            print "MemoryTable @ 0x%x" % noff
        if not verify_memorytable_offset(noff):
            break
        nexttable = noff
    
    lasttable = nexttable
    
    print "Last MemoryTable @ 0x%x" % lasttable
    fmm.seek(lasttable+PAGE_SIZE)
    nxpress = fmm.tell()
    while True:
        xsize = xpressblock_size(fmm,nxpress)
        fmm.seek(xsize,1)
        xh = fmm.read(8)
        if xh != XPRESS_SIG:
            break
        fmm.seek(-8,1)
        nxpress = fmm.tell()
        if VERBOSE:
            print "Xpress block @ 0x%x" % nxpress        
    print "Last Xpress block @ 0x%x" % nxpress
    fmm.seek(nxpress)
    fmm.seek(xpressblock_size(fmm,nxpress),1)
    slackstart = fmm.tell()
    print "Start of slack space @ %d" % slackstart
    print "Total file size %d" % fsize
    print "Slackspace size %d megs" % ((fsize - slackstart) / 1024 / 1024)

    
    bla = fmm.find(XPRESS_SIG)
    fmm.seek(bla-PAGE_SIZE)
    print verify_memorytable_offset(fmm.tell())
    print hex(unpack('<I',fmm.read(4))[0]*PAGE_SIZE)   
    print hex(unpack('<I',fmm.read(4))[0]*PAGE_SIZE)
    print hex(unpack('<I',fmm.read(4))[0]*PAGE_SIZE)    
    fmm.close()
    f.close()
    
