# flsloader
# =========
#
# IDA Pro loader module for IFX iPhone baseband firmwares.
# Based on a universal scatter loader script by roxfan.
#
# Supports loading of:
#
# * iPhone 2G  (S-Gold 2)
# * iPhone 3G  (X-Gold 608)
# * iPhone 3GS (X-Gold 608)
# * iPhone 4   (X-Gold 61x)
#
# baseband firmwares into IDA Pro.
#
# Tested with IDA Pro Advanced 6.1 & 6.2

import struct
import re

IFX_FLS_SIGNATURE = 'CJKT'

def dwordAt(li, off):
    li.seek(off)
    s = li.read(4)
    if len(s) < 4: 
        return 0
    return struct.unpack('<I', s)[0]

def matchBytes(addr,match):
    n = len(match)
    if n & 1:
        idc.Warning("Bad match string in matchBytes: %s",match)
        return 0
    i = 0
    while i < n:
        s = match[i:(i+2)]
        byteashex = "%02X" % idc.Byte(addr)
        if s != "??" and byteashex != s:
            return 0
        i += 2
        addr += 1
    return 1

def is_copy(ea):
    return matchBytes(ea, "102052E27800B0287800A128FBFFFF8A822EB0E13000B0283000A1280040904500408145??????E1")

def is_zeroinit(ea):
    return matchBytes(ea, "0030A0E30040A0E30050A0E30060A0E3102052E27800A128FCFFFF8A822EB0E13000A12800308145??????E1")

def is_decomp1(ea):
    return matchBytes(ea, "01C08FE21CFF2FE18A18037801305C07640F01D1047801301D1101D105780130")

def is_decomp0(ea):
    return (matchBytes(ea, "01C08FE21CFF2FE18A180478013025072D0F01D105780130240901D104780130") or
            matchBytes(ea, "012082E00140D0E40F5014E20150D0042442B0E10140D004015055E20300000A0130D0E4015055E20130C1E4FBFFFF1A014054E20200000A014054E20150C1E4FCFFFF1A020051E1EDFFFF3A0EF0A0E1"))

def decompress1(src, dst, dstsize):
    orig_src = src
    orig_dst = dst
    end = dst+dstsize
    while dst < end:
        r3 = idc.Byte(src)
        src += 1
        r4 = r3&7
        if r4 == 0:
            r4 = idc.Byte(src)
            src += 1
        r5 = r3 >> 4
        if r5 == 0:
            r5 = idc.Byte(src)
            src += 1
	# r4: length of region to copy from src
        while r4 > 1:
            idaapi.patch_byte(dst, idaapi.get_full_byte(src))
            dst += 1
            src += 1
            r4 -= 1
        if r3&8:
            r4 = idc.Byte(src)
            src += 1
            r5 += 1
            r3 = dst - r4
	    # fill region with constant value
            while r5 >= 0:
                idaapi.patch_byte(dst, idaapi.get_full_byte(src))
                dst +=1
                r3 += 1
                r5 -= 1
        else:
            while r5>0:
	        # zero-fill region
                idaapi.patch_byte(dst, 0)
                dst += 1
                r5 -= 1
    idc.Message("consumed=%0x, produced=%0x\n" % (src-orig_src, dst-orig_dst))
    return (dst-orig_dst)==dstsize

def decompress0(src, dst, dstsize):
    orig_src = src
    orig_dst = dst
    end = dst + dstsize
    while dst < end:
        r3 = idc.Byte(src)
        src += 1
        r4 = r3&0xF
        if r4 == 0:
            r4 = idc.Byte(src)
            src += 1
        r5 = r3 >> 4
        if r5 == 0:
            r5 = idc.Byte(src)
            src += 1
        while r4 > 1:
            idaapi.patch_byte(dst, idaapi.get_full_byte(src))            
            src += 1
            dst += 1
            r4 -= 1
        while r5 > 1:
            idaapi.patch_byte(dst, 0)
            dst += 1
            r5 -= 1
    idc.Message("consumed=%0x, produced=%0x\n" % (src-orig_src, dst-orig_dst))
    return (dst-orig_dst)==dstsize;

def ProcessEntry(entry):
    src = idc.Dword(entry);
    dst = idc.Dword(entry+4);
    size = idc.Dword(entry+8);
    proc = idc.Dword(entry+12);
    idc.Message("0x%08x: src=%08X dst=%08X size=%08X func=%08X\n" % (entry, src, dst, size, proc))
    if (idc.SegStart(dst) == idc.BADADDR) or (idc.SegEnd(dst) <(dst+size)):
        idc.AddSeg(dst,(dst+size),0,1,1,0)
    if is_copy(proc):
        idc.Message("0x%08x: copy(0x%08x, 0x%08x, %x)..." % (proc, src, dst, size))
        buf = idaapi.get_many_bytes(src, size)
        idaapi.patch_many_bytes(dst, buf)
        idc.Message("OK\n")
    elif is_zeroinit(proc):
        idc.Message("0x%08x: zeroinit(0x%08x, %x)..." % (proc, dst, size))
        idaapi.patch_many_bytes(dst, '\0' * size)
        Message("OK\n")
    elif is_decomp1(proc):
        idc.Message("0x%08x: uncompress1(0x%08x, 0x%08x, %x)..." % (proc, src, dst, size))
        decompress1(src, dst, size)
        Message("OK\n")
    elif is_decomp0(proc):
        idc.Message("0x%08x: uncompress0(0x%08x, 0x%08x, %x)..." % (proc, src, dst, size))
        idc.decompress0(src, dst, size)
        idc.Message("OK\n")
    else:
        idc.Message("0x%08x: unknown scatterload function\n" % proc)
        return 0
    return 1

def ProcessRegionTable(segstart):
    scatter_rt2 = idc.FindBinary(segstart, 1, "0F 00 BA E8 14 E0 4F E2 01 00 13 E3 03 F0 47 10")
    if scatter_rt2 == idc.BADADDR:
        idc.Message("Can't find __scatter_rt2\n")
        return 0

    idc.Message("__scatter_rt2 is at 0x%08x\n" % scatter_rt2)
    scatter_rt2 += 0x14
    tblstart = scatter_rt2+idc.Dword(scatter_rt2)
    tblend = scatter_rt2+idc.Dword(scatter_rt2+4)
    idc.Message("Scatterload table: 0x%08x-0x%08x\n" % (tblstart, tblend))
    if (tblstart>=tblend) or ((tblend-tblstart)%16):
        idc.Message("Bad table\n")
        return 0
    idc.MakeStruct(tblstart,  "ScatterEntry")
    idc.MakeArray(tblstart,  (tblend-tblstart)/16)
    idc.MakeName(tblstart,  "RegionTable_%08X" % tblstart)
    i = 0
    x = tblstart
    while tblstart < tblend:
        if ProcessEntry(tblstart) == 0:
            break
        b = idc.Dword(tblstart);
        tblstart += 16
        if (tblstart < tblend) and (is_zeroinit(idc.Dword(tblstart-4)) == 0):
            c = idc.Dword(tblstart);
            if c > b:
                idc.HideArea(b,c, "Scatterload source data for region %d" % i, "", "", 0xff0000)
        i += 1

def setup_structs():
  id = idc.AddStrucEx(-1,"ScatterEntry",0)
  id = idc.GetStrucIdByName("ScatterEntry")

  # FF_DWRD | FF_DATA | FF_0OFF
  idc.AddStrucMember(id, "src", 0*4, 0x20500400, 0xFFFFFFFF, 4)
  idc.AddStrucMember(id, "dst", 1*4, 0x20500400, 0xFFFFFFFF, 4)
  idc.AddStrucMember(id,"size", 2*4, 0x20000400, 0xFFFFFFFF, 4)
  idc.AddStrucMember(id,"proc", 3*4, 0x20500400, 0xFFFFFFFF, 4)

  return id

# Verify the input file format
#      li - loader_input_t object. it is positioned at the file start
#      n  - invocation number. if the loader can handle only one format,
#           it should return failure on n != 0
# Returns: if the input file is not recognized
#              return 0
#          else
#              return object with 2 attributes:
#                 format: description of the file format
#                 options:1 or ACCEPT_FIRST. it is ok not to set this attr

def accept_file(li, n):
    flsversion = None
    
    if n > 0:
	return 0

    li.seek(0x9e0, SEEK_SET)
    if li.read(4) == IFX_FLS_SIGNATURE:
        flsversion = 'iPhone S-GOLD2 baseband'
        arch = "arm:ARMv5TE"

    li.seek(0x1104, SEEK_SET)    
    if li.read(4) == IFX_FLS_SIGNATURE:
        li.seek(0x794)
        chipid = li.read(7)
        if chipid == 'Sibley\0':
            flsversion = 'iPhone X-GOLD 608 baseband'
            arch = "arm:ARMv5TE"
        elif chipid == 'XMM6180':
            flsversion = 'iPhone X-GOLD 61x baseband'
            arch = "arm:ARMv6"

    if flsversion != None:
        idaapi.set_processor_type(arch, SETPROC_ALL|SETPROC_FATAL)
	idc.ChangeConfig('ARM_SIMPLIFY = NO')
        return flsversion
    else:
        return 0

def load_file(li, neflags, format):
    """
    Load the file into the database
    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok    
    """
    
    if format == 'iPhone S-GOLD2 baseband':
        # ARM 926
        arch = "arm:ARMv5TE"        
        start = 0xA0000000
        offset = 0x9A4
        entry_point = dwordAt(li, 0x9dc)
        scattertbl_search_from = start        
    elif format == 'iPhone X-GOLD 608 baseband':
        # ARM 926
        arch = "arm:ARMv5TE"        
        start = 0x20040000
        offset = 0xCF8
        entry_point = dwordAt(li, 0x1100)
        scattertbl_search_from = entry_point        
    elif format == 'iPhone X-GOLD 61x baseband':
        # ARM 1176
        arch = "arm:ARMv6"        
        start = 0x40040000
        offset = 0xCF8
        entry_point = dwordAt(li, 0x1100)
        scattertbl_search_from = entry_point        
    else:
        Warning("Unknown format name: '%s'" % format)
        return 0

    li.seek(0, SEEK_END)
    size = li.tell() - offset

    if entry_point != 0:
        idc.Message("Entry point = 0x%08x" % entry_point)
    
    idaapi.set_processor_type(arch, SETPROC_ALL|SETPROC_FATAL)
    idc.ChangeConfig('ARM_SIMPLIFY = NO')
    AddSeg(start, start+size, 0, 1, idaapi.saRelPara, idaapi.scPub)
    li.seek(0)
    li.file2base(offset, start, start+size, 0)
    setup_structs()
    ProcessRegionTable(scattertbl_search_from)
    idaapi.add_entry(entry_point, entry_point, "start", 1)
    return 1
