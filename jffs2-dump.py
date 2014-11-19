#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# jffs2-dump - JFFS2 userspace dumper tool
#
# Copyright © 2009 Igor Skochinsky
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import sys, struct, os
from zlib import decompress

def getByte(f):
    return ord(f.read(1));

def getSWord(f):
    return struct.unpack("<h",f.read(2))[0];

def getWord(f):
    return struct.unpack("<H",f.read(2))[0];

def getDWord(f):
    return struct.unpack("<L",f.read(4))[0];

def strByte(s,off=0):
    return ord(s[off]);

def strSWord(s,off=0):
    return struct.unpack("<h",s[off:off+2])[0];

def strWord(s,off=0):
    return struct.unpack("<H",s[off:off+2])[0];

def strDWord(s,off=0):
    return struct.unpack("<L",s[off:off+4])[0];

def rtime_decompress(data_in, destlen):
  outpos = pos = 0;
  positions = [0] * 256
  cpage_out = ""

  while outpos < destlen:
    value, repeat = struct.unpack("BB",data_in[pos:pos+2])
    pos += 2
    cpage_out += chr(value)
    outpos += 1
    backoffs = positions[value]
    positions[value] = outpos
    if repeat:
      if backoffs + repeat >= outpos:
        for i in range(repeat):
          cpage_out += cpage_out[backoffs+i]
        backoffs += repeat
      else:
        cpage_out += cpage_out[backoffs:backoffs+repeat]
      outpos += repeat

  #print "after decompression: len=%d (wanted: %d), outpos: %d"%(len(cpage_out), destlen, outpos)
  return cpage_out

JFFS2_MAGIC_BITMASK = 0x1985
JFFS2_EMPTY_BITMASK = 0xffff
# Compatibility flags.
JFFS2_COMPAT_MASK   = 0xc000      # What do to if an unknown nodetype is found
JFFS2_NODE_ACCURATE = 0x2000
# INCOMPAT: Fail to mount the filesystem
JFFS2_FEATURE_INCOMPAT = 0xc000
# ROCOMPAT: Mount read-only
JFFS2_FEATURE_ROCOMPAT = 0x8000
# RWCOMPAT_COPY: Mount read/write, and copy the node when it's GC'd
JFFS2_FEATURE_RWCOMPAT_COPY = 0x4000
# RWCOMPAT_DELETE: Mount read/write, and delete the node when it's GC'd
JFFS2_FEATURE_RWCOMPAT_DELETE = 0x0000
JFFS2_NODETYPE_DIRENT      = (JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 1)
JFFS2_NODETYPE_INODE       = (JFFS2_FEATURE_INCOMPAT | JFFS2_NODE_ACCURATE | 2)
JFFS2_NODETYPE_CLEANMARKER = (JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 3)
JFFS2_NODETYPE_PADDING     = (JFFS2_FEATURE_RWCOMPAT_DELETE | JFFS2_NODE_ACCURATE | 4)

JFFS2_COMPR_NONE        = 0x00
JFFS2_COMPR_ZERO        = 0x01
JFFS2_COMPR_RTIME       = 0x02
JFFS2_COMPR_RUBINMIPS   = 0x03
JFFS2_COMPR_COPY        = 0x04
JFFS2_COMPR_DYNRUBIN    = 0x05
JFFS2_COMPR_ZLIB        = 0x06

DT_UNKNOWN = 0
DT_FIFO = 1
DT_CHR = 2
DT_DIR = 4
DT_BLK = 6
DT_REG = 8
DT_LNK = 10
DT_SOCK = 12
DT_WHT = 14

dt_typenames = {
  DT_UNKNOWN: "Unknown",
  DT_FIFO: "Fifo",
  DT_CHR : "Char device",
  DT_DIR : "Directory",
  DT_BLK : "Block device",
  DT_REG : "Regular file",
  DT_LNK : "Symlink",
  DT_SOCK: "Socket",
  DT_WHT : "Whiteout"
}

class jffs2_node:
  def __init__(self, f):
    cur_off   = f.tell()
    magic     = getWord(f)
    nodetype  = getWord(f)
    self.nodetype = nodetype
    if magic == JFFS2_EMPTY_BITMASK:
      new_off   = cur_off + 4
      self.type = nodetype
      self.data = ""
      while f.read(4) == '\xFF\xFF\xFF\xFF':
        new_off += 4
      f.seek(new_off)
      self.data_len = new_off - cur_off
      return
    if magic != JFFS2_MAGIC_BITMASK:
      raise Exception("Bad magic at offset %08X: %04X"%(cur_off, magic))

    totlen    = getDWord(f)
    crc       = getDWord(f)
    if nodetype == JFFS2_NODETYPE_DIRENT:
      self.pino      = getDWord(f)
      self.version   = getDWord(f)
      self.ino       = getDWord(f)
      self.mctime    = getDWord(f)
      nsize          = getByte(f)
      self.type      = getByte(f)
      f.read(2) #unused
      self.node_crc  = getDWord(f)
      self.name_crc  = getDWord(f)
      self.name      = f.read(nsize)
    elif nodetype == JFFS2_NODETYPE_INODE:
      self.ino       = getDWord(f)
      self.version   = getDWord(f)
      self.mode      = getDWord(f)
      self.uid       = getWord(f)
      self.gid       = getWord(f)
      self.isize     = getDWord(f)
      self.atime     = getDWord(f)
      self.mtime     = getDWord(f)
      self.ctime     = getDWord(f)
      self.offset    = getDWord(f)
      self.csize     = getDWord(f)
      self.dsize     = getDWord(f)
      self.compr     = getByte(f)
      self.usercompr = getByte(f)
      self.flags     = getWord(f)
      self.data_crc  = getDWord(f)
      self.node_crc  = getDWord(f)
      self.data_off  = f.tell()
    else:
      self.data_off = f.tell()
      self.data_len = totlen-12
    f.seek( cur_off + (totlen + 3)&~3)
    self.infile = f

  def get_data(self):
    if self.nodetype == JFFS2_NODETYPE_DIRENT:
      return None
    elif self.nodetype == JFFS2_NODETYPE_INODE:
      self.infile.seek(self.data_off)
      data = self.infile.read(self.csize)
      if self.compr == JFFS2_COMPR_NONE:
        pass
      elif self.compr == JFFS2_COMPR_ZERO:
        data = '\0'*self.dsize
      elif self.compr == JFFS2_COMPR_ZLIB:
        data = decompress(data)
      elif self.compr == JFFS2_COMPR_RTIME:
        data = rtime_decompress(data, self.dsize)
      else:
        raise Exception("Unknown compression %d", self.compr)
      if len(data) != self.dsize:
        raise Exception("Decompression error")
      return data
    elif self.nodetype == JFFS2_EMPTY_BITMASK:
      return ""
    else:
      self.infile.seek(self.data_off)
      return self.infile.read(self.data_len)

  def __repr__(self):
    s = ""
    if self.nodetype == JFFS2_NODETYPE_DIRENT:
      s = "<Dirent: pino=%d, ino=%d, type: %s, name='%s', ver=%d>"%(self.pino, self.ino, dt_typenames[self.type], self.name, self.version)
    elif self.nodetype == JFFS2_NODETYPE_INODE:
      s = "<Inode: ino=%d, offset=%08X, compr=%d, dsize=%d>"%(self.ino, self.offset, self.compr, self.dsize)
    elif self.nodetype == JFFS2_EMPTY_BITMASK:
      s = "<Padding (%d bytes)>"%(self.data_len)
    elif self.nodetype == JFFS2_NODETYPE_CLEANMARKER:
      s = "<Clean maker>"
    else:
      s = "<Unknown node of type %04X, data len=%d>"%(self.nodetype, self.data_len)
    return s

def unpack_main(filename, rootdir):
  f = file(filename, "rb")
  log = file("log.txt","w")
  cur_inode = -1
  cur_file = None
  f.seek(0,2)
  flen = f.tell()
  f.seek(0)
  inodes = {}
  dirents = {}
  parents = {}
  while f.tell()<flen:
    off = f.tell()
    n = jffs2_node(f)
    log.write("%08X: %r\n"%(off, n))
    if n.nodetype == JFFS2_NODETYPE_DIRENT:
      #if n.ino not in dirents:
      #  dirents[n.ino] = []
      #dirents[n.ino].append(n)
      if n.pino not in parents:
        parents[n.pino] = []
      parents[n.pino].append(n)
    elif n.nodetype == JFFS2_NODETYPE_INODE:
      if n.ino not in inodes:
        inodes[n.ino] = []
      inodes[n.ino].append(n)
  log.write("dirents: %r\n"%parents)
  log.write("inodes: %r\n"%inodes)

  try:
    os.makedirs(rootdir)
  except:
    pass

  tree = { 1: rootdir }
  stack = [1]
  while len(stack):
    cur_dir = stack.pop(0)
    log.write("Walking dir ino=%d\n"%cur_dir)
    if not cur_dir in parents:
      log.write("No entries\n")
      continue
    for n in parents[cur_dir]:
      log.write("\tdir entry ino=%d\n"%n.ino)
      path = tree[n.pino] + "/" + n.name
      tree[n.ino] = path
      log.write("\tfull path: %s\n"%(path))
      if n.type == DT_DIR:
        try:
          os.makedirs(path)
        except:
          pass
        stack.append(n.ino)
      elif n.type == DT_REG or n.type == DT_LNK:
        print path
        cur_file = file(path, "wb")
        for din in inodes[n.ino]:
          if din.dsize > 0:
            cur_file.seek(din.offset)
            cur_file.write(din.get_data())
        cur_file.close()
  f.close()

if __name__ == '__main__':
  unpack_main(sys.argv[1], 'root')
