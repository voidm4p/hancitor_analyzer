#!/usr/bin/env python

__description__ = "Program to find all the Hancitor payloads download URLs from a memory dump."
__author__ = 'voidm4p'
__version__ = '0.0.2'
__date__ = '2017/11/21'

"""
Special thanks to: Didier Stevens
"""

import sys
import re
import os
import hashlib
import struct
import os.path
from optparse import OptionParser
from urllib2 import urlopen, URLError, HTTPError

dLibrary = {
    'url': r'[a-zA-Z]+://[-a-zA-Z0-9.]+(?:/[-a-zA-Z0-9+&@#/%=~_|!:,.;]*)?(?:\?[a-zA-Z0-9+&@#/%=~_|!:,.;]*)?',
}

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def Library(name):
    global dLibrary

    try:
        return dLibrary[name]
    except KeyError:
        print('Invalid regex library name: %s' % name)
        print('')
        PrintLibrary()
        sys.exit(-1)

class cREExtra():
    def __init__(self, regex, flags, sensicalPickle='', listsDirectory=''):
        self.regex = regex
        self.flags = flags
        self.listsDirectory = listsDirectory
        self.oRE = re.compile(self.regex, self.flags)
        self.extra = None
        self.conditions = []

        if not self.regex.startswith('(?#extra='):
            return
        iRightParanthesis = regex.find(')')
        if iRightParanthesis == -1:
            raise Exception('Error extra regex comment: 1')
        self.extra = regex[9:iRightParanthesis]
 
        dLists = {os.path.basename(filename):filename for filename in sum(map(glob.glob, [os.path.join(listsDirectory, '*')]), [])}
        for condition in self.extra.split(';'):
            if condition.startswith('S:'):
                if condition[2:] != 'g' and condition[2:] != 's':
                    raise Exception('Error extra regex comment: 3')
                self.conditions.append(cExtraSensical(condition[2:] == 's', sensicalPickle))
            elif condition.startswith('E:'):
                if condition[2:] == '':
                    raise Exception('Error extra regex comment: 4')
                self.conditions.append(cExtraList(False, condition[2:], dLists))
            elif condition.startswith('I:'):
                if condition[2:] == '':
                    raise Exception('Error extra regex comment: 5')
                self.conditions.append(cExtraList(True, condition[2:], dLists))
            elif condition.startswith('P:'):
                if condition[2:] == '':
                    raise Exception('Error extra regex comment: 6')
                self.conditions.append(cExtraPython(condition[2:]))
            else:
                raise Exception('Error extra regex comment: 2')

    def Test(self, data):
        return all([oCondition.Test(data) for oCondition in self.conditions])

    def Findall(self, line):
        found = self.oRE.findall(line)
        results = []
        for result in found:
            if isinstance(result, str):
                if self.Test(result):
                    results.append(result)
            if isinstance(result, tuple):
                results.append(result)
        return results

    def Search(self, line, flags=0):
        oMatch = self.oRE.search(line, flags)
        if oMatch == None:
            return None
        if self.Test(oMatch.group(0)):
            return oMatch
        else:
            return None

def ProcessFile(fIn, fullread):
    if fullread:
        yield fIn.read()
    else:
        for line in fIn:
            yield line.strip('\n')

class cOutput():
    def __init__(self, grepall, filename=None):
        self.grepall = grepall
        self.filename = filename
        self.out = ''
        if self.filename and self.filename != '':
            if self.grepall:
                self.f = open(self.filename, 'wb')
            else:
                self.f = open(self.filename, 'w')
        else:
            self.f = None
            if self.grepall:
                IfWIN32SetBinary(sys.stdout)

    def Line(self, line):
        if self.grepall:
            if self.f:
                self.f.write(line)
            else:
                StdoutWriteChunked(line)
        else:
            if self.f:
                self.f.write(line + '\n')
            else:
                self.out += line + '\n'

    def Close(self):
        if self.f:
            self.f.close()
            self.f = None


class cOutputResult():
    def __init__(self):
        self.oOutput = cOutput(False)
        self.dLines = {}

    def Line(self, line):
        line = IFF(False, lambda: line.lower(), line)
        if not line in self.dLines:
            self.oOutput.Line(line)

    def Close(self):
        self.oOutput.Close()

def CompileRegex(regex):
    regex = IFF(True, lambda: Library(regex), regex)
    regex = IFF(False, '\\b%s\\b' % regex, regex)
    try:
        oREExtra = cREExtra(regex, IFF(False, 0, re.IGNORECASE) + IFF(False, 0, re.DOTALL), '')
    except:
        print('Error regex: %s' % regex)
        raise
    return regex, oREExtra

def RESearchSingle(regex, filename, oOutput):
    regex, oREExtra = CompileRegex(regex)

    fIn = open(filename, IFF(True, 'rb', 'r')) # Fullread
    for line in ProcessFile(fIn, True):
        results = oREExtra.Findall(line)
        for result in results:
            if isinstance(result, str):
                oOutput.Line(result)
            if isinstance(result, tuple):
                oOutput.Line(result[0])
    if fIn != sys.stdin:
        fIn.close()

def RESearch(regex, filenames):
    oOutput = cOutputResult()
    RESearchSingle(regex, filenames, oOutput)
    oOutput.Close()
    return oOutput.oOutput.out

import filecmp
import os


def _increment_filename(filename, marker='-'):
    """
    Returns a generator that yields filenames with a counter. This counter
    is placed before the file extension, and incremented with every iteration.

    For example:

        f1 = increment_filename("myimage.jpeg")
        f1.next() # myimage-1.jpeg
        f1.next() # myimage-2.jpeg
        f1.next() # myimage-3.jpeg

    If the filename already contains a counter, then the existing counter is
    incremented on every iteration, rather than starting from 1.

    For example:

        f2 = increment_filename("myfile-3.doc")
        f2.next() # myfile-4.doc
        f2.next() # myfile-5.doc
        f2.next() # myfile-6.doc

    The default marker is an underscore, but you can use any string you like:

        f3 = increment_filename("mymovie.mp4", marker="_")
        f3.next() # mymovie_1.mp4
        f3.next() # mymovie_2.mp4
        f3.next() # mymovie_3.mp4

    Since the generator only increments an integer, it is practically unlimited
    and will never raise a StopIteration exception.
    """
    # First we split the filename into three parts:
    #
    #  1) a "base" - the part before the counter
    #  2) a "counter" - the integer which is incremented
    #  3) an "extension" - the file extension
    basename, fileext = os.path.splitext(filename)

    # Check if there's a counter in the filename already - if not, start a new
    # counter at 0.
    if marker not in basename:
        base = basename
        value = 0

    # If it looks like there might be a counter, then try to coerce it to an
    # integer to get its value. Otherwise, start with a new counter at 0.
    else:
        base, counter = basename.rsplit(marker, 1)

        try:
            value = int(counter)
        except ValueError:
            base = basename
            value = 0

    # The counter is just an integer, so we can increment it indefinitely.
    while True:
        if value == 0:
            value += 1
            yield filename
        value += 1
        yield '%s%s%d%s' % (base, marker, value, fileext)


def copyfile(src, dst):
    """
    Copies a file from path src to path dst.

    If a file already exists at dst, it will not be overwritten, but:

     * If it is the same as the source file, do nothing
     * If it is different to the source file, pick a new name for the copy that
       is distinct and unused, then copy the file there.

    Returns the path to the copy.
    """
    if not os.path.exists(src):
        raise ValueError('Source file does not exist: {}'.format(src))

    # Create a folder for dst if one does not already exist
    if not os.path.exists(os.path.dirname(dst)):
        os.makedirs(os.path.dirname(dst))

    # Keep trying to copy the file until it works
    while True:

        dst_gen = _increment_filename(dst)
        dst = next(dst_gen)

        # Check if there is a file at the destination location
        if os.path.exists(dst):

            # If the namesake is the same as the source file, then we don't
            # need to do anything else.
            if filecmp.cmp(src, dst):
                return dst

        else:

            # If there is no file at the destination, then we attempt to write
            # to it. There is a risk of a race condition here: if a file
            # suddenly pops into existence after the `if os.path.exists()`
            # check, then writing to it risks overwriting this new file.
            #
            # We write by transferring bytes using os.open(). Using the O_EXCL
            # flag on the dst file descriptor will cause an OSError to be
            # raised if the file pops into existence; the O_EXLOCK stops
            # anybody else writing to the dst file while we're using it.
            try:
                src_fd = os.open(src, os.O_RDONLY)
                dst_fd = os.open(dst,
                                 os.O_WRONLY|os.O_EXCL|os.O_CREAT)

                # Read 100 bytes at a time, and copy them from src to dst
                while True:
                    data = os.read(src_fd, 100)
                    os.write(dst_fd, data)

                    # When there are no more bytes to read from the source
                    # file, 'data' will be an empty string
                    if not data:
                        break

                # If we get to this point, then the write has succeeded
                os.close(src_fd)
                os.close(dst_fd)

                return dst

            # An OSError errno 17 is what happens if a file pops into existence
            # at dst, so we print an error and try to copy to a new location.
            # Any other exception is unexpected and should be raised as normal.
            except OSError as e:
                if e.errno != 17 or e.strerror != 'File exists':
                    raise
                else:
                    print('Race condition: %s just popped into existence' % dst)


        # Copying to this destination path has been unsuccessful, so increment
        # the path and try again
        dst = next(dst_gen)


def unpack_from(fmt, buf, offset=0):
    """Unpack binary data, using struct.unpack(...)"""
    slice = buffer(buf, offset, struct.calcsize(fmt))
    return struct.unpack(fmt, slice)


class lznt1Error(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

def _dCompressBlock(x):
    size = len(x)
    u = ''
    while len(x):

        p = ord(x[0])
        ##print "BLOCK START ", hex(size - len(x)),hex(p),len(u)

        if p == 0: # These are symbol are tokens
            u += x[1:9]
            x = x[9:]
        else:  # There is a phrase token
            idx = 8
            x = x[1:]
            while idx and len(x):
                ustart = len(u)
                #print u[-250:]
                #print "======================================="
                #print "OFFSET ",hex(size - len(x)),ustart,p
                if not (p & 1):
                    u += x[0]
                    x = x[1:]
                else:
                    pt = unpack_from('<H', x)[0]
                    pt = pt & 0xffff
                    #print "PT = %x" % pt
                    i = (len(u)-1)  # Current Pos
                    l_mask = 0xfff
                    p_shift = 12
                    while i >= 0x10:
                        ##print i,l_mask,p_shift
                        l_mask >>= 1
                        p_shift -= 1
                        i >>= 1
                    #print "LMASK %x SHIFT %x" % (l_mask,p_shift)

                    length = (pt & l_mask) + 3
                    bp = (pt  >> p_shift) + 1
                    #print "\n\n\n"
                    #print "BackPtr = %d Len = %d" % (bp,length)

                    if length >= bp:
                        tmp = u[-bp:]
                        while length >= len(tmp):
                            u += tmp
                            length -= len(tmp)
                        u += tmp[:length]
                    else:
                        insert = u[-bp : -bp + length]
                        #print "INSERT <%s>,%d,%d" % (insert,-bp,-bp+length)
                        u = u + insert

                    x = x[2:]
                p >>= 1
                idx -= 1
    return u

def dCompressBuf(blob):
    good = True
    unc = ''
    while good:
        try:
            hdr = blob[0:2]
            blob = blob[2:]

            length = struct.unpack('<H', hdr)[0]
            compressed = ((length&0x8000) == (0x8000))
            length &= 0xfff
            length += 1
            if length > len(blob):
                raise lznt1Error("invalid block len")
                good = False
            else:
                y = blob[:length]
                blob = blob[length:]
                if(compressed):
                    unc += _dCompressBlock(y)
                else:
                    unc +=y
        except:
            good = False

    return unc

def decrypt(data):
    key = data[:8]
    data = data[8:]
    out=''
    for i in range(0,len(data)):
        i_key = i % len(key)
        out += chr(ord(key[i_key])^ord(data[i]))
    pe = dCompressBuf(out)
    return pe

import string

def strings(filename, min=4):
    with open(filename, "rb") as f:           # Python 2.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

def Main():
    global dLibrary

    moredesc = '''

To dump the memory you can use a tool like "Process Explorer", 
from Sysinternals (https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer). 

Then, just pass the filename to the script. You'll only see the 
payload download domains if the Hancitor C2 servers are still alive."
'''

    parser = OptionParser(usage='usage: %prog [options] filename\n' + __description__ + moredesc, version='%prog ' + __version__)
    parser.add_option("-s", "--secure", dest="secure", action='store_true', default=False,
                      help="prints hxxp instead of http for URLs")

    (options, args) = parser.parse_args()

    if len(args) == 0:
        parser.print_help()
    else:
        filename = args[0]
        out = RESearch('url', filename)
        out = out.replace('http', '\nhttp')
        c2 = ''
        payloads = ''
        for line in out.splitlines():
            if re.search(re.compile('/(1\||1|2\||2|3\||3|a1\||a1|22\|22)$'), line):
                payloads += line + '\n'
            elif re.search(re.compile('.+ls5.+\.php'), line):
                c2 += line + '\n'
        
        # Keeping uniques
        c2_aux = set(c2.replace('|', '').split('\n'))
        c2_aux.remove('')
        payloads_aux = set(payloads.replace('|', '').split('\n'))
        payloads_aux.remove('')
        if options.secure:
            print "[+] Hancitor C2 URLs:"
            print "\n".join(sorted(c2_aux)).replace('http', 'hxxp')
            print "[+] Payloads download URLs:"
            print "\n".join(sorted(payloads_aux)).replace('http', 'hxxp')
        else:
            print "[+] Hancitor C2 URLs:"
            print "\n".join(sorted(c2_aux))
            print "[+] Payloads download URLs:"
            print "\n".join(sorted(payloads_aux))

        payloads_base_urls = set()
        options = set()
        for base_url in payloads_aux:
            payloads_base_urls.add(base_url.rsplit('/',1)[0])
            options.add(base_url.rsplit('/',1)[1])

        md5s = set()
        files = []
        print "[+] Starting downloads..."
        if not os.path.exists('payloads'):
            os.makedirs('payloads')
        for i in sorted(payloads_base_urls):
            print "\t[+] Downloading from: " + i.split('/')[2]
            for j in sorted(options):
                print "\t\t[+] " + j + " ",
                try:
                    f = urlopen(i+'/'+j, timeout=4) # Download url
                    # Open our local file for writing
                    with open('payloads/' + i.split('/')[2]+'_'+j, "wb") as local_file:
                        local_file.write(f.read())

                    md5 = hashlib.md5(open('payloads/' + i.split('/')[2] + '_' + j, 'rb').read()).hexdigest()
                    files.append((md5,'payloads/' + i.split('/')[2] + '_' + j))
                    md5s.add(md5)
                    print "Success"

                #handle errors
                except HTTPError, e:
                    print "HTTP Error:", e.code, i+'/'+j
                except URLError, e:
                    print "URL Error:", e.reason, i+'/'+j 

        check = {}
        for i in md5s:
            check[i] = False

        print "[+] Copying unique MD5 files to uniques..."
        if not os.path.exists('uniques'):
            os.makedirs('uniques')
        for i in files: 
            for j in md5s:
                if i[0]==j:
                    if not check[j]:
                        check[j] = True
                        print "\t" + i[0] + " - " + i[1]
                        copyfile(i[1], 'uniques/' + i[1].split('_')[1])

        print "[+] Decrypting Hancitor payloads"
        if not os.path.exists('decrypted'):
            os.makedirs('decrypted')
        for filename in os.listdir('uniques'):
            if os.path.isfile('uniques/' + filename) and os.access('uniques/' + filename, os.R_OK):
                f = open('uniques/' + filename, 'r')
                data = f.read()
                open('decrypted/' + filename + '_decrypted', 'w').write(decrypt(data))
                md5 = hashlib.md5(open('decrypted/' + filename + '_decrypted', 'rb').read()).hexdigest()
                print "\t[+] File " + filename + " decrypted to " + filename + '_decrypted. MD5:' + md5

        #for filename in os.listdir('decrypted'):
        #    if os.path.isfile('decrypted/' + filename) and os.access('decrypted/' + filename, os.R_OK):
        #        print filter(re.compile(".php").match, strings('decrypted/'+filename))

if __name__ == '__main__':
    Main()
