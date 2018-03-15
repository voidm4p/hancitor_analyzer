#!/usr/bin/env python

__description__ = "Program to find all Hancitor IOCs, including grabbing and decoding the additional payloads, everything, from the initial doc dropper."
__author__ = 'voidm4p'
__version__ = '0.0.1'
__date__ = '2017/11/21'

"""
Special thanks to: Unit 42 (Palo Alto)
"""

import sys
import os
import re
import subprocess
import urllib2
import base64
import hashlib
import struct
import socket

###### AUX
from random import randint

def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

import string
import random
def id_generator(size=6, chars=string.ascii_uppercase):
    return ''.join(random.choice(chars) for _ in range(size))

from random import randrange
 
def generateIP():
    not_valid = [10,127,169,172,192]
 
    first = randrange(1,256)
    while first in not_valid:
        first = randrange(1,256)
 
    ip = ".".join([str(first),str(randrange(1,256)),
    str(randrange(1,256)),str(randrange(1,256))])
    return ip

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
######

h_decrypt = os.path.join(os.getcwd(), os.path.dirname(os.path.realpath(__file__)) + "/../external/pan-unit42/hancitor/h_decrypt.py")
output = ''

try:
    output += subprocess.check_output('{} {} {}'.format('python', h_decrypt, sys.argv[1] + '; exit 0'), shell=True, stderr=subprocess.STDOUT)
except subprocess.CalledProcessError as e:
    pass

print "[1] UNIT 42 SCRIPT"
print "------------------"
print output
print "------------------"
print "[2] TRYING C2 CONNECTION"

url_regex = re.compile('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
build_regex = re.compile("Hancitor Build Number '[\w\d]+'")

c2s = url_regex.findall(output.replace('hxxp', 'http'))
success = False
payloads_aux = set()
for c2 in c2s:
    print '\t[-] ' + c2.replace('http', 'hxxp')
    try:
        #guid = random_with_N_digits(20)
        guid=13846781925070929928
        build = build_regex.findall(output)[0].split("'")[1]
        machine = id_generator(5)
        username = id_generator(3)
        ip = generateIP()
        windows = ['10.0', '6.3', '6.2', '6.1'][3]
        d = 'GUID=%i&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%s(x32)' % (guid, build, machine + ' @ ' + machine + '\\' + username, ip, windows)
        print '\t[-] Param: ' + d
        req = urllib2.Request(c2)
        req.add_header('User-agent', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko')
        req.add_header('Content-type', 'application/x-www-form-urlencoded')
        f = urllib2.urlopen(req, timeout=4, data=d) # trying POST request to C2
        # Open our local file for writing
        
        print "\t\t[!] Success. Answer:"
        answer = f.read()
        print answer

        # C2 decrypt: https://www.carbonblack.com/2016/11/23/calendar-reminder-youre-infected-hancitor-malware/
        if ((0x9B - ord(answer[0])) == ord(answer[3]) and (0x9B - ord(answer[1])) == ord(answer[2])):
            decoded = base64.b64decode(answer[4:])
            answer_decoded = ''
            for x in decoded:
                answer_decoded = answer_decoded + chr(ord(x) ^ 0x7A)

            print "\t\t[!] Answer decoded:"
            print answer_decoded.replace('http', 'hxxp')

            for payload_url in url_regex.findall(answer_decoded):
                payloads_aux.add(payload_url)

            success = True
        else:
            decoded_c2_answers.append('')
            print "\nFailed to verify server comms"

    #handle errors
    except urllib2.HTTPError, e:
        print "\t\t[!] HTTP Error:", e.code
    except urllib2.URLError, e:
        print "\t\t[!] URL Error:", e.reason
    except socket.error as socketerror:
        print "\t\t[!] Error: ", socketerror

if success:
    print "[*] At least one C2 is alive. Continue..."
else:
    print "[*] No C2 alives anymore. Exiting..."
    exit(-1)

if len(payloads_aux) == 0:
    print "[*] No payloads URLs received. Exiting..."
    exit(-1)
payloads_base_urls = set()
options = set()
for base_url in payloads_aux:
    payloads_base_urls.add(base_url.rsplit('/',1)[0])
    options.add(base_url.rsplit('/',1)[1])

md5s = set()
files = []
print "------------------"
print "[3] STARTING PAYLOADS DOWNLOAD"
print "------------------"
if not os.path.exists('payloads'):
    os.makedirs('payloads')
for i in sorted(payloads_base_urls):
    print "[+] Downloading from: " + i.split('/')[2]
    for j in sorted(options):
        print "\t[+] " + j + " ",
        try:
            f = urllib2.urlopen(i+'/'+j, timeout=4) # Download url
            # Open our local file for writing
            with open('payloads/' + i.split('/')[2]+'_'+j, "wb") as local_file:
                local_file.write(f.read())

            md5 = hashlib.md5(open('payloads/' + i.split('/')[2] + '_' + j, 'rb').read()).hexdigest()
            files.append((md5,'payloads/' + i.split('/')[2] + '_' + j))
            md5s.add(md5)
            print "Success"

        #handle errors
        except urllib2.HTTPError, e:
            print "HTTP Error:", e.code, i+'/'+j
        except urllib2.URLError, e:
            print "URL Error:", e.reason, i+'/'+j

check = {}
for j in md5s:
    check[j] = False

print "[+] Copying unique MD5 files to uniques..."
if not os.path.exists('uniques'):
    os.makedirs('uniques')
for i in files: 
    for j in md5s:
        if i[0]==j:
            if not check[j]:
                check[j] = True
                print "\t" + i[0] + " - " + i[1]
                copyfile(i[1], 'uniques/' + i[1].split('/')[1])

print "[+] Decrypting Hancitor payloads"
if not os.path.exists('decrypted'):
    os.makedirs('decrypted')
for filename in os.listdir('uniques'):
    if os.path.isfile('uniques/' + filename) and os.access('uniques/' + filename, os.R_OK):
        f = open('uniques/' + filename, 'r')
        data = f.read()
        open('decrypted/' + filename + '_decrypted', 'w').write(decrypt(data))
        md5 = ''
        fb = open('decrypted/' + filename + '_decrypted',"rb")

        magic_header = fb.read(2)
        if magic_header == "MZ":
            md5 = hashlib.md5(fb.read()).hexdigest()
            print "\t[+] File " + filename + " is PE Executable. Decrypted to " + filename + '_decrypted. MD5:' + md5
        else:
            md5 = hashlib.md5(open('uniques/' + filename, 'rb').read()).hexdigest()
            print "\t[+] File " + filename + " is not PE Executable. Just copied original. MD5:" + md5
            os.remove('decrypted/' + filename + '_decrypted')
            copyfile('uniques/' + filename, 'decrypted/' + filename)
