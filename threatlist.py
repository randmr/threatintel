#!/usr/bin/python

import requests
import os
import re
import zlib
import time
import sys
import shutil
from datetime import datetime

from time import gmtime, strftime
from netaddr import iprange_to_cidrs
from StringIO import StringIO

destDir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lookups")
procDir = os.path.join(os.environ["SPLUNK_HOME"],"var","run","tmp")

# DO NOT EDIT ANY CONTENT BELOW THIS LINE

foutPath = os.path.join(destDir, "threatlist.csv")
tfoutPath = os.path.join(procDir, "threatlist.temp")

global success
success = True

def logging(content):
        print(str(datetime.now()) + ": " + content)

def errorLogging(content):
        sys.stderr.write(str(datetime.now()) + ": " + content + "\n")
        sys.stderr.flush()

def commit():
        try:
            shutil.copy(tfoutPath, foutPath)
            logging("Commit Success")
        except Exception, e:
            errorLogging("Failed to copy " + tfoutPath + " to " + foutPath + ". Error=\"" + e + "\"")

def formatter(name, category, sev, input):
        try:
                ef_input = zlib.decompress(StringIO(input).read(), zlib.MAX_WBITS|32)
        except Exception, e:
                try:
                        ef_input = zlib.decompress(StringIO(input).read(), -zlib.MAX_WBITS)
                except Exception, e:
                        ef_input = input
        logging(name + ": Extracting Fields")
        extractField(name, category, ef_input, sev)

def extractField(name, category, input, sev):
        global success
        sev = sev.strip()
        lineCount=0
        if category == 'ip':
                for line in StringIO(input):
                        if len(line.strip()) == 0:
                                continue
                        elif "#" in line.strip():
                                continue
                        elif line.strip().startswith("/"):
                                continue
                        elif "/" in line.strip():
                                tf_output.write(line.strip() + "," + name + "(" + sev + ")\n")
                                lineCount += 1
                        else:
                                tf_output.write(line.strip() + "/32," + name + "(" + sev + ")\n")
                                lineCount += 1
                logging("Extract Field Complete: name=" + name + " category=" + category + " sev=" + sev + " entries=" + str(lineCount))
        elif category == 'range':
                for line in StringIO(input):
                        if len(line.strip()) == 0:
                                continue
                        elif "#" in line:
                                continue
                        elif ":" in line:
                                reObj = re.search('(.*):([0-9]+.[0-9]+.[0-9]+.[0-9]+)-([0-9]+.[0-9]+.[0-9]+.[0-9]+).*',line.strip())
                                iprange_start = reObj.group(2)
                                iprange_end = reObj.group(3)
                                ipranges = list(iprange_to_cidrs(iprange_start, iprange_end))
                                for iprange in ipranges:
                                        tf_output.write(str(iprange) + "," + reObj.group(1).replace(",", "") + "(" + sev + ")\n")
                                lineCount += 1
                logging("Extract Field Complete: name=" + name + " category=" + category + " sev=" + sev + " entries=" + str(lineCount))
        elif category == 'col':
                for line in StringIO(input):
                        if len(line.strip()) == 0:
                                continue
                        elif "#" in line:
                                continue
                        elif "Start" in line:
                                continue
                        else:
                                reObj = re.search('([0-9]+.[0-9]+.[0-9]+.[0-9]+)\s+([0-9]+.[0-9]+.[0-9]+.[0-9]+).*',line.strip())
                                iprange_st = reObj.group(1)
                                iprange_ed = reObj.group(2)
                                ipranges = list(iprange_to_cidrs(iprange_st, iprange_ed))
                                for iprange in ipranges:
                                        tf_output.write(str(iprange) + "," + name + "(" + sev + ")\n")
                                lineCount += 1
                logging("Extract Field Complete: name=" + name + " category=" + category + " sev=" + sev + " entries=" + str(lineCount))
        else:
                logging("Extract Field Failure: No category has defined name=" + name + " category=" + category + " sev=" + sev + " input=" + input)
                success = False

def readThreatlist():
        global success
        try:
                threatlist =  open(os.path.join(destDir, 'threatlist.in.csv'), 'rU')
                next(threatlist, None) #skip the headers
                for line in threatlist :
                        cells = line.split(",")
                        try:
                                req = requests.get(cells[1], allow_redirects=True)
                                if req.status_code != requests.codes.ok:
                                    errorLogging("listName=" + cells[0] + ": Did not download. Error=" + str(req.status_code))
                                    continue
                                formatter(cells[0], cells[2], cells[3], req.content)
                                req = None
                        except requests.exceptions.ConnectionError as e:
                                errorLogging("listName=" + cells[0] + ": Download request failed. Error=\"" + str(e) + "\"")
                                # threatlist+=e+","
                        except IndexError as ie:
                                print 'Skip line: ' + cells
                        time.sleep(3)
                threatlist.close()
                logging("Read Threat list Success")
        except (OSError, IOError) as e:
                errorMsg = str(e)
                errorLogging("Read Threat List Failure: " + errorMsg)
                success = False
                logging("Read Threat List Failure: " + errorMsg)

def readcustomlist():
        if os.path.isfile(os.path.join(destDir, 'customlist.csv')):
            try:
                customlist = open(os.path.join(destDir,'customlist.csv'),'rU')
                next(customlist, None)
                for line in customlist :
                        tf_output.write(line)
                customlist.close()
                logging("Read custom list Success")
            except (OSError, IOError) as e:
                errorMsg = str(e)
                errorLogging("Read custom list Failure: " + errorMsg)

tf_output = open(tfoutPath, 'w')
tf_output.write("iprange,threat\n")

logging("Start")

readThreatlist()
readcustomlist()

tf_output.flush()
tf_output.close()

if success:
        commit()
        os.remove(tfoutPath)
else:
        os.remove(tfoutPath)
        logging("Commit is not performed due to unsuccessful threatlist download")
        errorLogging("Commit is not performed due to unsuccessful threatlist download")

logging("End")
