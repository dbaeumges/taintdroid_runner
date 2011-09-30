################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

import codecs
import re
from taintlog_json import *

# ================================================================================
# Log Analyzer
# ================================================================================ 
class TaintLogAnalyzer:
    def __init__(self, theVerboseFlag=True):
        self.verbose = theVerboseFlag

        self.jsonFactory = JsonFactory()
        
        self.logLines = []
        self.logEntries = []

        self.numControlChars = 0

    def setLogFile(self, theFile):
        """
        Sets the log lines from the provided file
        """
        logFile = open(theFile, 'r')
        for line in logFile:
            #if line[len(line)-2:] == '\r\n':
            #    self.logLines.append(line[:len(line)-2])
            #elif line[len(line)-1] == '\n':
            #    self.logLines.append(line[:len(line)-1])
            #elif line[len(line)-1] == '\r':
            #    self.logLines.append(line[:len(line)-1])
            #else:
            self.logLines.append(line)
        self.numControlChars = 2

    def setLogString(self, theStr):
        """
        Sets the log lines from the provided string splitted by \r\n
        """
        self.logLines = theStr.split('\r\n')
        self.numControlChars = 0

    def getLogEntries(self):
        """
        Returns the extracted log objects.
        extractLogObjects need to be run before
        """
        return self.logEntries

    def setLogEntries(self, theLogEntries):
        """
        Sets the log objects
        """
        self.logEntries = theLogEntries
        
    def extractLogEntries(self):
        """
        Extract JSON objects out of the log lines.
        setLogFile(<file>) or setLogString(<string>) need to be run before
        """
        # Init regex
        regexBegin = 'W/dalvikvm\([ 0-9]{5}\): TaintLog: \['
        regexGoOn = 'W/dalvikvm\([ 0-9]{5}\): '
        
        # Extract JSON strings
        if self.verbose:
            print 'Extract JSON string lines'
        jsonStringVec = []
        jsonString = ''
        jsonStartFound = False
        for line in self.logLines:
            # Find start
            if not jsonStartFound:
                regexMatch = re.match(regexBegin, line)
                if not regexMatch is None:
                    jsonStartFound = True
                    
                    # Check for end in same line
                    if line[len(line)-1] == ']' or line[len(line)-2] == ']' or line[len(line)-3] == ']':
                        jsonString = line[regexMatch.end()-1:len(line)]
                        jsonStringVec.append(jsonString)
                        jsonStartFound = False                    
                        if self.verbose:
                            print "Found JSON string: '%s'\n" % jsonString
                    else:
                        jsonString = line[regexMatch.end()-1:len(line)-self.numControlChars] # remove control chars at the end

            # Find end
            else: # jsonStartFound
                regexMatch = re.match(regexGoOn, line)
                if not regexMatch is None:
                    partString = line[regexMatch.end():len(line)-self.numControlChars] # remove control chars at the end
                    jsonString = jsonString + partString
                    if line[len(line)-1] == ']' or line[len(line)-2] == ']' or line[len(line)-3] == ']':                        
                        jsonStringVec.append(jsonString)
                        jsonStartFound = False
                        if self.verbose:
                            print "Found JSON string: '%s'\n" % jsonString
                else:
                    print "Warning: Do not find line match even though it was expected\n"

        # Extract JSON objects
        self.logEntries = []
        if self.verbose:
            print 'Extract JSON objects'
        for jsonString in jsonStringVec:
            print jsonString
            self.logEntries.extend(self.jsonFactory.json2Py(jsonString))

    def cleanUpLogObjects(self, theDeleteFileDescriptorsFlag=True):
        """
        CleanUp log objects:
        - Generate stack trace vector
        - Set file path for OSFileAccess
        """
        for logEntry in self.logEntries:
            # Stack trace vec
            if isinstance(logEntry, FileSystemLogEntry) or isinstance(logEntry, NetworkSendLogEntry):
                stackTrace = logEntry.stackTraceStr.split('||')
                logEntry.stackTrace = stackTrace[:len(stackTrace)-1]
                
            # File descriptor
            if isinstance(logEntry, FileSystemLogEntry):
                for logEntry2 in self.logEntries:
                    if isinstance(logEntry2, FileDescriptorLogEntry):
                        if logEntry.fileDescriptor == logEntry2.fileDescriptor:
                            logEntry.filePath = logEntry2.path
                            break

        if theDeleteFileDescriptorsFlag:
            i = 0
            while i < len(self.logEntries):
                if isinstance(self.logEntries[i], FileDescriptorLogEntry):
                    del self.logEntries[i]
                else:
                    i += 1
                

    def printOverview(self):
        """
        Print overview.
        FileDescriptorObjects need to be deleted before
        """
        for logEntry in self.logEntries:
            print logEntry.getOverviewLogStr()
