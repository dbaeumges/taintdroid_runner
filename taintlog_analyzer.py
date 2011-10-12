################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

from taintlog_json import *
from utils import Logger, LogLevel

import re


# ================================================================================
# TaintLog Analyzer Error Obejct
# ================================================================================ 
class TainLogAnalyzerError(Exception):  
    def __init__(self, theValue):
        self.value = theValue

    def __str__(self):
        return repr(self.value)


# ================================================================================
# Log Analyzer
# ================================================================================ 
class TaintLogAnalyzer:
    def __init__(self, theLogger=Logger()):
        self.log = theLogger

        self.jsonFactory = JsonFactory()
        
        self.logLines = []
        self.logEntryList = []
        self.json2pyFailedList = []

        self.numControlChars = 0

    def setLogFile(self, theFile):
        """
        Sets the log lines from the provided file
        """
        logFile = open(theFile, 'r')
        for line in logFile:
            self.logLines.append(line)
        self.numControlChars = 2

    def setLogString(self, theStr):
        """
        Sets the log lines from the provided string splitted by \r\n
        """
        self.logLines = theStr.split('\r\n')
        self.numControlChars = 0

    def getLogEntryList(self):
        """
        Returns the extracted log objects.
        extractLogObjects need to be run before
        """
        return self.logEntryList

    def getJson2PyFailedList(self):
        """
        Returns the list of JSON strings which couldn't
        be converted into LogEntries.
        """
        return self.json2pyFailedList
        
    def extractLogEntries(self):
        """
        Extract JSON objects out of the log lines.
        setLogFile(<file>) or setLogString(<string>) need to be run before
        """
        # Init regex
        regexBegin = 'W/dalvikvm\([ 0-9]{5}\): TaintLog: \['
        regexGoOn = 'W/dalvikvm\([ 0-9]{5}\): '
        
        # Extract JSON strings
        self.log.info('Extract JSON string lines')
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
                        self.log.debug('Found JSON string: \'%s\'\n' % jsonString)
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
                        self.log.debug('Found JSON string: \'%s\'\n' % jsonString)
                else:
                    self.log.info('Warning: Do not find line match even though it was expected\n')

        # Extract JSON objects
        self.logEntryList = []
        self.json2pyFailedList = []
        self.log.info('Extract JSON objects')
        for jsonString in jsonStringVec:
            self.log.dev(jsonString)
            try:
                self.logEntryList.extend(self.jsonFactory.json2Py(jsonString))
            except Exception, ex:
                self.json2pyFailedList.append(jsonString)
                self.log.error('Conversion for JSON string \'%s\' failed: %s.' % (jsonString, str(ex)))

    def postProcessLogObjects(self, theDeleteFileDescriptorsFlag=True):
        """
        CleanUp log objects:
        - Generate stack trace vector
        - Set file path for OSFileAccess
        """
        for logEntry in self.logEntryList:
            # Stack trace vec
            if isinstance(logEntry, FileSystemLogEntry) or isinstance(logEntry, NetworkSendLogEntry):
                stackTrace = logEntry.stackTraceStr.split('||')
                logEntry.stackTrace = stackTrace[:len(stackTrace)-1]
                
            # File descriptor
            if isinstance(logEntry, FileSystemLogEntry):
                for logEntry2 in self.logEntryList:
                    if isinstance(logEntry2, FileDescriptorLogEntry):
                        if logEntry.fileDescriptor == logEntry2.fileDescriptor:
                            logEntry.filePath = logEntry2.path
                            break

        if theDeleteFileDescriptorsFlag:
            i = 0
            while i < len(self.logEntryList):
                if isinstance(self.logEntryList[i], FileDescriptorLogEntry):
                    del self.logEntryList[i]
                else:
                    i += 1
                

    def printOverview(self):
        """
        Print overview.
        FileDescriptorObjects need to be deleted before
        """
        for logEntry in self.logEntryList:
            self.log.write(logEntry.getOverviewLogStr())


# ================================================================================
# Main method
# ================================================================================
def main():
    # Parse options
    parser = OptionParser(usage='usage: %prog [options] logFile', version='%prog 0.1')    
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=True)
    parser.add_option('-q', '--quiet', action='store_false', dest='verbose')
    (options, args) = parser.parse_args()

    # Run
    if options.verbose:
        logger = Logger(LogLevel.DEBUG)
    else:
        logger = Logger()
    logAnalyzer = TaintLogAnalyzer(theLogger=logger)
    logAnalyzer.setLogFile(args[0])
    logAnalyzer.extractLogEntries()
    logAnalyzer.postProcessLogObjects()
    logAnalyzer.printOverview()

if __name__ == '__main__':
    main()
    
