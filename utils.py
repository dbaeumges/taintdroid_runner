################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

import sys

# ================================================================================
# TaintDroid Runner Logger
# ================================================================================

class LogLevel:
    DEV = 0
    DEBUG = 1
    INFO = 2
    ERROR = 3

class LogMode:
    DEFAULT = 0
    ARRAY = 1
    FILE = 2

class ArrayLogFile:
    def __init__(self):
        self.logEntries = []

    def write(self, theMsg):
        self.logEntries.append(theMsg)

class Logger:
    def __init__(self, theLevel=LogLevel.INFO, theMode=LogMode.DEFAULT, theLogFile=None):
        self.level = theLevel
        self.mode = theMode
        self.logFile = theLogFile

        if theMode == LogMode.DEFAULT:
            self.log = sys.stdout
        elif theMode == LogMode.FILE:
            if theLogFile is None:
                raise ValueError('Log file is not set')
            self.log = open(theLogFile, 'a')            
        elif theMode == LogMode.ARRAY:
            self.log = ArrayLogFile()

    def getLevel(self):
        return self.level

    def getLogEntries(self):
        if theMode == LogMode.ARRAY:
            return self.log.logEntries
        else:
            return []

    def isDebug(self):
        return self.level <= LogLevel.DEBUG

    def dev(self, theMsg):
        if self.level <= LogLevel.DEV:
            self.write(theMsg)
        
    def debug(self, theMsg):
        if self.level <= LogLevel.DEBUG:
            self.write(theMsg)

    def info(self, theMsg):
        if self.level <= LogLevel.INFO:
            self.write(theMsg)

    def error(self, theMsg):
        self.write(theMsg)

    def write(self, theMsg):
        self.log.write('%s\n' % theMsg)

# ================================================================================
# TaintDroid Runner Utils Class
# ================================================================================

class Utils:
    @staticmethod
    def getEmulatorPath(theSdkPath):
        if theSdkPath == '':
            return ''
        else:
            return theSdkPath + 'tools/'

    @staticmethod
    def getAdbPath(theSdkPath):
        if theSdkPath == '':
            return ''
        else:
            return theSdkPath + 'platform-tools/'

    @staticmethod
    def getAaptPath(theSdkPath):
        if theSdkPath == '':
            return ''
        else:
            return theSdkPath + 'platform-tools/'

    @staticmethod
    def addSlashToPath(thePath):
        if thePath is None or thePath == '':
            return ''
        if thePath[len(thePath)-1] != '/':
            return thePath + '/'
        else:
            return thePath

    @staticmethod
    def splitFileIntoDirAndName(thePath):
        if len(thePath.rsplit('/', 1)) == 1:
            return [''].extend(thePath.rsplit('/', 1))
        return thePath.rsplit('/', 1)

    @staticmethod
    def getDateAsString(theDate):
        return "%04d%02d%02d" % (theDate.year, theDate.month, theDate.day)


    @staticmethod
    def getTimeAsString(theTime):
        return "%02d%02d%02d" % (theTime.hour, theTime.minute, theTime.second)
