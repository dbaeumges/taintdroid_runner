################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################


# ================================================================================
# TaintDroid Runner Logger
# ================================================================================

class LogLevel:
    DEV = 0
    DEBUG = 1
    INFO = 2
    ERROR = 3

class Logger:
    def __init__(self, theLevel=LogLevel.INFO):
        self.level = theLevel

    def getLevel(self):
        return self.level

    def isDebug(self):
        return self.level <= LogLevel.DEBUG

    def dev(self, theMsg):
        if self.level <= LogLevel.DEV:
            print theMsg
        
    def debug(self, theMsg):
        if self.level <= LogLevel.DEBUG:
            print theMsg

    def info(self, theMsg):
        if self.level <= LogLevel.INFO:
            print theMsg

    def error(self, theMsg):
        print theMsg

    def write(self, theMsg):
        print theMsg

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
        return thePath.rsplit('/', 1)

