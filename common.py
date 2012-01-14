################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

import os
import sys

# ================================================================================
# TaintDroid Enums
# ================================================================================

class TaintLogActionEnum:
    FS_READ_ACTION           = 0x00000001
    FS_READ_DIRECT_ACTION    = 0x00000002
    FS_READV_ACTION          = 0x00000004
    FS_WRITE_ACTION          = 0x00000008
    FS_WRITE_DIRECT_ACTION   = 0x00000010
    FS_WRITEV_ACTION         = 0x00000020

    NET_READ_ACTION          = 0x00000100
    NET_READ_DIRECT_ACTION   = 0x00000200
    NET_RECV_ACTION          = 0x00000400
    NET_RECV_DIRECT_ACTION   = 0x00000800
    NET_SEND_ACTION          = 0x00001000
    NET_SEND_DIRECT_ACTION   = 0x00002000
    NET_SEND_URGENT_ACTION   = 0x00004000
    NET_WRITE_ACTION         = 0x00008000
    NET_WRITE_DIRECT_ACTION  = 0x00010000

    SSL_READ_ACTION          = 0x00020000
    SSL_WRITE_ACTION         = 0x00040000

    SMS_ACTION               = 0x00100000 
    SMS_MULTIPART_ACTION     = 0x00200000 
    SMS_DATA_ACTION          = 0x00400000

    CIPHER_ACTION            = 0x00800000
    ERROR_ACTION             = 0x01000000
    CALL_ACTION              = 0x02000000

    @staticmethod
    def getActionString(theAction):
        if theAction == TaintLogActionEnum.FS_READ_ACTION:
            actionString = 'read'
        elif theAction == TaintLogActionEnum.FS_READ_DIRECT_ACTION:
            actionString = 'readDirect'
        elif theAction == TaintLogActionEnum.FS_READV_ACTION:
            actionString = 'readv'
        elif theAction == TaintLogActionEnum.FS_WRITE_ACTION:
            actionString = 'write'
        elif theAction == TaintLogActionEnum.FS_WRITE_DIRECT_ACTION:
            actionString = 'writeDirect'
        elif theAction == TaintLogActionEnum.FS_WRITEV_ACTION:
            actionString = 'writev'

        elif theAction == TaintLogActionEnum.NET_READ_ACTION:
            actionString = 'read'
        elif theAction == TaintLogActionEnum.NET_READ_DIRECT_ACTION:
            actionString = 'readDirect'
        elif theAction == TaintLogActionEnum.NET_RECV_ACTION:
            actionString = 'recv'
        elif theAction == TaintLogActionEnum.NET_RECV_DIRECT_ACTION:
            actionString = 'recvDirect'
        elif theAction == TaintLogActionEnum.NET_SEND_ACTION:
            actionString = 'send'
        elif theAction == TaintLogActionEnum.NET_SEND_DIRECT_ACTION:
            actionString = 'sendDirect'
        elif theAction == TaintLogActionEnum.NET_SEND_URGENT_ACTION:
            actionString = 'sendUrgentData'
        elif theAction == TaintLogActionEnum.NET_WRITE_ACTION:
            actionString = 'write'
        elif theAction == TaintLogActionEnum.NET_WRITE_DIRECT_ACTION:
            actionString = 'writeDirect'

        elif theAction == TaintLogActionEnum.SSL_READ_ACTION:
            actionString = 'read'
        elif theAction == TaintLogActionEnum.SSL_WRITE_ACTION:
            actionString = 'write'

        elif theAction == TaintLogActionEnum.SMS_ACTION:
            actionString = 'sms'
        elif theAction == TaintLogActionEnum.SMS_MULTIPART_ACTION:
            actionString = 'multipartSms'
        elif theAction == TaintLogActionEnum.SMS_DATA_ACTION:
            actionString = 'dataSms'

        elif theAction == TaintLogActionEnum.CIPHER_ACTION:
            actionString = 'cipher'
        elif theAction == TaintLogActionEnum.ERROR_ACTION:
            actionString = 'error'

        else:
            actionString = 'invalid (%d)' % theAction

        return actionString
    

class SimulationSteps:
    INSTALL             = 1
    START               = 2
    MONKEY_BEFORE_GSM   = 4
    GSM                 = 8
    MONKEY_BEFORE_GEO   = 16
    GEO                 = 32
    MONKEY_BEFORE_SMS   = 64
    SMS                 = 128
    MONKEY_BEFORE_POWER = 256
    POWER               = 2512    
    MONKEY              = 1024
    SLEEP               = 2048
    WAIT_FOR_RAW_INPUT  = 4096

    @staticmethod
    def getStepsAsString(theSteps):
        stepString = str(theSteps) + ' ('
        if theSteps & SimulationSteps.INSTALL:
            stepString += 'Install, '
        if theSteps & SimulationSteps.START:
            stepString += 'Start, '
        if theSteps & SimulationSteps.MONKEY_BEFORE_GSM:
            stepString += 'Monkey Before GSM, '
        if theSteps & SimulationSteps.GSM:
            stepString += 'GSM, '
        if theSteps & SimulationSteps.MONKEY_BEFORE_GEO:
            stepString += 'Monkey Before GEO, '
        if theSteps & SimulationSteps.GEO:
            stepString += 'GEO, '
        if theSteps & SimulationSteps.MONKEY_BEFORE_SMS:
            stepString += 'Monkey Before SMS, '
        if theSteps & SimulationSteps.SMS:
            stepString += 'SMS, '
        if theSteps & SimulationSteps.MONKEY_BEFORE_POWER:
            stepString += 'Monkey Before Power, '
        if theSteps & SimulationSteps.POWER:
            stepString += 'Power, '
        if theSteps & SimulationSteps.MONKEY:
            stepString += 'Monkey, '
        if theSteps & SimulationSteps.SLEEP:
            stepString += 'Sleep, '
        if theSteps & SimulationSteps.WAIT_FOR_RAW_INPUT:
            stepString += 'Wait For Input, '
        if stepString[-2:] == ') ':
            stepString = stepString[:-2]
        elif stepString[-2:] == ', ':
            stepString = stepString[:-2] + ')'
        return stepString
    

class TaintLogKeyEnum:
    GLOBAL_ACTIVE_KEY          = "tdroid.global.active"
    GLOBAL_SKIP_LOOKUP_KEY     = "tdroid.global.skiplookup"
    GLOBAL_ACTION_MASK_KEY     = "tdroid.global.actionmask"
    GLOBAL_TAINT_MASK_KEY      = "tdroid.global.taintmask"
    FS_LOG_TIMESTAMP_KEY       = "tdroid.fs.logtimestamp"
    
    
class TaintTagEnum:
    TAINT_CLEAR		= 0x0
    TAINT_LOCATION	= 0x1       
    TAINT_CONTACTS	= 0x2
    TAINT_MIC           = 0x4
    TAINT_PHONE_NUMBER  = 0x8
    TAINT_LOCATION_GPS  = 0x10
    TAINT_LOCATION_NET  = 0x20
    TAINT_LOCATION_LAST = 0x40
    TAINT_CAMERA        = 0x80
    TAINT_ACCELEROMETER = 0x100
    TAINT_SMS           = 0x200
    TAINT_IMEI          = 0x400
    TAINT_IMSI          = 0x800
    TAINT_ICCID         = 0x1000
    TAINT_DEVICE_SN     = 0x2000
    TAINT_ACCOUNT       = 0x4000
    TAINT_HISTORY       = 0x8000
    TAINT_INCOMING_DATA = 0x10000
    TAINT_USER_INPUT    = 0x20000
    TAINT_MEDIA         = 0x40000

    @staticmethod
    def appendTaintTags(theTag1, theTag2):
        tagInt1 = int(theTag1, 16)
        tagInt2 = int(theTag2, 16)
        tagInt = tagInt1 | tagInt2
        tag = "0x%X" % tagInt
        return tag

    @staticmethod
    def getTaintString(theTag):
        tagInt = int(theTag, 16)
        tagString = str(theTag) + ' ('
        if tagInt == TaintTagEnum.TAINT_CLEAR:
            tagString += 'No Tag)'
        else:
            if tagInt & TaintTagEnum.TAINT_LOCATION:
                tagString += 'Location, '
            if tagInt & TaintTagEnum.TAINT_CONTACTS:
                tagString += 'Contact, '
            if tagInt & TaintTagEnum.TAINT_MIC:
                tagString += 'Microphone, '
            if tagInt & TaintTagEnum.TAINT_PHONE_NUMBER:
                tagString += 'Phone Number, '
            if tagInt & TaintTagEnum.TAINT_LOCATION_GPS:
                tagString += 'GPS Location, '
            if tagInt & TaintTagEnum.TAINT_LOCATION_NET:
                tagString += 'Net Location, '
            if tagInt & TaintTagEnum.TAINT_LOCATION_LAST:
                tagString += 'Last Location, '
            if tagInt & TaintTagEnum.TAINT_CAMERA:
                tagString += 'Camera, '
            if tagInt & TaintTagEnum.TAINT_ACCELEROMETER:
                tagString += 'Accelerometer, '
            if tagInt & TaintTagEnum.TAINT_SMS:
                tagString += 'SMS, '
            if tagInt & TaintTagEnum.TAINT_IMEI:
                tagString += 'IMEI, '
            if tagInt & TaintTagEnum.TAINT_IMSI:
                tagString += 'IMSI, '
            if tagInt & TaintTagEnum.TAINT_ICCID:
                tagString += 'ICCID, '
            if tagInt & TaintTagEnum.TAINT_DEVICE_SN:
                tagString += 'Device SN, '
            if tagInt & TaintTagEnum.TAINT_ACCOUNT:
                tagString += 'Account ,'  
            if tagInt & TaintTagEnum.TAINT_HISTORY:
                tagString += 'History, '
            if tagInt & TaintTagEnum.TAINT_INCOMING_DATA:
                tagString += 'Incoming, '
            if tagInt & TaintTagEnum.TAINT_USER_INPUT:
                tagString += 'UserInput, '
            if tagInt & TaintTagEnum.TAINT_MEDIA:
                tagString += 'Media, '
        if tagString[-2:] == ') ':
            tagString = tagString[:-2]
        elif tagString[-2:] == ', ':
            tagString = tagString[:-2] + ')'
        return tagString

    
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
    def __init__(self, theLevel=LogLevel.INFO, theMode=LogMode.DEFAULT, theLogFile=None, thePrintAlwaysFlag=False):
        self.level = theLevel
        self.mode = theMode
        self.logFile = theLogFile
        self.printAlwaysFlag = thePrintAlwaysFlag

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
            self.__writeInternal(theMsg)
        
    def debug(self, theMsg):
        if self.level <= LogLevel.DEBUG:
            self.__writeInternal(theMsg)

    def info(self, theMsg):
        if self.level <= LogLevel.INFO:
            self.__writeInternal(theMsg)

    def error(self, theMsg):
        self.__writeInternal('Error: %s' % theMsg)        
            
    def write(self, theMsg):
        self.__writeInternal(theMsg)

    def __writeInternal(self, theMsg):
        self.log.write('%s\n' % theMsg)
        if self.printAlwaysFlag:
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
        if thePath is None: return ['', '']
        if len(thePath.rsplit('/', 1)) == 1:
            return [''].extend(thePath.rsplit('/', 1))
        return thePath.rsplit('/', 1)

    @staticmethod
    def getDateAsString(theDate):
        return "%04d%02d%02d" % (theDate.year, theDate.month, theDate.day)


    @staticmethod
    def getTimeAsString(theTime):
        return "%02d%02d%02d" % (theTime.hour, theTime.minute, theTime.second)

    @staticmethod
    def _getAppListInDirectory(theDir):
        """
        Returns the list of all .apk files within one directory.
        """
        appList = []
        for root, dirs, files in os.walk(theDir):
            for fileName in files:
                if fileName.find('.apk') != -1:
                    appList.append(os.path.join(root, fileName))
        return appList
