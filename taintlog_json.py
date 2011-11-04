################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

import json


# ================================================================================
# Enum Classes
# ================================================================================
class CipherActionEnum:
    INIT_ACTION = 'init'
    UPDATE_ACTION = 'update'
    DO_FINAL_ACTION = 'doFinal'
    CLEANED = 'cleaned'

class CipherModeEnum:
    ENCRYTP_MODE = 1
    DECRYPT_MODE = 2
    
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
        if tagString[len(tagString)-2:] == ') ':
            tagString = tagString[:len(tagString)-2]
        elif tagString[len(tagString)-2:] == ', ':
            tagString = tagString[:len(tagString)-2] + ')'
        return tagString

    
# ================================================================================
# Json Objects
# ================================================================================

class BaseLogEntry:
    _json = True
    
    def __init__(self, **keys):
        self.__dict__.update(keys)
        
    def append(self, name, value):
        setdefault(self.__dict__, name, []).append(value)
        
    def insert(self, name, index, value):
        setdefault(self.__dict__, name, []).insert(index, value)
        
    def update(self, name, **keys):
        setdefault(self, name, {}).update(keys) 

class FileDescriptorLogEntry(BaseLogEntry):
    """
    """
    fileDescriptor = 0
    path = ''

class CipherUsageLogEntry(BaseLogEntry):
    """
    """
    action = '' # CipherActionEnum
    id = 0    
    mode = 0 # CipherModeEnum
    tag = TaintTagEnum.TAINT_CLEAR
    input = ''
    output = ''
    stackTraceStr = ''
    stackTrace = [] # filled by postProcess
    timestamp = ''
    
    def getOverviewLogStr(self):
        return 'CipherUsage (%s), id: %d, tag: %s, mode: %d' % (self.action, self.id, TaintTagEnum.getTaintString(self.tag), self.mode)
        
class FileSystemLogEntry(BaseLogEntry):
    """
    """
    action = ''
    tag = TaintTagEnum.TAINT_CLEAR
    fileDescriptor = 0
    filePath = '' # filled by postProcess
    data = ''
    stackTraceStr = ''    
    stackTrace = [] # filled by postProcess
    timestamp = ''

    def getOverviewLogStr(self):
        return 'FileSystemAccess (%s), tag: %s, file: %s (%d)' % (self.action, TaintTagEnum.getTaintString(self.tag), self.filePath, self.fileDescriptor)
    
class NetworkSendLogEntry(BaseLogEntry):
    """
    """
    action = ''
    tag = TaintTagEnum.TAINT_CLEAR
    destination = ''
    port = 0
    data = ''
    stackTraceStr = ''
    stackTrace = [] # filled by postProcess
    timestamp = ''
    
    def getOverviewLogStr(self):
        return 'NetworkAccess (%s), tag: %s, destination: %s:%d' % (self.action, TaintTagEnum.getTaintString(self.tag), self.destination, self.port)

class SendSmsLogEntry(BaseLogEntry):
    """
    """
    action = ''
    tag = TaintTagEnum.TAINT_CLEAR
    destination = ''
    scAddress = ''
    text = ''
    stackTraceStr = ''
    stackTrace = [] # filled by postProcess
    timestamp = ''
    
    def getOverviewLogStr(self):
        return 'NetworkAccess (%s), tag: %s, destination: %s' % (self.action, TaintTagEnum.getTaintString(self.tag), self.destination)


# ================================================================================
# Json En-/Decoder
# ================================================================================

class _JSONEncoder(json.JSONEncoder):
    def default(self, theObject):
        if hasattr(theObject, '_json'):
            res = {}
            if theObject._json == True:
                for key in theObject.__dict__:
                    if not key.startswith('_'):
                        res[key] = theObject.__dict__[key]
            else:
                for key in theObject._json:
                    res[key] = theObject.__dict__[key]
            res['__' + theObject.__class__.__name__ + '__'] = True
            return res
        return json.JSONEncoder.default(self, theObject)

def _JSONDecoder(theDict):
    object = None
    type = None

    for type in theDict.keys():
        if type.startswith("__"):
            break
    if type == None: return theDict

    if '__CipherUsageLogEntry__' == type:
        object = CipherUsageLogEntry()
    elif '__FileDescriptorLogEntry__' == type:
        object = FileDescriptorLogEntry()
    elif '__FileSystemObject__' == type:
        object = FileSystemLogEntry()
    elif '__NetworkSendLogEntry__' == type:
        object = NetworkSendLogEntry()
    elif '__SendSmsLogEntry__' == type:
        object = SendSmsLogEntry()
    else:
        raise Exception('Unkown type \'%s\' found' % type)

    if not object: return theDict

    object.__dict__.update(theDict)

    return object


# ================================================================================
# Json Factory
# ================================================================================ 

class JsonFactory:
    def py2Json(self, theObject, theIndentFlag=False):
        if theIndentFlag:
            return json.dumps(theObject, cls=_JSONEncoder, indent=2, sort_keys=True)
        else:
            return json.dumps(theObject, cls=_JSONEncoder, sort_keys=True)

    def json2Py(self, theString):
        return json.loads(theString, object_hook=_JSONDecoder)