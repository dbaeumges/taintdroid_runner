################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

from common import TaintLogActionEnum, TaintTagEnum
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
    ENCRYPT_MODE = 1
    DECRYPT_MODE = 2


# ================================================================================
# Json Base Class
# ================================================================================
class JsonBase:
    _json = True
    
    def __init__(self, **keys):
        self.__dict__.update(keys)
        
    def append(self, name, value):
        setdefault(self.__dict__, name, []).append(value)
        
    def insert(self, name, index, value):
        setdefault(self.__dict__, name, []).insert(index, value)
        
    def update(self, name, **keys):
        setdefault(self, name, {}).update(keys) 


# ================================================================================
# Json Log Objects (comming from TaintDroid)
# ================================================================================
class BaseLogEntry(JsonBase):
    pass

class ErrorLogEntry(BaseLogEntry):
    """
    """
    message = ''
    stackTraceStr = ''
    stackTrace = [] # filled by postProcess
    timestamp = ''

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

    def getHtmlReportColumnList(self):
        columnList = [TaintTagEnum.getTaintString(self.tag)]
        if self.mode == CipherModeEnum.ENCRYPT_MODE:
            columnList.append('encrypt')
            columnList.append(self.input)
        else:
            columnList.append('decrypt')
            columnList.append(self.output)
        columnList.append(self.timestamp)
        columnList.append(self.stackTraceStr)
        return columnList
        
class FileSystemLogEntry(BaseLogEntry):
    """
    """
    action = 0 # TaintLogActionEnum.FS_*
    tag = TaintTagEnum.TAINT_CLEAR
    fileDescriptor = 0
    filePath = '' # filled by postProcess
    data = ''
    stackTraceStr = ''    
    stackTrace = [] # filled by postProcess
    timestamp = ''

    def getOverviewLogStr(self):
        return 'FileSystemAccess (%s), tag: %s, file: %s (%d)' % (TaintLogActionEnum.getActionString(self.action), TaintTagEnum.getTaintString(self.tag), self.filePath, self.fileDescriptor)

    def getHtmlReportColumnList(self):
        columnList = [TaintTagEnum.getTaintString(self.tag)]
        columnList.append(TaintLogActionEnum.getActionString(self.action))
        columnList.append(self.filePath)
        columnList.append(self.data)
        columnList.append(self.timestamp)
        columnList.append(self.stackTraceStr)
        return columnList
    
class NetworkSendLogEntry(BaseLogEntry):
    """
    """
    action = 0 # TaintLogActionEnum.NET_*
    tag = TaintTagEnum.TAINT_CLEAR
    destination = ''
    port = 0
    data = ''
    stackTraceStr = ''
    stackTrace = [] # filled by postProcess
    timestamp = ''
    
    def getOverviewLogStr(self):
        return 'NetworkAccess (%s), tag: %s, destination: %s:%d' % (TaintLogActionEnum.getActionString(self.action), TaintTagEnum.getTaintString(self.tag), self.destination, self.port)

    def getHtmlReportColumnList(self):
        columnList = [TaintTagEnum.getTaintString(self.tag)]
        columnList.append(TaintLogActionEnum.getActionString(self.action))
        columnList.append('%s:%d' % (self.destination, self.port))
        columnList.append(self.data)
        columnList.append(self.timestamp)
        columnList.append(self.stackTraceStr)
        return columnList

class SSLLogEntry(BaseLogEntry):
    """
    """
    action = 0 # TaintLogActionEnum.SSL_*
    tag = TaintTagEnum.TAINT_CLEAR
    destination = ''
    port = 0
    data = ''
    stackTraceStr = ''
    stackTrace = [] # filled by postProcess
    timestamp = ''
    
    def getOverviewLogStr(self):
        return 'SSL (%s), tag: %s, destination: %s:%d' % (TaintLogActionEnum.getActionString(self.action), TaintTagEnum.getTaintString(self.tag), self.destination, self.port)

    def getHtmlReportColumnList(self):
        columnList = [TaintTagEnum.getTaintString(self.tag)]
        columnList.append(TaintLogActionEnum.getActionString(self.action))
        columnList.append('%s:%d' % (self.destination, self.port))
        columnList.append(self.data)
        columnList.append(self.timestamp)
        columnList.append(self.stackTraceStr)
        return columnList

class SendSmsLogEntry(BaseLogEntry):
    """
    """
    action = 0 # TaintLogActionEnum.SMS_*
    tag = TaintTagEnum.TAINT_CLEAR
    destination = ''
    scAddress = ''
    text = ''
    stackTraceStr = ''
    stackTrace = [] # filled by postProcess
    timestamp = ''
    
    def getOverviewLogStr(self):
        return 'NetworkAccess (%s), tag: %s, destination: %s' % (TaintLogActionEnum.getActionString(self.action), TaintTagEnum.getTaintString(self.tag), self.destination)

    def getHtmlReportColumnList(self):
        columnList = [TaintTagEnum.getTaintString(self.tag)]
        columnList.append(TaintLogActionEnum.getActionString(self.action))
        columnList.append(self.scAddress)
        columnList.append(self.destination)
        columnList.append(self.text)
        columnList.append(self.timestamp)
        columnList.append(self.stackTraceStr)
        return columnList


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

    # Log objects
    if '__CipherUsageLogEntry__' == type:
        object = CipherUsageLogEntry()
    elif '__FileDescriptorLogEntry__' == type:
        object = FileDescriptorLogEntry()
    elif '__FileSystemLogEntry__' == type:
        object = FileSystemLogEntry()
    elif '__NetworkSendLogEntry__' == type:
        object = NetworkSendLogEntry()
    elif '__SSLLogEntry__' == type:
        object = SSLLogEntry()
    elif '__SendSmsLogEntry__' == type:
        object = SendSmsLogEntry()
        
    # Else...
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
