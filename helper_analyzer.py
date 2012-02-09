from apk_wrapper import APKWrapper, APKWrapperError
from common import Logger, LogLevel, TaintLogActionEnum, TaintTagEnum, Utils
from taintlog_analyzer import TaintLogAnalyzer, TaintLogAnalyzerError
from taintlog_json import *

from optparse import OptionParser

import copy
import datetime
import os
import shutil


# ================================================================================
# Analyzer
# ================================================================================

class Analyzer:
    def __init__(self, theDirs, theMode=0, theSdkPath=None):
        self.dirs = theDirs
        self.mode = theMode
        self.sdkPath = theSdkPath
        self.latexFile = None
        self.baseAppDir = None
        self.printDictFile = None
        self.htmlOutputDir = None
        
    def getRuntime(self, theObj):
        startTime = datetime.datetime(int(theObj.startTime[0:4]),
                                      int(theObj.startTime[4:6]),
                                      int(theObj.startTime[6:8]),
                                      int(theObj.startTime[9:11]),
                                      int(theObj.startTime[11:13]),
                                      int(theObj.startTime[13:15]))
        endTime = datetime.datetime(int(theObj.endTime[0:4]),
                                    int(theObj.endTime[4:6]),
                                    int(theObj.endTime[6:8]),
                                    int(theObj.endTime[9:11]),
                                    int(theObj.endTime[11:13]),
                                    int(theObj.endTime[13:15]))
        timeDiff = endTime - startTime
        return timeDiff

    def getMainReport(self, theDir, theFactory):
        reportFileName = os.path.join(theDir, 'report.json')
        if os.path.exists(reportFileName):
            reportFile = open(reportFileName, 'r')
            reportJson = reportFile.read()
            report = theFactory.json2Py(reportJson)
            return report
        else:
            report = MainReportEntry()
            timeNow = datetime.datetime.now()
            report.startTime = '%s %s' % (Utils.getDateAsString(timeNow), Utils.getTimeAsString(timeNow))
            report.endTime = '%s %s' % (Utils.getDateAsString(timeNow), Utils.getTimeAsString(timeNow))
            fileNameList = os.listdir(theDir)
            for logcatFile in fileNameList:
                if logcatFile.endswith('_logcat.log'):
                    logcatFileNameParts = logcatFile.split('_')
                    apkName = ''
                    for i in xrange(len(logcatFileNameParts) - 2):
                        if i > 0:
                            apkName += '_'
                        apkName += logcatFileNameParts[i]                        
                    apkName += '.apk'
                    apk = self.getAppApk(apkName)
                    appReportEntry = AppReportEntry()
                    appReportEntry.id = int(logcatFileNameParts[-2])
                    appReportEntry.appPackage = apk.getPackage()
                    appReportEntry.appPath = apkName
                    appReportEntry.md5Hash = apk.getMd5Hash()
                    appReportEntry.logcatFile = logcatFile
                    appReportEntry.startTime = '%s %s' % (Utils.getDateAsString(timeNow), Utils.getTimeAsString(timeNow))
                    appReportEntry.endTime = '%s %s' % (Utils.getDateAsString(timeNow), Utils.getTimeAsString(timeNow))
                    report.appList.append(appReportEntry)
            return report
                    

    def getAppTaintLog(self, theDir, theLogcatFile):
        logcatFileParts = theLogcatFile.split('/')
        if len(logcatFileParts) < 2:
            logcatFile = os.path.join(theDir, theLogcatFile)
        else:
            logcatFile = os.path.join(theDir, logcatFileParts[1])
        logAnalyzer = TaintLogAnalyzer(theLogger=Logger(theLevel=LogLevel.ERROR))
        try:
            logAnalyzer.setLogFile(logcatFile)
        except IOError, ioErr:
            #raw_input('getAppTaintLog::IOError')
            return None
        logAnalyzer.extractLogEntries()
        if len(logAnalyzer.getLogEntryList()) == 0:
            logAnalyzer.numControlChars = 1
            logAnalyzer.extractLogEntries()
        if len(logAnalyzer.getLogEntryList()) == 0:
            #raw_input('XX')
            pass
        logAnalyzer.postProcessLogObjects()
        return logAnalyzer

    def getAppApk(self, theAppPath):
        baseAppDir = ''
        if self.baseAppDir is None:
            baseAppDir = '/home/daniel/Documents/Malware/thesis_analysis'
        else:
            baseAppDir = self.baseAppDir
        appPathParts = theAppPath.split('/')
        appName = appPathParts[-1]
        apkWrapper = APKWrapper(os.path.join(baseAppDir, appName), theSdkPath=self.sdkPath)
        return apkWrapper

    def printToLatexFile(self, theFile, theDict):
        pass


    INITIAL_NUMBERS_DICT = {'noTag':[0,[]],
                            'contact':[0,[]],
                            'deviceInfos':[0,[]],
                            'userInput':[0,[]],
                            'incomingData':[0,[]],
                            'location':[0,[]],
                            'other':[0,[]],
                            'nothing':[0,[]]}
    def evalTagNumbers(self, theTaintLog, theApk, theBaseObj, theNumbers, theAppendApkFlag=True):
        oneMatch = False
        
        noTag = copy.deepcopy(theBaseObj)
        noTag.tag = -1
        if theTaintLog.doesMatch([noTag]):
            theNumbers['noTag'][0] += 1
            if theAppendApkFlag: theNumbers['noTag'][1].append(theApk)
            oneMatch = True
            
        contact = copy.deepcopy(theBaseObj)
        contact.tagList.append(TaintTagEnum.TAINT_CONTACTS)
        if theTaintLog.doesMatch([contact]):
            theNumbers['contact'][0] += 1
            if theAppendApkFlag: theNumbers['contact'][1].append(theApk)
            oneMatch = True
            
        deviceInfos = copy.deepcopy(theBaseObj)
        deviceInfos.tagList.append(TaintTagEnum.TAINT_PHONE_NUMBER)
        deviceInfos.tagList.append(TaintTagEnum.TAINT_IMEI)
        deviceInfos.tagList.append(TaintTagEnum.TAINT_IMSI)
        deviceInfos.tagList.append(TaintTagEnum.TAINT_ICCID)
        deviceInfos.tagList.append(TaintTagEnum.TAINT_DEVICE_SN)
        if theTaintLog.doesMatch([deviceInfos]):
            theNumbers['deviceInfos'][0] += 1
            if theAppendApkFlag: theNumbers['deviceInfos'][1].append(theApk)
            oneMatch = True
            
        userInput = copy.deepcopy(theBaseObj)
        userInput.tagList.append(TaintTagEnum.TAINT_USER_INPUT)
        if theTaintLog.doesMatch([userInput]):
            theNumbers['userInput'][0] += 1
            if theAppendApkFlag: theNumbers['userInput'][1].append(theApk)
            oneMatch = True
            
        incomingData = copy.deepcopy(theBaseObj)
        incomingData.tagList.append(TaintTagEnum.TAINT_INCOMING_DATA)
        if theTaintLog.doesMatch([incomingData]):
            theNumbers['incomingData'][0] += 1
            if theAppendApkFlag: theNumbers['incomingData'][1].append(theApk)
            oneMatch = True
            
        location = copy.deepcopy(theBaseObj)
        location.tagList.append(TaintTagEnum.TAINT_LOCATION)
        location.tagList.append(TaintTagEnum.TAINT_LOCATION_GPS)
        location.tagList.append(TaintTagEnum.TAINT_LOCATION_NET)
        location.tagList.append(TaintTagEnum.TAINT_LOCATION_LAST)
        if theTaintLog.doesMatch([location]):
            theNumbers['location'][0] += 1
            if theAppendApkFlag: theNumbers['location'][1].append(theApk)
            oneMatch = True
            
        other = copy.deepcopy(theBaseObj)
        other.tagList.append(TaintTagEnum.TAINT_MIC)
        other.tagList.append(TaintTagEnum.TAINT_CAMERA)
        other.tagList.append(TaintTagEnum.TAINT_ACCELEROMETER)
        other.tagList.append(TaintTagEnum.TAINT_HISTORY)
        other.tagList.append(TaintTagEnum.TAINT_MEDIA)
        other.tagList.append(TaintTagEnum.TAINT_SMS)
        if theTaintLog.doesMatch([other]):
            theNumbers['other'][0] += 1
            if theAppendApkFlag: theNumbers['other'][1].append(theApk)
            oneMatch = True

        if not oneMatch:
            theNumbers['nothing'][0] += 1
            if theAppendApkFlag: theNumbers['nothing'][1].append(theApk)

        return oneMatch

    def evalSmsDestTagNumbers(self, theTaintLog, theApk, theBaseObj, theNumbers, theAppendApkFlag=True):
        oneMatch = False
        
        noTag = copy.deepcopy(theBaseObj)
        noTag.destinationTag = -1
        if theTaintLog.doesMatch([noTag]):
            theNumbers['noTag'][0] += 1
            if theAppendApkFlag: theNumbers['noTag'][1].append(theApk)
            oneMatch = True
            
        contact = copy.deepcopy(theBaseObj)
        contact.destinationTagList.append(TaintTagEnum.TAINT_CONTACTS)
        if theTaintLog.doesMatch([contact]):
            theNumbers['contact'][0] += 1
            if theAppendApkFlag: theNumbers['contact'][1].append(theApk)
            oneMatch = True
            
        deviceInfos = copy.deepcopy(theBaseObj)
        deviceInfos.destinationTagList.append(TaintTagEnum.TAINT_PHONE_NUMBER)
        deviceInfos.destinationTagList.append(TaintTagEnum.TAINT_IMEI)
        deviceInfos.destinationTagList.append(TaintTagEnum.TAINT_IMSI)
        deviceInfos.destinationTagList.append(TaintTagEnum.TAINT_ICCID)
        deviceInfos.destinationTagList.append(TaintTagEnum.TAINT_DEVICE_SN)
        if theTaintLog.doesMatch([deviceInfos]):
            theNumbers['deviceInfos'][0] += 1
            if theAppendApkFlag: theNumbers['deviceInfos'][1].append(theApk)
            oneMatch = True
            
        userInput = copy.deepcopy(theBaseObj)
        userInput.destinationTagList.append(TaintTagEnum.TAINT_USER_INPUT)
        if theTaintLog.doesMatch([userInput]):
            theNumbers['userInput'][0] += 1
            if theAppendApkFlag: theNumbers['userInput'][1].append(theApk)
            oneMatch = True
            
        incomingData = copy.deepcopy(theBaseObj)
        incomingData.destinationTagList.append(TaintTagEnum.TAINT_INCOMING_DATA)
        if theTaintLog.doesMatch([incomingData]):
            theNumbers['incomingData'][0] += 1
            if theAppendApkFlag: theNumbers['incomingData'][1].append(theApk)
            oneMatch = True
            
        location = copy.deepcopy(theBaseObj)
        location.destinationTagList.append(TaintTagEnum.TAINT_LOCATION)
        location.destinationTagList.append(TaintTagEnum.TAINT_LOCATION_GPS)
        location.destinationTagList.append(TaintTagEnum.TAINT_LOCATION_NET)
        location.destinationTagList.append(TaintTagEnum.TAINT_LOCATION_LAST)
        if theTaintLog.doesMatch([location]):
            theNumbers['location'][0] += 1
            if theAppendApkFlag: theNumbers['location'][1].append(theApk)
            oneMatch = True
            
        other = copy.deepcopy(theBaseObj)
        other.destinationTagList.append(TaintTagEnum.TAINT_MIC)
        other.destinationTagList.append(TaintTagEnum.TAINT_CAMERA)
        other.destinationTagList.append(TaintTagEnum.TAINT_ACCELEROMETER)
        other.destinationTagList.append(TaintTagEnum.TAINT_HISTORY)
        other.destinationTagList.append(TaintTagEnum.TAINT_MEDIA)
        other.destinationTagList.append(TaintTagEnum.TAINT_SMS)
        if theTaintLog.doesMatch([other]):
            theNumbers['other'][0] += 1
            if theAppendApkFlag: theNumbers['other'][1].append(theApk)
            oneMatch = True

        if not oneMatch:
            theNumbers['nothing'][0] += 1
            if theAppendApkFlag: theNumbers['nothing'][1].append(theApk)

        return oneMatch

    def printNumbers(self, theNumbers):
        for key, numbers in theNumbers['numbers'].iteritems():
            numberStr = ''
            for number, value in numbers.iteritems():
                numberStr += '%s: %d, ' % (number, value[0])
            print '- %s: %s' % (key, numberStr)

        print '- Nothing at all: %d' % theNumbers['nothing'][0]
        print '- Errors: %d' % theNumbers['error'][0]

    def consolidateResultDicts(self, theResultDicts):
        # Init overall list
        resultDict = {}
        resultDict['appList'] = []
        resultDict['numbers'] = {'sms' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'smsDest' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'call' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'netRead' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'netWrite' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'fsRead' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'fsWrite' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'cipher' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'ssl' : copy.deepcopy(self.INITIAL_NUMBERS_DICT)}
        resultDict['nothing'] = [0, []]
        resultDict['error'] = [0, []]
        numAnalyzeRuns = 0
        overallRuntime = 0

        # Analyzed apps -> Do be removed from nothing and error
        analyzedApps = []

        # For result dicts
        for resultDictPart in theResultDicts:
            # Runtime infos
            numAnalyzeRuns += len(resultDictPart['mainReport'].appList)
            overallRuntime += self.getRuntime(resultDictPart['mainReport']).seconds

            # Consolidate numbers
            for key, numbers in resultDictPart['numbers'].iteritems():
                for number, value in numbers.iteritems():
                    for app in value[1]:
                        md5 = app.getMd5Hash()

                        # Add to app list
                        if not md5 in resultDict['appList']:
                            resultDict['appList'].append(md5)

                        # Add to analyzed list
                        if not md5 in analyzedApps:
                            analyzedApps.append(md5)

                        # Add to numbers
                        if not md5 in resultDict['numbers'][key][number][1]:
                            resultDict['numbers'][key][number][0] += 1
                            resultDict['numbers'][key][number][1].append(md5)

            # Nothing
            for app in resultDictPart['nothing'][1]:
                md5 = app.getMd5Hash()
                if not md5 in resultDict['appList']:
                    resultDict['appList'].append(md5)
                if not md5 in resultDict['nothing'][1]:
                    resultDict['nothing'][0] += 1
                    resultDict['nothing'][1].append(md5)
                    
            # Errors
            for app in resultDictPart['error'][1]:
                md5 = app.getMd5Hash()
                if not md5 in resultDict['appList']:
                    resultDict['appList'].append(md5)
                if not md5 in resultDict['error'][1]:
                    resultDict['error'][0] += 1
                    resultDict['error'][1].append(md5)

        # CleanUp nothing (dict)
        for key, numbers in resultDict['numbers'].iteritems():
            deleteIdxList = []
            idx = 0
            for app in numbers['nothing'][1]:
                foundFlag = False
                for number, value in numbers.iteritems():
                    if number == 'nothing':
                        continue
                    if app in value[1]:
                        foundFlag = True
                        break
                if foundFlag:
                    deleteIdxList.append(idx)                    
                idx += 1
            deleteIdxList.sort()
            for i in xrange(len(deleteIdxList)):
                numbers['nothing'][0] -= 1
                del numbers['nothing'][1][deleteIdxList[i] - i]
                    
        # CleanUp nothing (main)
        deleteIdxList = []
        idx = 0
        for app in resultDict['nothing'][1]:
            if app in analyzedApps:
                deleteIdxList.append(idx)
            idx += 1
        deleteIdxList.sort()
        for i in xrange(len(deleteIdxList)):
            resultDict['nothing'][0] -= 1
            del resultDict['nothing'][1][deleteIdxList[i] - i]            
                    
        # CleanUp error
        deleteIdxList = []
        idx = 0
        for app in resultDict['error'][1]:
            if app in analyzedApps:
                deleteIdxList.append(idx)
            idx += 1
        deleteIdxList.sort()
        for i in xrange(len(deleteIdxList)):
            resultDict['error'][0] -= 1
            del resultDict['error'][1][deleteIdxList[i] - i]
        
        # Fill main list
        resultDict['avgAppRuntime'] = overallRuntime / numAnalyzeRuns
        return resultDict
    
    def analyzeMain(self, theDir):  
        # Factory
        jsonFactory = JsonFactory()

        # Read main report file
        mainReport = self.getMainReport(theDir, jsonFactory)        

        # Patterns
        filterList = [
            NetworkSendLogEntry(action=0,
                                tagList=[],
                                destination='unknown',
                                port=123,
                                stackTraceStr=''),
            FileSystemLogEntry(action=0,
                               tagList=[],
                               filePath='/data/data/com.android.music/shared_prefs/Music.xml',
                               stackTraceStr='')
            ]        

        callPatterns = [
            CallActionLogEntry(dialString='') # 15555218135
            ]
        
        # Analyze apps
        numApps = 0
        resultDict = {'numbers' : {'sms' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                   'smsDest' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                   'call' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                   'netRead' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                   'netWrite' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                   'fsRead' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                   'fsWrite' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                   'cipher' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                   'ssl' : copy.deepcopy(self.INITIAL_NUMBERS_DICT)},
                      'nothing' : [0, []],
                      'error' : [0, []],
                      'mainReport' : mainReport}

        for appReport in mainReport.appList:
            
            apk = self.getAppApk(appReport.appPath)
            taintLog = self.getAppTaintLog(theDir, appReport.logcatFile)
            if not taintLog is None:
                numApps += 1 # increase counter
                #taintLog.printOverview()
                taintLog.filterLogObjects(filterList) # filter for recurring patterns
                #if taintLog.doesMatch(notInstrumentedPatterns): # check for not instrumented patters
                #    taintLog.printOverview()
                #    print '--------------------'

                # Get numbers for overview table (eval calls)
                oneMatch = self.evalTagNumbers(taintLog, apk, CallActionLogEntry(tagList=[]), resultDict['numbers']['call'])
                oneMatch |= self.evalTagNumbers(taintLog, apk, CipherUsageLogEntry(tagList=[]), resultDict['numbers']['cipher'])
                oneMatch |= self.evalTagNumbers(taintLog, apk, FileSystemLogEntry(actionList=[TaintLogActionEnum.FS_READ_ACTION,
                                                                                  TaintLogActionEnum.FS_READ_DIRECT_ACTION,
                                                                                  TaintLogActionEnum.FS_READV_ACTION],
                                                                      tagList=[]),
                                    resultDict['numbers']['fsRead'])
                oneMatch |= self.evalTagNumbers(taintLog, apk, FileSystemLogEntry(actionList=[TaintLogActionEnum.FS_WRITE_ACTION,
                                                                                  TaintLogActionEnum.FS_WRITE_DIRECT_ACTION,
                                                                                  TaintLogActionEnum.FS_WRITEV_ACTION],
                                                                      tagList=[]),
                                    resultDict['numbers']['fsWrite'])
                oneMatch |= self.evalTagNumbers(taintLog, apk, NetworkSendLogEntry(actionList=[TaintLogActionEnum.NET_READ_ACTION,
                                                                                   TaintLogActionEnum.NET_READ_DIRECT_ACTION,
                                                                                   TaintLogActionEnum.NET_RECV_ACTION,
                                                                                   TaintLogActionEnum.NET_RECV_DIRECT_ACTION],
                                                                       tagList=[]),
                                    resultDict['numbers']['netRead'])
                oneMatch |= self.evalTagNumbers(taintLog, apk, NetworkSendLogEntry(actionList=[TaintLogActionEnum.NET_SEND_ACTION,
                                                                                   TaintLogActionEnum.NET_SEND_DIRECT_ACTION,
                                                                                   TaintLogActionEnum.NET_SEND_URGENT_ACTION,
                                                                                   TaintLogActionEnum.NET_WRITE_ACTION,
                                                                                   TaintLogActionEnum.NET_WRITE_DIRECT_ACTION],
                                                                       tagList=[]),
                                    resultDict['numbers']['netWrite'])
                oneMatch |= self.evalTagNumbers(taintLog, apk, SSLLogEntry(tagList=[]), resultDict['numbers']['ssl'])
                oneMatch |= self.evalTagNumbers(taintLog, apk, SendSmsLogEntry(tagList=[]), resultDict['numbers']['sms'])
                oneMatch |= self.evalSmsDestTagNumbers(taintLog, apk, SendSmsLogEntry(destinationTagList=[]), resultDict['numbers']['smsDest'])

                # Nothing happens
                if not oneMatch:
                    resultDict['nothing'][0] += 1
                    resultDict['nothing'][1].append(apk)

            else:
                resultDict['error'][0] += 1
                resultDict['error'][1].append(apk)

        # Return
        return resultDict

    def analyzeModeNumbers(self):        
        # Do main analysis
        resultDictList = []
        for directory in self.dirs:
            resultDict = self.analyzeMain(directory)
            resultDictList.append(resultDict)           
            
        # Print results
        idx = 0
        for resultDict in resultDictList:
            # Print overview
            print '\n--------------------'
            print 'Folder: %s' % self.dirs[idx]
            idx += 1
            print '- %d apps were analyzed' % (len(resultDict['mainReport'].appList))
            print '- Runtime report: %s - %s (%s)' % (str(resultDict['mainReport'].startTime), str(resultDict['mainReport'].endTime), self.getRuntime(resultDict['mainReport']))
            avgAppRuntime = self.getRuntime(resultDict['mainReport']).seconds/len(resultDict['mainReport'].appList)
            avgAppRuntimeMin = avgAppRuntime / 60
            avgAppRuntimeSecs = avgAppRuntime - (avgAppRuntimeMin * 60)
            print '- Average analyze runtime: %dsecs (%02d:%02d)' % (avgAppRuntime, avgAppRuntimeMin, avgAppRuntimeSecs)
            self.printNumbers(resultDict)

        # Consolidate results
        resultDict = self.consolidateResultDicts(resultDictList)

        # Print overview
        print '\n--------------------\nMain Result'
        print '- %d apps were analyzed' % (len(resultDict['appList']))
        avgAppRuntime = resultDict['avgAppRuntime']
        avgAppRuntimeMin = avgAppRuntime / 60
        avgAppRuntimeSecs = avgAppRuntime - (avgAppRuntimeMin * 60)
        print '- Average analyze runtime: %dsecs (%02d:%02d)' % (avgAppRuntime, avgAppRuntimeMin, avgAppRuntimeSecs)
        self.printNumbers(resultDict)

        # Store in file
        if not self.printDictFile is None:
            dictFile = open(self.printDictFile, 'w')
            dictFile.write(str(resultDict))

    def analyzeModeDetails(self):        
        # Factory
        jsonFactory = JsonFactory()
        numberList = {}
        smsDestList = {}
        filePathList = {}
        networkWriteDestList = {}
        networkReadSourceList = {}
        
        for directory in self.dirs:
            # Read main report file
            mainReport = self.getMainReport(directory, jsonFactory)

            # Patterns
            filterList = [
                NetworkSendLogEntry(action=0,
                                    tagList=[],
                                    destination='unknown',
                                    port=123,
                                    stackTraceStr=''),
                FileSystemLogEntry(action=0,
                                   tagList=[],
                                   filePath='/data/data/com.android.music/shared_prefs/Music.xml',
                                   stackTraceStr='')
                ]

            for appReport in mainReport.appList:
                apk = self.getAppApk(appReport.appPath)
                md5 = apk.getMd5Hash()
                taintLog = self.getAppTaintLog(directory, appReport.logcatFile)
                if not taintLog is None:
                    taintLog.filterLogObjects(filterList) # filter for recurring patterns

                    # Call
                    gsmEntries = taintLog.getLogEntryList(CallActionLogEntry)
                    for gsmEntry in gsmEntries:
                        if not numberList.has_key(gsmEntry.dialString):
                            numberList[gsmEntry.dialString] = [1, [md5]]
                        else:
                            numberList[gsmEntry.dialString][0] += 1
                            if not md5 in numberList[gsmEntry.dialString][1]:
                                numberList[gsmEntry.dialString][1].append(md5)

                    # SMS
                    smsEntries = taintLog.getLogEntryList(SendSmsLogEntry)
                    for smsEntry in smsEntries:
                        if not smsDestList.has_key(smsEntry.destination):
                            smsDestList[smsEntry.destination] = [1, [md5]]
                        else:
                            smsDestList[smsEntry.destination][0] += 1
                            if not md5 in smsDestList[smsEntry.destination][1]:
                                smsDestList[smsEntry.destination][1].append(md5)


                    # File paths
                    fileEntries = taintLog.getLogEntryList(FileSystemLogEntry)
                    for fileEntry in fileEntries:
                        if not filePathList.has_key(fileEntry.filePath):
                            filePathList[fileEntry.filePath] = [1, [md5]]
                        else:                            
                            filePathList[fileEntry.filePath][0] += 1
                            if not md5 in filePathList[fileEntry.filePath][1]:
                                filePathList[fileEntry.filePath][1].append(md5)

                    # Network write dest
                    networkEntries = taintLog.getLogEntryList(NetworkSendLogEntry)
                    for networkEntry in networkEntries:
                        if networkEntry.doesMatch(NetworkSendLogEntry(actionList=[TaintLogActionEnum.NET_READ_ACTION,
                                                                                  TaintLogActionEnum.NET_READ_DIRECT_ACTION,
                                                                                  TaintLogActionEnum.NET_RECV_ACTION,
                                                                                  TaintLogActionEnum.NET_RECV_DIRECT_ACTION],
                                                                      tagList=[])):
                            if not networkReadSourceList.has_key(networkEntry.destination):
                                networkReadSourceList[networkEntry.destination] = [1, [md5]]
                            else:
                                networkReadSourceList[networkEntry.destination][0] += 1
                                if not md5 in networkReadSourceList[networkEntry.destination][1]:
                                    networkReadSourceList[networkEntry.destination][1].append(md5)
                        else:
                            if not networkWriteDestList.has_key(networkEntry.destination):
                                networkWriteDestList[networkEntry.destination] = [1, [md5]]
                            else:
                                networkWriteDestList[networkEntry.destination][0] += 1
                                if not md5 in networkWriteDestList[networkEntry.destination][1]:
                                    networkWriteDestList[networkEntry.destination][1].append(md5)
                            
                    sslEntries = taintLog.getLogEntryList(SSLLogEntry)
                    for sslEntry in sslEntries:
                        if sslEntry.action == TaintLogActionEnum.SSL_READ_ACTION:
                            if not networkReadSourceList.has_key(sslEntry.destination):
                                networkReadSourceList[sslEntry.destination] = [1, [md5]]
                            else:
                                networkReadSourceList[sslEntry.destination][0] += 1
                                if not md5 in networkReadSourceList[sslEntry.destination][1]:
                                    networkReadSourceList[sslEntry.destination][1].append(md5)
                        else:
                            if not networkWriteDestList.has_key(sslEntry.destination):
                                networkWriteDestList[sslEntry.destination] = [1, [md5]]
                            else:
                                networkWriteDestList[sslEntry.destination][0] += 1
                                if not md5 in networkWriteDestList[sslEntry.destination][1]:
                                    networkWriteDestList[sslEntry.destination][1].append(md5)
                                
        print '------------------'
        print 'Dial strings'
        for entry, value in numberList.iteritems():
            print '- %s (%d, distinct: %d)' % (entry, value[0], int(len(value[1])))

        print '-------------------'
        print 'SMS destinations'
        for entry, value in smsDestList.iteritems():
            print '- %s (%d, distinct: %d)' % (entry, value[0], int(len(value[1])))
            
        print '-------------------'
        print 'File paths'
        for entry, value in filePathList.iteritems():
            print '- %s (%d, distinct: %d)' % (entry, value[0], int(len(value[1])))
            
        print '-------------------'
        print 'Network (write) destinations'
        for entry, value in networkReadSourceList.iteritems():
            print '- %s (%d, distinct: %d)' % (entry, value[0], int(len(value[1])))
            
        print '-------------------'
        print 'Network (read) sources'
        for entry, value in networkWriteDestList.iteritems():
            print '- %s (%d, distinct: %d)' % (entry, value[0], int(len(value[1])))

    def generateList(self):
        alreadyVisited = []
        appList = []
        jsonFactory = JsonFactory()
        for directory in self.dirs:            
            mainReport = self.getMainReport(directory, jsonFactory)
            for appReport in mainReport.appList:
                apk = self.getAppApk(appReport.appPath)
                targetName = '%s-%s.apk' % (apk.getPackage(), apk.getMd5Hash())
                if not targetName in alreadyVisited:
                    alreadyVisited.append(targetName)
                    appList.append((targetName, apk))
        return appList

    def generateHtmlReport(self):
        jsonFactory = JsonFactory()
        
        # Create folder
        if self.htmlOutputDir is None:
            raise ValueError('HTML output dir has to be provided')
        if not os.path.exists(self.htmlOutputDir):
            os.mkdir(self.htmlOutputDir)
        appHtmlOutputDir = os.path.join(self.htmlOutputDir, 'html')
        if not os.path.exists(appHtmlOutputDir):
            os.mkdir(appHtmlOutputDir)

        # Collect information of all apps
        result = {} # app: {}
        resultType = {'apk':None,
                      'taintLogList':[],
                      'taintLogFileNameList':[],
                      'logFileNameList':[],
                      'overview':copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                      'details':{'sms' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'smsDest' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'call' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'netRead' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'netWrite' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'fsRead' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'fsWrite' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'cipher' : copy.deepcopy(self.INITIAL_NUMBERS_DICT),
                                 'ssl' : copy.deepcopy(self.INITIAL_NUMBERS_DICT)},
                      'fileName':''}
        
        for directory in self.dirs:
            mainReport = self.getMainReport(directory, jsonFactory)
            for appReport in mainReport.appList:
                apk = self.getAppApk(appReport.appPath)
                md5 = apk.getMd5Hash()

                # Build entry in dict
                if not result.has_key(md5):
                    result[md5] = copy.deepcopy(resultType)
                    result[md5]['apk'] = apk
                
                # Taint log
                taintLog = self.getAppTaintLog(directory, appReport.logcatFile)
                if taintLog is None:
                    pass
                else:
                    result[md5]['taintLogFileNameList'].append(appReport.logcatFile)
                    result[md5]['taintLogList'].append(taintLog)

                # Log file(s)
                result[md5]['logFileNameList'].append(appReport.logcatFile[:-7] + '.log')

        # Evaluate results
        for appMd5, appResult in result.iteritems():
            for taintLog in appResult['taintLogList']:
                oneMatch = self.evalTagNumbers(taintLog, appResult['apk'], CallActionLogEntry(tagList=[]), appResult['details']['call'])
                oneMatch |= self.evalTagNumbers(taintLog, appResult['apk'], CipherUsageLogEntry(tagList=[]), appResult['details']['cipher'])
                oneMatch |= self.evalTagNumbers(taintLog, appResult['apk'], FileSystemLogEntry(actionList=[TaintLogActionEnum.FS_READ_ACTION,
                                                                                  TaintLogActionEnum.FS_READ_DIRECT_ACTION,
                                                                                  TaintLogActionEnum.FS_READV_ACTION],
                                                                      tagList=[]),
                                    appResult['details']['fsRead'])
                oneMatch |= self.evalTagNumbers(taintLog, appResult['apk'], FileSystemLogEntry(actionList=[TaintLogActionEnum.FS_WRITE_ACTION,
                                                                                  TaintLogActionEnum.FS_WRITE_DIRECT_ACTION,
                                                                                  TaintLogActionEnum.FS_WRITEV_ACTION],
                                                                      tagList=[]),
                                    appResult['details']['fsWrite'])
                oneMatch |= self.evalTagNumbers(taintLog, appResult['apk'], NetworkSendLogEntry(actionList=[TaintLogActionEnum.NET_READ_ACTION,
                                                                                   TaintLogActionEnum.NET_READ_DIRECT_ACTION,
                                                                                   TaintLogActionEnum.NET_RECV_ACTION,
                                                                                   TaintLogActionEnum.NET_RECV_DIRECT_ACTION],
                                                                       tagList=[]),
                                    appResult['details']['netRead'])
                oneMatch |= self.evalTagNumbers(taintLog, appResult['apk'], NetworkSendLogEntry(actionList=[TaintLogActionEnum.NET_SEND_ACTION,
                                                                                   TaintLogActionEnum.NET_SEND_DIRECT_ACTION,
                                                                                   TaintLogActionEnum.NET_SEND_URGENT_ACTION,
                                                                                   TaintLogActionEnum.NET_WRITE_ACTION,
                                                                                   TaintLogActionEnum.NET_WRITE_DIRECT_ACTION],
                                                                       tagList=[]),
                                    appResult['details']['netWrite'])
                oneMatch |= self.evalTagNumbers(taintLog, appResult['apk'], SSLLogEntry(tagList=[]), appResult['details']['ssl'])
                oneMatch |= self.evalTagNumbers(taintLog, appResult['apk'], SendSmsLogEntry(tagList=[]), appResult['details']['sms'])
                oneMatch |= self.evalSmsDestTagNumbers(taintLog, appResult['apk'], SendSmsLogEntry(destinationTagList=[]), appResult['details']['smsDest'])

                # Nothing happens
                if not oneMatch:
                    pass

            # Add numbers to overview table
            for tag, overviewNumbers in appResult['overview'].iteritems():
                for action, actionEntry in appResult['details'].iteritems():
                    overviewNumbers[0] += actionEntry[tag][0]
                    
        # Print report (per app)
        descrDict = {'call':'Call', 'cipher':'Cipher Usage', 'fsRead':'File System Read', 'fsWrite':'File System Write', 'netRead':'Network Read', 'netWrite':'Network Write', 'ssl':'SSL', 'sms':'SMS', 'smsDest':'SMS Destination'}
        tagTypeList = ['deviceInfos', 'contact', 'location', 'incomingData', 'userInput', 'other', 'noTag']
        actionList = ['call', 'cipher', 'fsRead', 'fsWrite', 'netRead', 'netWrite', 'ssl', 'sms', 'smsDest']
        for appMd5, appResult in result.iteritems():
            appReportFileName = '%s_%s.html' % (appResult['apk'].getPackage(), appMd5)
            appResult['fileName'] = os.path.join('html', appReportFileName)
            appReport = open(os.path.join(appHtmlOutputDir, appReportFileName), 'w')
            appReport.write('<html><head><title>TaintDroid Runner Report for %s</title></head><body><p>' % appResult['apk'].getPackage())
            appReport.write('<h1>TaintDroid Runner Report for %s</h1>' % appResult['apk'].getPackage())
            appReport.write('<br /><h2>Application</h2>')
            appReport.write('<li><b>Package</b>: %s</li>' % (appResult['apk'].getPackage()))
            appReport.write('<li><b>MD5</b>: %s</li>' % (appResult['apk'].getMd5Hash()))
            appReport.write('<li><b>Sha256</b>: %s</li>' % (appResult['apk'].getSha256Hash()))

            appReport.write('<br /><h2>Overview</h2>')
            appReport.write('<table border="1" rules="groups">')
            appReport.write("""<thead><tr><th></th>
                                   <th align="center">Dev. Info</th>
                                   <th align="center">Contact</th>
                                   <th align="center">Location</th>
                                   <th align="center">Incoming</th>
                                   <th align="center">User Input</th>
                                   <th align="center">Other</th>
                                   <th align="center">W/O Tag</th></tr></thead>""")

            sumDict = {}
            appReport.write('<tbody>')
            for action in actionList:
                appReport.write('<tr>')
                appReport.write('<td><b>%s</b></td>' % (descrDict[action]))
                for tagType in tagTypeList:
                    appReport.write('<td align="center">%d</td>' % (appResult['details'][action][tagType][0]))
                    if sumDict.has_key(tagType):
                        sumDict[tagType] += appResult['details'][action][tagType][0]
                    else:
                        sumDict[tagType] = appResult['details'][action][tagType][0]
                appReport.write('</tr>')                
            appReport.write('</tbody>')

            appReport.write('<tfoot><tr><td></td>')
            for tagType in tagTypeList:
                appReport.write('<td align="center">%d</td>' % (sumDict[tagType]))
            appReport.write('</tr></tfoot>')
            
            appReport.write('</table>')
            
            appReport.write('<br /><h2>Details (Filtered)</h2>')
            for action in actionList[:-1]:
                foundFlag = False
                for tagType in tagTypeList:
                    if appResult['details'][action][tagType][0] > 0:
                        foundFlag = True
                        break
                if not foundFlag:
                    continue

                appReport.write('<h3>%s</h3>' % (descrDict[action]))
                

            appReport.write('<br /><h2>Raw Files</h2>')
            for i in xrange(len(appResult['taintLogFileNameList'])):
                appReport.write('<li>Logcat output (%d): <a href="%s">%s</a></li>' % ((i+1), appResult['taintLogFileNameList'][i], appResult['taintLogFileNameList'][i]))
            for i in xrange(len(appResult['logFileNameList'])):
                appReport.write('<li>Log output (%d): <a href="%s">%s</a></li>' % ((i+1), appResult['logFileNameList'][i], appResult['logFileNameList'][i]))
            appReport.write('</p></body></html>')
        
        # Print main report
        mainReport = open(os.path.join(self.htmlOutputDir, 'index.html'), 'w')
        mainReport.write('<html><head><title>TaintDroid Runner Report</title></head><body><p>')
        mainReport.write('<h1>TaintDroid Runner Report</h1>')
        mainReport.write('<table border="1" rules="rows">')
        mainReport.write("""<thead><tr><th></th>
                              <th align="center">Dev. Info</th>
                              <th align="center">Contact</th>
                              <th align="center">Location</th>
                              <th align="center">Incoming</th>
                              <th align="center">User Input</th>
                              <th align="center">Other</th>
                              <th align="center">W/O Tag</th></tr></thead>""")
        sumDict = {}
        mainReport.write('<tbody>')
        for appMd5, appResult in result.iteritems():
            mainReport.write('<tr>')
            mainReport.write('<td><a href="%s">%s</a> (%s)</td>' % (appResult['fileName'], appResult['apk'].getPackage(), appMd5))
            for tagType in tagTypeList:
                mainReport.write('<td align="center">%d</td>' % (appResult['overview'][tagType][0]))
                if sumDict.has_key(tagType):
                    sumDict[tagType] += appResult['overview'][tagType][0]
                else:
                    sumDict[tagType] = appResult['overview'][tagType][0]
            mainReport.write('</tr>')
        mainReport.write('</tbody>')
        
        mainReport.write('<tfoot><tr><td></td>')
        for tagType in tagTypeList:
            mainReport.write('<td align="center">%d</td>' % (sumDict[tagType]))
        mainReport.write('</tr></tfoot>')
            
        mainReport.write('</table>')
        mainReport.write('</p></body></html>')


    def findNotInstrumentedPatterns(self):
        notInstrumentedPatterns = [
            NetworkSendLogEntry(action=0,
                                actionList=[TaintLogActionEnum.NET_READ_DIRECT_ACTION,
                                            TaintLogActionEnum.NET_WRITE_DIRECT_ACTION,
                                            TaintLogActionEnum.NET_RECV_DIRECT_ACTION,
                                            TaintLogActionEnum.NET_SEND_DIRECT_ACTION],
                                tagList=[],
                                destination='',
                                stackTraceStr=''),
            FileSystemLogEntry(action=0,
                               actionList=[TaintLogActionEnum.FS_READ_DIRECT_ACTION,
                                           TaintLogActionEnum.FS_WRITE_DIRECT_ACTION,
                                           TaintLogActionEnum.FS_READV_ACTION,
                                           TaintLogActionEnum.FS_WRITEV_ACTION],
                               tagList=[],
                               filePath='',
                               stackTraceStr='')
            ]
        
        jsonFactory = JsonFactory()
        for directory in self.dirs:
            mainReport = self.getMainReport(directory, jsonFactory)
            for appReport in mainReport.appList:
                apk = self.getAppApk(appReport.appPath)
                taintLog = self.getAppTaintLog(directory, appReport.logcatFile)
                if not taintLog is None:
                    if taintLog.doesMatch(notInstrumentedPatterns): # check for not instrumented patters
                        print '--------------------'
                        taintLog.printOverview()
            
    def analyze(self):
        if int(self.mode) == 0:
            self.analyzeModeNumbers()
        elif int(self.mode) == 1:
            self.analyzeModeDetails()
        elif int(self.mode) == 2:
            self.generateList()
        elif int(self.mode) == 3:
            self.generateHtmlReport()
        elif int(self.mode) == 4:
            self.findNotInstrumentedPatterns()

# ================================================================================
# Main method
# ================================================================================
    
if __name__ == '__main__':
    # Get directory
    parser = OptionParser(usage='usage: %prog [options] reportDir')
    parser.add_option('-m', '--mode', metavar='<int>', default=0, help='Set mode')
    parser.add_option('', '--sdkPath', metavar='<path>', default='', help='Set path to Android SDK')
    parser.add_option('', '--latexFile', metavar='<path>', default=None, help='Set path to Latex file')
    parser.add_option('', '--baseAppDir', metavar='<path>', default=None, help='Set path to dicrectory in which applications are stored')
    parser.add_option('', '--printDictFile', metavar='<path>', default=None, help='Set path to file in which output dict should be printed')
    parser.add_option('', '--htmlOutputDir', metavar='<path>', default=None, help='Output directory for generated HTML report')
    (options, args) = parser.parse_args()

    # Get report dir
    if len(args) < 1:
        raise ValueError('Provide a directory')
    reportDirs = []
    for arg in args:
        reportDirs.append(arg)

    # Analyze
    analyzer = Analyzer(reportDirs,
                        theMode=options.mode,
                        theSdkPath=options.sdkPath)
    analyzer.latexFile = options.latexFile
    analyzer.baseAppDir = options.baseAppDir
    analyzer.printDictFile = options.printDictFile
    analyzer.htmlOutputDir = options.htmlOutputDir
    analyzer.analyze()
