################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
# Co-Author: mspreitz
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

from apk_wrapper import APKWrapper, APKWrapperError
from common import Logger, LogLevel, LogMode, SimulationSteps, Utils
from emulator_client import *
from emulator_telnet_client import *
from ms_db_interface import MsDbInterface, MsDbInterfaceError
from optparse import OptionParser
from report_generator import ReportGenerator
from taintlog_analyzer import TaintLogAnalyzer, TaintLogAnalyzerError
from taintlog_json import CallActionLogEntry, CipherUsageLogEntry, FileSystemLogEntry, NetworkSendLogEntry, SSLLogEntry, SendSmsLogEntry
from taintlog_json import AppReportEntry, MainReportEntry
from taintlog_json import JsonFactory
from threading import Thread

import datetime
import os
import shutil
import time
import traceback


# ================================================================================
# TaintDroid Runner Enums
# ================================================================================
class TaintDroidRunnerMode:
    DEFAULT_MODE     = 1
    REPORT_MODE      = 2
    INTERACTIVE_MODE = 3
    MS_MODE          = 4
    JSON_MODE        = 5

    @staticmethod
    def getModeFromString(theStr):
        if theStr == 'default':
            return TaintDroidRunnerMode.DEFAULT_MODE
        elif theStr == 'interactive':
            return TaintDroidRunnerMode.INTERACTIVE_MODE
        elif theStr == 'report':
            return TaintDroidRunnerMode.REPORT_MODE
        elif theStr == 'mobileSandbox':
            return TaintDroidRunnerMode.MS_MODE
        elif theStr == 'json':
            return TaintDroidRunnerMode.JSON_MODE
        else:
            raise ValueError('Invalid TaintDroid Runner mode: %s' % theStr)

        
# ================================================================================
# TaintDroid Runner Error
# ================================================================================
class TaintDroidRunnerError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# ================================================================================
# TaintDroid Runner Thread
# ================================================================================
class RunnerThread(Thread):
    def __init__(self, theTDRunnerMain, theApp, theLogger=Logger()):
        Thread.__init__(self)

        self.tdRunnerMain = theTDRunnerMain
        self.app = theApp
        self.emulatorPort = 5554
        self.log = theLogger
        self.maxLogcatSize = self.tdRunnerMain.maxLogcatSize
        self.simulationSteps = 4095
        self.numMonkeyEvents = self.tdRunnerMain.numMonkeyEvents
        self.startTime = datetime.datetime.now()

        self.emulator = None
        self.result = {}

        self.cancelFlag = False # Flag for canceling run

    def __checkForCancelation(self):
        """
        Checks for the cancelation flag sent from the main program.
        If cancel flag is set, abort execution by raising KeyboardInterrupt.
        """
        if self.cancelFlag:
            self.log.write('%s: Cancelation flag found, abort thread' % Utils.getTimeAsString(datetime.datetime.now()))
            traceback.print_stack(file=self.log.log)
            raise KeyboardInterrupt
        
    def getResult(self):
        return self.result

    def killEmulator(self):
        if not self.emulator is None:
            self.emulator.killRun()
        
    def run(self):
        """
        Run the simulations.
        """
        # Debug infos
        self.log.debug('simulationSteps: %s' % SimulationSteps.getStepsAsString(self.simulationSteps))
        self.log.debug('numMonkeyEvents: %d' % self.numMonkeyEvents)
        self.log.debug('emulatorPort: %d' % self.emulatorPort)
        self.log.debug('maxLogcatSize: %d' % self.maxLogcatSize)        
                    
        # Run apps    
        try:            
            imageDirPath = None
            self.log.write('Analyze app %s (%s)' % (self.app.getApkFileName(), self.app.getApkPath()))          
            
            # Init clean image dir
            imageDirPath = self._initCleanImageDir(self.tdRunnerMain.imageDirPath, self.app.getId(), self.app.getApkName())

            # Init result
            self.result['app'] = self.app
            self.result['cleanImageDir'] = imageDirPath
            self.result['steps'] = self.simulationSteps
            self.result['numMonkeyEvents'] = self.numMonkeyEvents
            self.result['maxLogcatSize'] = self.maxLogcatSize
            self.result['sleepTime'] = self.tdRunnerMain.sleepTime
            self.result['startTime'] = self.startTime
            self.result['errorList'] = []
                
            # Check for calcelation flag
            self.__checkForCancelation()                
                
            # Start emulator
            self.emulator = EmulatorClient(theSdkPath=self.tdRunnerMain.sdkPath,
                                      thePort=self.emulatorPort,
                                      theImageDirPath=imageDirPath,
                                      theAvdName=self.tdRunnerMain.avdName,
                                      theRunHeadlessFlag=self.tdRunnerMain.runHeadless,
                                      theLogger=self.log)
            self.emulator.start()                

            # Run app
            keyboardInterruptFlag = self.runApp(self.emulator, self.app, self.simulationSteps)

            # Stop emulator
            self.emulator.stop()

            # Print results
            self.log.write('- App: %s (package: %s)' % (self.app.getApkFileName(), self.app.getPackage()))
            self.log.write('- Time: %s %s - %s' % (Utils.getDateAsString(self.startTime), Utils.getTimeAsString(self.startTime), Utils.getTimeAsString(self.result['endTime'])))
            if self.result.has_key('log'):
                self.result['log'].printOverview()
                
            # Keyboard interrupt
            if keyboardInterruptFlag:
                raise KeyboardInterrupt
                                
        except KeyboardInterrupt:
            pass
        except EmulatorClientError, ecErr:
            pass
        except Exception, ex:
            traceback.print_exc(file=self.log.log)
            #raise ex

        finally:
            # CleanUp folder
            if self.tdRunnerMain.cleanUpImageDir:
                self._cleanUpImageDir(imageDirPath)
            else:
                self.log.info('Image dir \'%s\' will not be removed, cleanUpImageDir flag set to false.' % imageDirPath)
        

    def _initCleanImageDir(self, theImageDir, theSampleId, theAppName):
        """
        Build a new directory with clean images.
        Also checks if all images are available.
        Return the new folder.
        """
        imageFileList = ['ramdisk.img', 'sdcard.img', 'system.img', 'userdata.img', 'zImage']
        newPath = '/tmp/%s_%06d' % (theAppName, theSampleId)
        if os.path.exists(newPath):
            i = 1
            while True:
                newPath = '/tmp/%s_%06d_%02d' % (theAppName, theSampleId, i)
                if os.path.exists(newPath):
                    i += 1
                else:
                    break
                
        self.log.info('Create clean image dir: %s' % newPath)
        os.mkdir(newPath)
        for imageFile in imageFileList:
            self.__checkForCancelation()
            self.log.info('- Copy %s' % imageFile)
            shutil.copy2(os.path.join(theImageDir, imageFile), os.path.join(newPath, imageFile))
        return newPath

    def _cleanUpImageDir(self, theImageDirPath):
        """
        Clean up the image dir.
        """
        if not theImageDirPath is None:            
            try:
                shutil.rmtree(theImageDirPath, True)
            except OSError, ose:
                self.log.error('Error during cleaning up image dir \'%s\': %s' % (theImageDirPath, ose))    

    def _getLogcatFileName(self, theLogcatDirPath, theSampleId, theFileName):
        """
        Generates logcat file name
        """
        if theLogcatDirPath != '':
            if not os.path.exists(theLogcatDirPath):
                os.mkdir(theLogcatDirPath)
        logcatFileName = '%s%s_%06d_logcat.log' % (theLogcatDirPath, theFileName, theSampleId)
        self.result['logcatFileName'] = logcatFileName
        if os.path.exists(logcatFileName):
            i = 1
            while True:
                logcatFileName = '%s%s_%06d_%02d_logcat.log' % (theLogcatDirPath, theFileName, theSampleId, i)
                if os.path.exists(logcatFileName):
                    i += 1
                else:
                    break
        self.log.debug('Store logcat in %s' % logcatFileName)
        return logcatFileName
    
    def _storeLogcatAsFile(self, theLogcatDirPath, theSampleId, theFileName, theLog):
        """
        Store logcat in file.
        """
        logcatFileName = self._getLogcatFileName(theLogcatDirPath, theSampleId, theFileName)        
        logFile = open(logcatFileName, "w")
        logFile.write(theLog)

    def runApp(self, theEmulator, theApp, theSteps):
        """
        Runs the application and does various simulations and monkey runs.
        Afterwards a result entry is returned.
        """       
        # Determine monkey runs
        numMonkeyRuns = 0
        if (theSteps & SimulationSteps.MONKEY_BEFORE_GSM):
            numMonkeyRuns += 1
        if (theSteps & SimulationSteps.MONKEY_BEFORE_GEO):
            numMonkeyRuns += 1
        if (theSteps & SimulationSteps.MONKEY_BEFORE_SMS):
            numMonkeyRuns += 1
        if (theSteps & SimulationSteps.MONKEY_BEFORE_POWER):
            numMonkeyRuns += 1
        if (theSteps & SimulationSteps.MONKEY):
            numMonkeyRuns += 1            

        if numMonkeyRuns != 0:
            if self.numMonkeyEvents % numMonkeyRuns == 0:
                numMonkeyEventsFirst = self.numMonkeyEvents / numMonkeyRuns
                numMonkeyEventsLast = numMonkeyEventsFirst
            else:
                numMonkeyEventsFirst = self.numMonkeyEvents / numMonkeyRuns
                numMonkeyEventsLast = self.numMonkeyEvents - (numMonkeyEventsFirst * (numMonkeyRuns - 1))
        
        # Clear log
        theEmulator.clearLog()        

        # Install app
        self.log.write('- %s: Install app' % Utils.getTimeAsString(datetime.datetime.now()))
        if (theSteps & SimulationSteps.INSTALL):
            numRetries = 0
            while True:
                self.__checkForCancelation()
                #numRetries += 1
                try:            
                    theEmulator.installApp(theApp.getApk())
                    break
                
                except EmulatorClientError, ecErr:
                    errorOccuredFlag = True
                    if ecErr.getCode() == EmulatorClientError.INSTALLATION_ERROR_ALREADY_EXISTS:
                        break
                    elif ecErr.getCode() == EmulatorClientError.INSTALLATION_ERROR_SYSTEM_NOT_RUNNING:
                        if numRetries == 4:
                            self.log.debug('Number of maximum retries reached, abort installation')
                        else:
                            # Wait and retry
                            errorOccuredFlag = False
                            waitTime = numRetries * 10
                            self.log.debug('Installation failed as system might not be running. Wait for %dsec and try again' % waitTime)
                            time.sleep(waitTime)
                            continue
                        
                    if errorOccuredFlag: # Error occured
                        self.result['errorList'].append(ecErr)
                        self.result['endTime'] = datetime.datetime.now()
                        
                        # Return
                        return False

        # Change language code
        #theEmulator.setSimCountryIso('de')
                    
        # Start logcat redirect
        logcatRedirectFile = '/mnt/sdcard/logcat.log'
        theEmulator.startLogcatRedirect(logcatRedirectFile, self.maxLogcatSize)
        
        # Switch on taint tracking
        theEmulator.changeGlobalTaintLogState('1', True)
                    
        # Start all services
        self.__checkForCancelation()
        if (theSteps & SimulationSteps.START):
            try:
                for service in theApp.getServiceNameList():
                    theEmulator.startService(theApp.getPackage(), service)
            except EmulatorClientError, ecErr:
                self.result['errorList'].append(ecErr)

        # Simulations
        keyboardInterruptFlag = False
        try:
            self.log.info('Run simulation')

            if (theSteps & SimulationSteps.MONKEY_BEFORE_GSM):
                self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsFirst)
            if (theSteps & SimulationSteps.GSM):
                self._runGsmSimulation(theEmulator.getTelnetClient())
            if (theSteps & SimulationSteps.MONKEY_BEFORE_GEO):
                self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsFirst)
            if (theSteps & SimulationSteps.GEO):
                self._runGeoSimulation(theEmulator.getTelnetClient())
            if (theSteps & SimulationSteps.MONKEY_BEFORE_SMS):
                self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsFirst)
            if (theSteps & SimulationSteps.SLEEP):
                self._runSleep(theEmulator, theApp)
            if (theSteps & SimulationSteps.SMS):
                self._runSmsSimulation(theEmulator.getTelnetClient())
            if (theSteps & SimulationSteps.MONKEY_BEFORE_POWER):
                self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsFirst)
            if (theSteps & SimulationSteps.POWER):
                self._runPowerSimulation(theEmulator.getTelnetClient())
            if (theSteps & SimulationSteps.MONKEY):
                self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsLast)
                
        except KeyboardInterrupt:
            self.log.write('Keyboard interrupt detected: store log, postprocess, and finish')
            keyboardInterruptFlag = True
        except Exception, ex:
            traceback.print_exc(file=self.log.log)
            self.result['errorList'].append(ex)

        # Wait?
        if (theSteps & SimulationSteps.WAIT_FOR_RAW_INPUT):
            raw_input('Press to end...')

        # End
        logAnalyzer = None
        try:
            self.log.write('- %s: Analyze log' % Utils.getTimeAsString(datetime.datetime.now()))
            # Store log in logfile
            #log = theEmulator.getLog()
            theEmulator.stopLogcatRedirect()
            #log = theEmulator.getLogcatRedirectFile(logcatRedirectFile)
            #self._storeLogcatAsFile(self.tdRunnerMain._getLogDirPath(), theApp.getId(), theApp.getApkName(), log)
            logcatFileName = self._getLogcatFileName(self.tdRunnerMain._getLogDirPath(), theApp.getId(), theApp.getApkName())
            theEmulator.storeLogcatRedirectFile(logcatRedirectFile, logcatFileName)
            
            # Build LogAnalyzer
            logAnalyzer = TaintLogAnalyzer(theLogger=self.log)
            #logAnalyzer.setLogString(log)
            logAnalyzer.setLogFile(logcatFileName)
            logAnalyzer.extractLogEntries()
            logAnalyzer.postProcessLogObjects()
            self.result['errorList'].extend(logAnalyzer.getJson2PyFailedErrorList())
            
        except EmulatorClientError, ecErr:
            self.result['errorList'].append(exErr)
            
        except TaintLogAnalyzerError, tlaErr:
            self.result['errorList'].append(tlaErr)

        # Build result entry
        self.result['log'] = logAnalyzer
        self.result['endTime'] = datetime.datetime.now()
        
        # Return
        return keyboardInterruptFlag

    # ================================================================================
    # Simulations
    # ================================================================================
    def _runGsmSimulation(self, theTelnetClient):
        """
        Simulates incoming calls
        """
        self.__checkForCancelation()
        
        self.log.info('- %s: GSM simulation' % Utils.getTimeAsString(datetime.datetime.now()))

        theTelnetClient.changeGSMState(GsmState.OFF)
        time.sleep(8)
        theTelnetClient.changeGSMState(GsmState.ON)
        time.sleep(8)

        theTelnetClient.call('+491702662662')
        time.sleep(1)
        theTelnetClient.acceptCall('+491702662662')
        time.sleep(10)
        theTelnetClient.cancelCall('+491702662662')
        time.sleep(1)
        

    def _runGeoSimulation(self, theTelnetClient):
        """
        Simulates route in China
        """
        self.__checkForCancelation()
        
        self.log.info('- %s: Geo simulation' % Utils.getTimeAsString(datetime.datetime.now()))
        
        theTelnetClient.changeLocation('28.411629', '119.054553')
        time.sleep(3)
        theTelnetClient.changeLocation('28.411629', '118.554553')
        time.sleep(3)
        theTelnetClient.changeLocation('28.41162', '118.054553')
        time.sleep(3)
        theTelnetClient.changeLocation('28.411629', '117.054553')
        time.sleep(3)
        theTelnetClient.changeLocation('427.911629', '116.854553')
        time.sleep(3)
        theTelnetClient.changeLocation('27.411629', '115.954553')
        time.sleep(3)        

    def _runSmsSimulation(self, theTelnetClient):
        """
        Simulates SMS
        """
        self.__checkForCancelation()
        
        self.log.info('- %s: SMS simulation' % Utils.getTimeAsString(datetime.datetime.now()))
        
        theTelnetClient.sendSms('+491702662662', 'Hi there. How are you? I am currently on a business trip in Germany. What about a short meeting?')
        time.sleep(3)
        theTelnetClient.sendSms('+491702662662', 'Ok. Fine. See you at 6pm in front of the cafe')
        time.sleep(3)
        #theTelnetClient.sendSms('81001', 'Dummy message for Android.RuFraud')
        #time.sleep(3)

    def _runPowerSimulation(self, theTelnetClient):
        """
        Simulates Power
        """
        self.__checkForCancelation()
        
        self.log.info('- %s: Power simulation' % Utils.getTimeAsString(datetime.datetime.now()))
        
        theTelnetClient.setBatteryPowerState(BatteryPowerState.DISCHARGING)
        time.sleep(1)
        theTelnetClient.setBatteryCapacity(5)
        time.sleep(5)
        theTelnetClient.setBatteryPowerState(BatteryPowerState.CHARGING)
        time.sleep(3)
        theTelnetClient.setBatteryCapacity(75)
        time.sleep(2)
        theTelnetClient.setBatteryCapacity(100)
        time.sleep(2)
        theTelnetClient.setBatteryPowerState(BatteryPowerState.FULL)
        time.sleep(2)

    def _runMonkey(self, theEmulator, thePackage=None, theEventCount=1000):
        """
        Runs monkey simulation and restarts simulation if package cannot be found.
        """
        self.__checkForCancelation()
        
        self.log.info('- %s: Monkey (events=%d)' % (Utils.getTimeAsString(datetime.datetime.now()), theEventCount))
        
        try:
            theEmulator.useMonkey(thePackage, theEventCount)
        except EmulatorClientError, ecErr:
            if ecErr.getCode() == EmulatorClientError.MONKEY_ERROR and not thePackage is None:
                self.log.debug('Monkey abort detected. Restart monkey run without package.')
                theEmulator.useMonkey(theEventCount=theEventCount)
            else:
                raise ecErr

    def _runSleep(self, theEmulator, theApp):
        """
        Runs sleep.
        Do check for cancelation every 10 seconds
        """
        self.log.info('- %s: Sleep for %dsec' % (Utils.getTimeAsString(datetime.datetime.now()), self.tdRunnerMain.sleepTime))

        # Start (main) activity
        try:
            mainActivity = theApp.getMainActivityName()
            if not mainActivity is None:
                theEmulator.startActivity(theApp.getPackage(), mainActivity)
                
        except EmulatorClientError, ecErr:
            self.result['errorList'].append(ecErr)

        # Sleep
        numRuns = self.tdRunnerMain.sleepTime / 10
        if self.tdRunnerMain.sleepTime % 10 == 0:
            timeFirst = self.tdRunnerMain.sleepTime / 10
            timeLast = timeFirst
        else:
            timeFirst = self.tdRunnerMain.sleepTime / 10
            timeLast = self.tdRunnerMain.sleepTime - (timeFirst * (numRuns - 1))

        for i in xrange(numRuns):
            self.__checkForCancelation()
            if i < numRuns - 2:
                time.sleep(timeFirst)
            else:
                time.sleep(timeLast)
        

    
# ================================================================================
# TaintDroid Runner
# ================================================================================
class TaintDroidRunner:
    def __init__(self, theMode, theReportPathSuffix=None, theLogPathSuffix=None, theLogger=Logger()):
        self.log = theLogger

        self.mode = TaintDroidRunnerMode.getModeFromString(theMode)
        
        self.app = None # app to be analyzed
        self.appDir = None # directory in which all apps are analyzed

        self.imageDirPath = '' # path to TaintDroid 2.3 image files
        self.numThreads = 1 # number of parallell threads for analyzing
        self.emulatorStartPort = 5554
        self.maxThreadRuntime = 300

        self.reportPathSuffix = theReportPathSuffix
        self.reportPath = ''
        
        self.sdkPath = ''        
        self.avdName = None

        self.runHeadless = False
        
        self.numMonkeyEvents = 500
        self.sleepTime = 60
        self.cleanUpImageDir = True
        
        self.storeLogInFile = False
        self.logPathSuffix = theLogPathSuffix
        self.maxLogcatSize = 4096

        self.msDbLocation = 'mobile_sandbox/mobile_sandbox.db'
        self.msDb = None
        if self.mode == TaintDroidRunnerMode.MS_MODE:
            self.msDb = MsDbInterface(self.msDbLocation, theLogger=self.log)

        self.startTime = datetime.datetime.now()

        self.resultVec = []

        # Report mode
        if self.mode == TaintDroidRunnerMode.REPORT_MODE or \
                self.mode == TaintDroidRunnerMode.MS_MODE or \
                self.mode == TaintDroidRunnerMode.JSON_MODE:
            # Create report directory if it not exists
            self.reportPath = self._getReportDirPath()
            if not os.path.exists(self.reportPath):
                self.log.debug('Create report directory: %s' % self.reportPath)
                os.mkdir(self.reportPath)

            # Change path variables            
            self.storeLogInFile = True
            self.logPathSuffix = self.reportPathSuffix        

        # Logcat
        logPath = self._getLogDirPath()
        if not os.path.exists(logPath):
            self.log.debug('Create log directory: %s' % logPath)
            os.mkdir(logPath)
    
    # ================================================================================
    # Helpers
    # ================================================================================
    def _getLogDirPath(self):
        """
        Return log directory for storing log and logcat.
        """
        if self.logPathSuffix is None or self.logPathSuffix == '':
            return '%s-%s/' % (Utils.getDateAsString(self.startTime), Utils.getTimeAsString(self.startTime))
        else:
            if self.logPathSuffix[-1] == '/':
                self.logPathSuffix = self.logPathSuffx[:-1]
            return '%s_%s-%s/' % (self.logPathSuffix, Utils.getDateAsString(self.startTime), Utils.getTimeAsString(self.startTime))

    def _getReportDirPath(self):
        """
        Return report directory for storing report.
        """
        if self.reportPathSuffix[-1] == '/':
            self.reportPathSuffix = self.reportPathSuffx[:-1]
        return '%s_%s-%s/' % (self.reportPathSuffix, Utils.getDateAsString(self.startTime), Utils.getTimeAsString(self.startTime))

    def _getAppThreadLogFile(self, theSampleId, theFileName):
        """
        Return log file name for app runner thread.
        """
        logFileName = '%s_%06d_log.log' % (theFileName, theSampleId)
        logFile = '%s%s' % (self._getLogDirPath(), logFileName)
        if os.path.exists(logFile):
            i = 1
            while True:
                logFileName = '%s_%06d_%02d_log.log' % (theFileName, theSampleId, i)
                logFile = '%s%s' % (self._getLogDirPath(), logFileName)
                if os.path.exists(logFile):
                    i += 1
                else:
                    break
                
        return logFileName   

    def _getReportName(self, theReportPath, theSampleId):
        """
        Return report name
        """
        reportName = 'report_app_%06d.html' % theSampleId
        reportFile = '%s%s' % (theReportPath, reportName)
        if os.path.exists(reportFile):
            i = 1
            while True:
                reportName = 'report_app_%06d_%02d.html' % (theSampleId, i)
                reportFile = '%s%s' % (theReportPath, reportName)
                if os.path.exists(reportFile):
                    i += 1
                else:
                    break
                
        return reportName    

    # ================================================================================
    # Run
    # ================================================================================
    def run(self):
        """
        Run TaintDroid and analyze the provided applications
        """        
        # Check for equal emulatorStartPort
        if int(self.emulatorStartPort) % 2 != 0:
            raise ValueError('Emulator start port has to be even')
            
        # Init result vec
        threadLogFileList = []
            
        # Build list of apps to be run      
        appList = [] 
        if self.app is not None and self.appDir is not None:
            raise TaintDroidRunnerError('Both application and application directory set')
        elif self.app is not None:
            try:                
                appList.append(APKWrapper(self.app, theSdkPath=self.sdkPath, theLogger=self.log))
            except APKWrapperError, apkwErr:
                self.log.debug('App %s could not be load: %s' % (self.app, str(apkwErr)))
                aResultEntry = {'app' : self.app,
                                'errorList' : [apkwErr]}
                self.resultVec.append(aResultEntry)
        elif self.appDir is not None:
            appNameList = Utils._getAppListInDirectory(self.appDir)
            for appName in appNameList:
                try:
                    appList.append(APKWrapper(appName, theSdkPath=self.sdkPath, theLogger=self.log))
                except APKWrapperError, apkwErr:
                    aResultEntry = {'app' : appName,
                                    'errorList' : [apkwErr]}
                    self.resultVec.append(aResultEntry)
        else:
            raise TaintDroidRunnerError('Neither application nor application directory set')        

        # Determine SampleIds
        if self.mode == TaintDroidRunnerMode.MS_MODE:
            self.msDb.connect()
            for app in appList:
                sampleId = self.msDb.storeSample(app.getApkFileName(),
                                                 app.getPackage(),
                                                 theMd5Value=app.getMd5Hash(),
                                                 theSha256Value=app.getSha256Hash(),
                                                 theFilesystemPosition=app.getApk())
                app.setId(sampleId)
            self.msDb.commit()
            self.msDb.close()

        # Debug info
        self.log.write('The following apps are analyzed:')
        for app in appList:
            self.log.write('- %s (%s), id=%06d' % (app.getApkFileName(), app.getApkPath(), app.getId()))
          
        # Run
        if self.mode != TaintDroidRunnerMode.INTERACTIVE_MODE:
            # Adjust max thread number if numTheads > numApps
            numThreads = self.numThreads
            if numThreads > len(appList):
                self.log.debug('- Number of threads is greater than number of apps to be analyzed. Reduce number of threads from %d to %d.' % (int(numThreads), int(len(appList))))
                numThreads = len(appList)

            # Inits
            numFinishedApps = 0 # number of analyzed apps
            lastAppIndex = 0 # next app to be analyzed
            numRunningThreads = 0 # number of running threads
            threadList = [] # list of threads, size=numThreads
            threadActiveMask = [] # bitmask to determine if thread is active, size=numThreads            
            for i in xrange(numThreads):
                threadList.append(None)
                threadActiveMask.append(False)
                
            while True:
                try:
                    # Get app and start thread
                    if numRunningThreads < numThreads and lastAppIndex < len(appList):
                        # Get app
                        app = appList[lastAppIndex]                    

                        # Check for inactive thread
                        threadIndex = -1
                        for i in xrange(numThreads):
                            if not threadActiveMask[i]:
                                threadIndex = i
                        if threadIndex == -1:
                            self.log.error('No free thread index found even though numRunningThreads < numThreads')
                            continue
                        lastAppIndex += 1
                        self.log.debug('Free thread found (%d) for analyzing %s' % (threadIndex+1, app.getApkName()))
                        self.log.write('Analyze %s' % app.getApk())

                        # Determine logger
                        threadLogger = self.log
                        if self.storeLogInFile:
                            logFileName = self._getAppThreadLogFile(app.getId(), app.getApkName())
                            logFile = '%s%s' % (self._getLogDirPath(), logFileName)
                            threadLogFileList.append(logFileName)
                            threadLogger = Logger(theLevel=self.log.level,
                                                  theMode=LogMode.FILE,
                                                  theLogFile=logFile)

                        # Build thread
                        runnerThread = RunnerThread(self, theApp=app, theLogger=threadLogger)
                        runnerThread.emulatorPort = self.emulatorStartPort + (threadIndex*2)
                        runnerThread.daemon = False
                        runnerThread.startTime = datetime.datetime.now()

                        # Start thread
                        threadList[threadIndex] = runnerThread
                        threadActiveMask[threadIndex] = True
                        numRunningThreads += 1
                        runnerThread.start()

                    # No free thread -> check timing
                    else:
                        if lastAppIndex < len(appList):
                            self.log.debug('No free thread found, wait for free thread')
                        else:
                            self.log.debug('No more apps to be analyzed, wait for end of analysis')
                        
                        # Check for inactive threads
                        currentTime = datetime.datetime.now()
                        for i in xrange(numThreads):
                            # Thread terminated regulary
                            if not threadList[i] is None and not threadList[i].isAlive():
                                self.log.debug('Thread %d for %s finished' % ((i+1), threadList[i].app.getApk()))
                                self._handleThreadResult(threadList[i].getResult())
                                numFinishedApps += 1
                                threadList[i] = None
                                threadActiveMask[i] = False
                                numRunningThreads -= 1

                            # Check how long thread is running                           
                            elif not threadList[i] is None:                                
                                runningTime = currentTime - threadList[i].startTime
                                if runningTime.seconds > self.maxThreadRuntime:
                                    self.log.debug('Thread %d for %s is running more than %dsec, cancel' % ((i+1), threadList[i].app.getApk(), self.maxThreadRuntime))
                                    threadList[i].cancelFlag = True
                                    threadList[i].join(60) # Wait until finished, max 1min
                                    if threadList[i].isAlive():
                                        self.log.error('Thread %d cannot be terminated, anyway free it up.' % ((i+1)))
                                        self._handleThreadResult(threadList[i].getResult(), True)
                                        threadList[i].killEmulator()
                                        threadList[i].join(10)
                                    else:
                                        self.log.debug('Thread %d successfully terminated' % ((i+1)))
                                        self._handleThreadResult(threadList[i].getResult())
                                    numFinishedApps += 1
                                    threadList[i] = None
                                    threadActiveMask[i] = False
                                    numRunningThreads -= 1                                    

                        # Sleep
                        time.sleep(10)

                    # Check for end
                    if numFinishedApps == len(appList):
                        break
                    
                except KeyboardInterrupt:
                    self.log.write('KeyboardInterrupt detected, stop threads')
                    for runnerThread in threadList:
                        if not runnerThread is None:
                            runnerThread.cancelFlag = True
                            runnerThread.join(60) # Wait until finished, max 1min
                            self._handleThreadResult(runnerThread.getResult())
                            if runnerThread.isAlive():
                                runnerThread.killEmulator()
                                runnerThread.join(10)
                    break
                        
                except Exception, ex:
                    traceback.print_exc(file=self.log.log)
                    
        else: # self.mode == TaintDroidRunnerMode.INTERACTIVE_MODE:
            # Initial check
            if self.appDir is not None:
                raise TaintDroidRunnerError('Interactive mode can only work with one app')
            
            # Determine logger
            threadLogger = self.log
            if self.storeLogInFile:
                logFileName = self._getAppThreadLogFile(app.getId(), app.getApkName())
                logFile = '%s%s' % (self._getLogDirPath(), logFileName)
                threadLogFileList.append(logFileName)
                threadLogger = Logger(theLevel=self.log.level,
                                      theMode=LogMode.FILE,
                                      theLogFile=logFile,
                                      thePrintAlwaysFlag=True)
                
            # Inits
            localSimulationSteps = 4095 # all
            localNumMonkeyEvents = self.numMonkeyEvents

            while True:
                try:
                    self.log.write('####################')
                    self.log.write('# Interactive mode #')
                    self.log.write('####################')
                                
                    self.log.write('Current simulation steps: %s' % SimulationSteps.getStepsAsString(localSimulationSteps))
                    self.log.write('Current num monkey events: %d' % localNumMonkeyEvents)
                    self.log.write('\nChoose')
                    self.log.write('(0) Run')
                    self.log.write('(1) Choose steps')
                    self.log.write('(2) Determine monkey events')
                    self.log.write('(9) Quit')
                    cmd = raw_input('Your choice: ')
                    cmd = int(cmd)
                    if cmd == 0: # run
                        runnerThread = RunnerThread(self, theApp=appList[0], theLogger=threadLogger)
                        runnerThread.simulationSteps = localSimulationSteps
                        runnerThread.numMonkeyEvents = localNumMonkeyEvents
                        runnerThread.start()
                        self.log.debug('Runner thread started')
                        try:
                            while True:
                                time.sleep(10)
                                if not runnerThread.isAlive():
                                    break
                        except KeyboardInterrupt:
                            self.log.debug('KeyboardInterrupt detected, stop threads')
                            runnerThread.cancelFlag = True
                            runnerThread.join(60) # Wait until finished, max 1min
                        except Exception, ex:
                            raise ex
                        self._handleThreadResult(runnerThread.getResult())
                    elif cmd == 1: # steps
                        localSimulationSteps = int(raw_input('Simulations steps: '))
                    elif cmd == 2: # monkey events
                        localNumMonkeyEvents = int(raw_input('Number of monkey events: '))
                    elif cmd == 9: # quit
                        break
                    else:
                        self.log.write('Invalid command: %s...' % str(cmd))
                except ValueError, ve:
                    self.log.write('Invalid command...')

        # Store results
        self._handleMainResult(threadLogFileList)
            

    def _handleThreadResult(self, theThreadResult, theBadCancelationFlag=False):
        """
        Adds the thread results to the result list.
        In case of the report mode the report is stored.
        In case of the MS mode the database is filled.
        """
        if not theThreadResult.has_key('endTime'):
            theThreadResult['endTime'] = datetime.datetime.now()

        # Report mode
        if self.mode == TaintDroidRunnerMode.REPORT_MODE:            
            # Generate app report
            if theBadCancelationFlag:
                theThreadResult['badCancelationFlag'] = ''
            self.log.debug(theThreadResult)
            appId = theThreadResult['app'].getId()
            reportName = self._getReportName(self.reportPath, appId)
            reportFile = '%s%s' % (self.reportPath, reportName)
            try:
                ReportGenerator.generateAppReport(reportFile, theThreadResult)
            except Exception, ex:
                self.log.write('Error during report generation: %s' % str(ex))
                    
            # Add to result list
            if theThreadResult.has_key('log'):
                numCallAction = theThreadResult['log'].getNumLogEntries(theType=CallActionLogEntry)
                numCipherUsage = theThreadResult['log'].getNumLogEntries(theType=CipherUsageLogEntry)
                numFileSystem = theThreadResult['log'].getNumLogEntries(theType=FileSystemLogEntry)
                numNetwork = theThreadResult['log'].getNumLogEntries(theType=NetworkSendLogEntry)
                numSSL = theThreadResult['log'].getNumLogEntries(theType=SSLLogEntry)
                numSMS = theThreadResult['log'].getNumLogEntries(theType=SendSmsLogEntry)
                
            else:
                numCallAction = -1
                numCipherUsage = -1
                numFileSystem = -1
                numNetwork = -1
                numSSL = -1
                numSMS = -1                

            numErrors = len(theThreadResult['errorList'])
            if theBadCancelationFlag:
                numErrors += 1
                
            reportResultEntry = {'id' : appId,
                                 'appPackage' : theThreadResult['app'].getPackage(),
                                 'appPath' : theThreadResult['app'].getApk(),
                                 'reportName' : reportName,
                                 'numCallAction' : numCallAction,
                                 'numCipherUsage' : numCipherUsage,
                                 'numFileSystem' : numFileSystem,
                                 'numNetwork' : numNetwork,
                                 'numSSL' : numSSL,
                                 'numSMS' : numSMS,
                                 'numErrors' : numErrors}
                        
            self.resultVec.append(reportResultEntry)

        # MS mode
        elif self.mode == TaintDroidRunnerMode.MS_MODE:
            # Generate app report
            if theBadCancelationFlag:
                theThreadResult['badCancelationFlag'] = ''
            self.log.debug(theThreadResult)
            appId = theThreadResult['app'].getId()
            reportName = self._getReportName(self.reportPath, appId)
            reportFile = '%s%s' % (self.reportPath, reportName)
            try:
                ReportGenerator.generateAppReport(reportFile, theThreadResult)
            except Exception, ex:
                self.log.write('Error during report generation: %s' % str(ex))
                
            # Store infos in ms database
            reportStatus = 'ok'
            if theBadCancelationFlag:
                reportStatus = 'aborted and not terminated'
            elif len(theThreadResult['errorList']) > 0:
                reportStatus = 'finished with errors'
            self.msDb.connect()
            reportId = self.msDb.storeReport(appId,
                                             theFilesystemPosition=os.path.abspath(reportFile),
                                             theTypeOfReport='HTML',
                                             theAnalyzerId=1,
                                             theStatus=reportStatus,
                                             theStartTime=theThreadResult['startTime'],
                                             theEndTime=theThreadResult['endTime'])
            self.msDb.commit()
            self.msDb.close()

        # JSON mode
        elif self.mode == TaintDroidRunnerMode.JSON_MODE:            
            # Generate app report
            if theBadCancelationFlag:
                theThreadResult['badCancelationFlag'] = ''
            self.log.debug(theThreadResult)
            appId = theThreadResult['app'].getId()
            reportName = self._getReportName(self.reportPath, appId)
            reportFile = '%s%s' % (self.reportPath, reportName)
            try:
                ReportGenerator.generateAppReport(reportFile, theThreadResult)
            except Exception, ex:
                self.log.write('Error during report generation: %s' % str(ex))
                    
            # Add to result list
            if theThreadResult.has_key('log'):
                numCallAction = theThreadResult['log'].getNumLogEntries(theType=CallActionLogEntry)
                numCipherUsage = theThreadResult['log'].getNumLogEntries(theType=CipherUsageLogEntry)
                numFileSystem = theThreadResult['log'].getNumLogEntries(theType=FileSystemLogEntry)
                numNetwork = theThreadResult['log'].getNumLogEntries(theType=NetworkSendLogEntry)
                numSSL = theThreadResult['log'].getNumLogEntries(theType=SSLLogEntry)
                numSMS = theThreadResult['log'].getNumLogEntries(theType=SendSmsLogEntry)
                
            else:
                numCallAction = -1
                numCipherUsage = -1
                numFileSystem = -1
                numNetwork = -1
                numSSL = -1
                numSMS = -1                

            numErrors = len(theThreadResult['errorList'])
            if theBadCancelationFlag:
                numErrors += 1

            logcatFileName = ''
            if theThreadResult.has_key('logcatFileName'):
                logcatFileName = theThreadResult['logcatFileName']
            reportResultEntry = {'id' : appId,
                                 'appPackage' : theThreadResult['app'].getPackage(),
                                 'appPath' : theThreadResult['app'].getApk(),
                                 'reportName' : reportName,
                                 'startTime' : theThreadResult['startTime'],
                                 'endTime' : theThreadResult['endTime'],
                                 'appMd5Hash' : theThreadResult['app'].getMd5Hash(),
                                 'logcatFileName' : logcatFileName,
                                 'numCallAction' : numCallAction,
                                 'numCipherUsage' : numCipherUsage,
                                 'numFileSystem' : numFileSystem,
                                 'numNetwork' : numNetwork,
                                 'numSSL' : numSSL,
                                 'numSMS' : numSMS,
                                 'numErrors' : numErrors}
                        
            self.resultVec.append(reportResultEntry)

    def _handleMainResult(self, theThreadLogFileList):
        """
        Handels the main result
        """
        if self.mode == TaintDroidRunnerMode.REPORT_MODE:
            endTime = datetime.datetime.now()
            report = {'workingDir' : Utils.addSlashToPath(os.getcwd()),
                      'startTime' : self.startTime,
                      'endTime' : endTime,
                      'appList' : self.resultVec,
                      'numThreads' : self.numThreads,
                      'emulatorStartPort' : self.emulatorStartPort,
                      'cleanImageDir' : self.imageDirPath,
                      'mainLogFile' : Utils.splitFileIntoDirAndName(self.log.logFile)[1],
                      'threadLogFileList' : theThreadLogFileList}
            reportFile = '%sreport.html' % (self.reportPath)
            ReportGenerator.generateMainReport(reportFile, report)

        elif self.mode == TaintDroidRunnerMode.JSON_MODE:
            endTime = datetime.datetime.now()
            report = {'workingDir' : Utils.addSlashToPath(os.getcwd()),
                      'startTime' : self.startTime,
                      'endTime' : endTime,
                      'appList' : self.resultVec,
                      'numThreads' : self.numThreads,
                      'emulatorStartPort' : self.emulatorStartPort,
                      'cleanImageDir' : self.imageDirPath,
                      'mainLogFile' : Utils.splitFileIntoDirAndName(self.log.logFile)[1],
                      'threadLogFileList' : theThreadLogFileList}
            reportFile = '%sreport.html' % (self.reportPath)
            ReportGenerator.generateMainReport(reportFile, report)

            jsonFileName = '%sreport.json' % (self.reportPath)
            mainReport = MainReportEntry(workingDir=Utils.addSlashToPath(os.getcwd()),
                                         startTime='%s %s' % (Utils.getDateAsString(self.startTime), Utils.getTimeAsString(self.startTime)),
                                         endTime='%s %s' % (Utils.getDateAsString(endTime), Utils.getTimeAsString(endTime)),
                                         appList=[])
            for appResult in self.resultVec:
                appReport = AppReportEntry(id=appResult['id'],
                                           appPackage=appResult['appPackage'],
                                           appPath=appResult['appPath'],
                                           logcatFile=appResult['logcatFileName'],
                                           md5Hash=appResult['appMd5Hash'],
                                           startTime='%s %s' % (Utils.getDateAsString(appResult['startTime']), Utils.getTimeAsString(appResult['startTime'])),
                                           endTime='%s %s' % (Utils.getDateAsString(appResult['endTime']), Utils.getTimeAsString(appResult['endTime'])))
                mainReport.appList.append(appReport)

            jsonFactory = JsonFactory()
            jsonReportStr = jsonFactory.py2Json(mainReport)
            jsonFile = open(jsonFileName, "w")
            jsonFile.write(jsonReportStr)
            

# ================================================================================
# Main method
# ================================================================================

def main():
    # Parse options
    parser = OptionParser(usage='usage: %prog [options] mode', version='%prog 0.4')    
    parser.add_option('-a', '--app', metavar='<app>', help='Set path to Android app to run in TaintDroid')
    parser.add_option('-d', '--appDir', metavar='<directory>', help='Set directory in which all Android apps should be run in TaintDroid')
    
    parser.add_option('-i', '--imageDirPath', metavar='<path>', help='Set path to the TaintDroid 2.3 image files zImage, system.img, ramdisk.img, and sdcard.img')
    parser.add_option('-t', '--numThreads', metavar='#', default=1, help='Number of threads to be used')
    parser.add_option('', '--maxThreadRuntime', metavar='<secs>', default=300, help='Maximum seconds for thread')
    parser.add_option('', '--emulatorStartPort', metavar='<port>', default=5554, help='First emulator port (has to be an even number)')

    parser.add_option('', '--reportPathSuffix', metavar='<path>', help='Report directory in which all files are stored (date is appended)')
    
    parser.add_option('-l', '--logPathSuffix', metavar='<path>', help='Set path to directory in which log and logcat files should be stored')
    parser.add_option('', '--storeLogInFile', action='store_true', default=False, help='Set to true (1) if outputs should be logged in separate file.')
    parser.add_option('', '--maxLogcatSize', metavar='kBytes', default=4096, help='Define the maximum logcat size in kBytes (logcat is ringbuffer), default is 4096kByes')

    parser.add_option('', '--sdkPath', metavar='<path>', help='Set path to Android SDK')
    parser.add_option('', '--avdName', metavar='<name>', help='Set the name of the AVD to be used')

    parser.add_option('', '--runHeadless', action='store_true', dest='headless', default=False, help='Run emulator without window.')
    
    parser.add_option('', '--numMonkeyEvents', metavar='#', default='500', help='Define number of monkey events to be executed (split into up to 5 separate runs).')    
    parser.add_option('', '--cleanUpImageDir', action='store_false', default=True, help='Set to false (0) if image dir should not be removed after run.')
    parser.add_option('', '--sleepTime', metavar='<secs>', default='60', help='Set time to sleep during simulation.')
    
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=False)
    parser.add_option('-q', '--quiet', action='store_false', dest='verbose')    
    
    (options, args) = parser.parse_args()
    mode = 'default'
    if len(args) == 1:
        mode = args[0]

    # TaintDroidRunner
    tdroidRunner = TaintDroidRunner(theMode=mode, theReportPathSuffix=options.reportPathSuffix, theLogPathSuffix=options.logPathSuffix)    

    # Run TaintDroidRunner    
    tdroidRunner.app = options.app
    tdroidRunner.appDir = options.appDir
    
    tdroidRunner.imageDirPath = options.imageDirPath
    tdroidRunner.numThreads = int(options.numThreads)
    tdroidRunner.maxThreadRuntime = int(options.maxThreadRuntime)
    tdroidRunner.emulatorStartPort = int(options.emulatorStartPort)    
    
    if not tdroidRunner.storeLogInFile:
        tdroidRunner.storeLogInFile = options.storeLogInFile

    tdroidRunner.maxLogcatSize = int(options.maxLogcatSize)

    tdroidRunner.sdkPath = options.sdkPath
    tdroidRunner.avdName = options.avdName
    tdroidRunner.runHeadless = options.headless
    tdroidRunner.numMonkeyEvents = int(options.numMonkeyEvents)
    tdroidRunner.cleanUpImageDir = options.cleanUpImageDir
    tdroidRunner.sleepTime = int(options.sleepTime)

    tdroidRunner.startTime = datetime.datetime.now()

    # Build logger
    logLevel = LogLevel.INFO
    if options.verbose:
        logLevel = LogLevel.DEBUG

    if options.storeLogInFile or tdroidRunner.mode == TaintDroidRunnerMode.REPORT_MODE:
        logger = Logger(theLevel=logLevel,
                        theMode=LogMode.FILE,
                        theLogFile='%staintdroid_runner_main.log' % (tdroidRunner._getLogDirPath()),
                        thePrintAlwaysFlag=True)
    else:
        logger=Logger(theLevel=logLevel)
    tdroidRunner.log = logger

    # Run
    tdroidRunner.run()
    

if __name__ == '__main__':
    main()

