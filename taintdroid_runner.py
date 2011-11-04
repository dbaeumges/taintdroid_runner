################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
# Co-Author: mspreitz
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

from apk_wrapper import APKWrapper, APKWrapperError
from emulator_client import *
from emulator_telnet_client import *
from optparse import OptionParser
from taintlog_analyzer import TaintLogAnalyzer, TaintLogAnalyzerError
from threading import Thread
from utils import Logger, LogLevel

import datetime
import os
import shutil
import time
import traceback


# ================================================================================
# TaintDroid Runner Enums
# ================================================================================
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
    WAIT_FOR_RAW_INPUT  = 2048

    
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
    def __init__(self, theTDRunnerMain, theAppList, theLogger):
        Thread.__init__(self)

        self.tdRunnerMain = theTDRunnerMain
        self.appList = theAppList
        self.log = theLogger
        self.simulationSteps = 2047
        self.numMonkeyEvents = self.tdRunnerMain.numMonkeyEvents

        self.resultList = []

        self.cancelFlag = False # Flag for canceling run

    def __checkForCancelation(self):
        if self.cancelFlag:
            raise KeyboardInterrupt
        
    def run(self):
        """
        """
        # Debug infos
        self.log.debug('simulationSteps: %d' % self.simulationSteps)
        self.log.debug('numMonkeyEvents: %d' % self.numMonkeyEvents)
        
        # Check for empty app list (interactive mode)
        simulationSteps = self.simulationSteps
        if len(self.appList) == 0:
            # Fake APK
            try:
                app = APKWrapper('tdRunnerGeneric.apk', self.tdRunnerMain.sdkPath, self.log)
            except:
                pass

            app.package = 'taintDroidRunner.generic.app'
            self.appList.append(app)
            
            # Change simulation steps
            simulationSteps &= ~SimulationSteps.INSTALL
            simulationSteps &= ~SimulationSteps.START
                
        # Run apps    
        for app in self.appList:
            # Init clean image dir
            imageDirPath = self._initCleanImageDir(self.tdRunnerMain.imageDirPath, app.getApkFileName())
            try:
                # Check for calcelation flag
                self.__checkForCancelation()                
                
                # Start emulator
                emulator = EmulatorClient(theSdkPath=self.tdRunnerMain.sdkPath,
                                          theImageDirPath=imageDirPath,
                                          theAvdName=self.tdRunnerMain.avdName,
                                          theRunHeadlessFlag=self.tdRunnerMain.runHeadless,
                                          theLogger=self.log)                
                emulator.start()

                # Run app
                resultEntry, keyboardInterruptFlag = self.runApp(emulator, app, simulationSteps)
                self.resultList.append(resultEntry)

                # Stop emulator
                emulator.stop()
                
                # Keyboard interrupt
                if keyboardInterruptFlag:
                    raise KeyboardInterrupt
                                
            except KeyboardInterrupt:
                pass
            except Exception, ex:
                traceback.print_exc()
                raise ex
            finally:
                # CleanUp folder
                if self.tdRunnerMain.cleanUpImageDir:
                    self._cleanUpImageDir(imageDirPath)
                else:
                    self.log.info('Image dir \'%s\' will not be removed, cleanUpImageDir flag set to false.' % imageDirPath)

        self.printResult()
        

    def _initCleanImageDir(self, theImageDir, theAppName):
        """
        Build a new directory with clean images.
        Also checks if all images are available.
        Return the new folder.
        """
        imageFileList = ['ramdisk.img', 'sdcard.img', 'system.img', 'userdata.img', 'zImage']
        time = datetime.datetime.now()
        newPath = '/tmp/%s_%s_%s' % (theAppName, Utils.getDateAsString(time), Utils.getTimeAsString(time))
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
        try:
            shutil.rmtree(theImageDirPath, True)
        except OSError, ose:
            self.log.error('Error during cleaning up image dir \'%s\': %s' % (theImageDirPath, ose))

    def _storeLogAsFile(self, theLogDirPath, theFileName, theLog):
        """
        Store log in file.
        """
        if theLogDirPath != '':
            if not os.path.exists(theLogDirPath):
                os.mkdir(theLogDirPath)
        logFile = open("%s%s_log.log" % (theLogDirPath, theFileName), "w")
        logFile.write(theLog)

    def runApp(self, theEmulator, theApp, theSteps):
        """
        Runs the application and does various simulations and monkey runs.
        Afterwards a result entry is returned.
        """       
        # Init
        errorList = []
        startTime = datetime.datetime.now()

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
        self.__checkForCancelation()
        if (theSteps & SimulationSteps.INSTALL):
            try:            
                theEmulator.installApp(theApp.getApk())
            except EmulatorClientError, ecErr:
                if ecErr.getCode() != EmulatorClientError.INSTALLATION_ERROR_ALREADY_EXISTS:
                    errorList.append(ecErr)

        # Start all services
        self.__checkForCancelation()
        if (theSteps & SimulationSteps.START):
            try:
                for service in theApp.getServiceNameList():
                    theEmulator.startService(theApp.getPackage(), service)
            except EmulatorClientError, ecErr:
                errorList.append(ecErr)

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
            errorList.append(ex)

        # Wait?
        if (theSteps & SimulationSteps.WAIT_FOR_RAW_INPUT):
            raw_input('Press to end...')

        # End
        endTime = datetime.datetime.now()

        logAnalyzer = None
        try:
            # Store log in logfile
            log = theEmulator.getLog()
            self._storeLogAsFile(self.tdRunnerMain.logDirPath, theApp.getApkFileName(), log)            

            # Build LogAnalyzer
            logAnalyzer = TaintLogAnalyzer(theLogger=self.log)
            logAnalyzer.setLogString(log)
            logAnalyzer.extractLogEntries()
            logAnalyzer.postProcessLogObjects()
            
        except EmulatorClientError, ecErr:
            errorList.append(exErr)
            
        except TaintLogAnalyzerError, tlaErr:
            errorList.append(tlaErr)

        # Build result entry
        resultEntry = {'app' : theApp,
                       'errorList' : errorList,
                       'startTime' : startTime,
                       'endTime': endTime,
                       'log' : logAnalyzer}
        
        # Return
        return (resultEntry, keyboardInterruptFlag)

    def printResult(self):
        """
        Print results
        """
        self.log.write('Results\n-------')
        for result in self.resultList:
            if isinstance(result['app'], APKWrapper):
                self.log.write('- App: %s (package: %s)' % (result['app'].getApkFileName(), result['app'].getPackage()))
                self.log.write('- Time: %d-%d-%d %d:%d:%d - %d:%d:%d' % (result['startTime'].year, result['startTime'].month, result['startTime'].day, result['startTime'].hour, result['startTime'].minute, result['startTime'].second, result['endTime'].hour, result['endTime'].minute, result['endTime'].second))
                result['log'].printOverview()
            else:
                self.log.write('- App: %s' % result['app'])
                self.log.write('- Error occured during extracting information from APK: %s' % str(result['errorList'][0]))

    # ================================================================================
    # Simulations
    # ================================================================================
    def _runGsmSimulation(self, theTelnetClient):
        """
        Simulates incoming calls
        """
        self.__checkForCancelation()
        
        self.log.info('- GSM simulation')

        theTelnetClient.changeGSMState(GsmState.OFF)
        time.sleep(3)
        theTelnetClient.changeGSMState(GsmState.ON)
        time.sleep(3)

        theTelnetClient.call('+491702662662')
        time.sleep(1)
        theTelnetClient.acceptCall('+491702662662')
        time.sleep(5)
        theTelnetClient.cancelCall('+491702662662')
        time.sleep(1)
        

    def _runGeoSimulation(self, theTelnetClient):
        """
        Simulates route in China
        """
        self.__checkForCancelation()
        
        self.log.info('- Geo simulation')
        
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
        
        self.log.info('- SMS simulation')
        
        theTelnetClient.sendSms('+491702662662', 'Hi there. How are you? I am currently on a business trip in Germany. What about a short meeting?')
        time.sleep(3)
        theTelnetClient.sendSms('+491702662662', 'Ok. Fine. See you at 6pm in front of the cafe')
        time.sleep(3)

    def _runPowerSimulation(self, theTelnetClient):
        """
        Simulates Power
        """
        self.__checkForCancelation()
        
        self.log.info('- Power simulation')
        
        theTelnetClient.setBatteryPowerState(BatteryPowerState.DISCHARGING)
        time.sleep(1)
        theTelnetClient.setBatteryCapacity(5)
        time.sleep(5)
        theTelnetClient.setBatteryPowerState(BatteryPowerState.CHARGING)
        time.sleep(3)
        theTelnetClient.setBatteryCapacity(75)
        time.sleep(2)
        theTelnetClient.setBatteryPowerState(BatteryPowerState.FULL)
        time.sleep(2)

    def _runMonkey(self, theEmulator, thePackage=None, theEventCount=1000):
        """
        Runs monkey simulation and restarts simulation if package cannot be found.
        """
        self.__checkForCancelation()
        
        self.log.info('- Monkey (events=%d)' % theEventCount)
        
        try:
            theEmulator.useMonkey(thePackage, theEventCount)
        except EmulatorClientError, ecErr:
            if ecErr.getCode() == EmulatorClientError.MONKEY_ERROR and not thePackage is None:
                self.log.debug('Monkey abort detected. Restart monkey run without package.')
                theEmulator.useMonkey(theEventCount=theEventCount)
            else:
                raise ecErr

    
# ================================================================================
# TaintDroid Runner
# ================================================================================
class TaintDroidRunner:
    def __init__(self, theLogger=Logger()):
        self.log = theLogger
        
        self.app = None
        self.appDir = None

        self.sdkPath = ''
        self.imageDirPath = ''
        self.avdName = None        
        self.interactiveMode = False        
        self.runHeadless = False
        self.numMonkeyEvents = 500
        self.cleanUpImageDir = True
        self.logDirPath = ''

        self.resultVec = []


    # ================================================================================
    # Setter
    # ================================================================================
    def setApp(self, theApp):
        """
        Set app to analyze with TaintDroid
        """
        self.app = theApp

    def setAppDir(self, theAppDir):
        """
        Set directory in which apps should be run with TaintDroid
        """
        self.appDir = theAppDir

    def setSdkPath(self, thePath):
        """
        Set path to Android SDK.
        """
        self.sdkPath = thePath
    
    def setImageDirPath(self, thePath):
        """
        Set path to the TaintDroid 2.3 image files like
        zImage, system.img, ramdisk.img, sdcard.img, and userdata.img
        """
        self.imageDirPath = thePath

    def setAvdName(self, theName):
        """
        Set name of AVD to be used.
        """
        self.avdName = theName

    def setLogDirPath(self, thePath):
        """
        Set path in which logfiles should be stored.
        """
        self.logDirPath = Utils.addSlashToPath(thePath)
        
    def setRunHeadless(self, theFlag=True):
        """
        Set if emulator should run headless.
        """
        self.runHeadless = theFlag

    def setInteractiveMode(self, theFlag=True):
        """
        Set if user interactions should happen.
        """
        self.interactiveMode = theFlag

    def setNumMonkeyEvents(self, theNum):
        """
        Set number of monkey events.
        There are 5 separate runs. Each run will have n/5 events.
        """
        if theNum is not None:
            self.numMonkeyEvents = int(theNum)

    def setCleanUpImageDir(self, theFlag):
        """
        Set if image dir should be removed afterwards.
        """
        self.cleanUpImageDir = theFlag

    
    # ================================================================================
    # Helpers
    # ================================================================================
    def _getAppListInDirectory(self, theDir):
        """
        Returns the list of all .apk files within one directory.
        """
        appList = []
        for root, dirs, files in os.walk(theDir):
            for fileName in files:
                if fileName.find('.apk') != -1:
                    appList.append(os.path.join(root, fileName))
        return appList      

    def _initCleanImageDir(self, theImageDir, theAppName):
        """
        Build a new directory with clean images.
        Also checks if all images are available.
        Return the new folder.
        """
        imageFileList = ['ramdisk.img', 'sdcard.img', 'system.img', 'userdata.img', 'zImage']
        time = datetime.datetime.now()
        newPath = '/tmp/%s_%s_%s' % (theAppName, Utils.getDataAsString(time), Utils.getTimeAsString(time))
        self.log.info('Create clean image dir: %s' % newPath)
        os.mkdir(newPath)
        for imageFile in imageFileList:
            self.log.info('- Copy %s' % imageFile)
            shutil.copy2(os.path.join(theImageDir, imageFile), os.path.join(newPath, imageFile))
        return newPath
        

    # ================================================================================
    # Run
    # ================================================================================
    def run(self):
        """
        Run TaintDroid and analyze the provided applications
        """
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
            appNameList = self._getAppListInDirectory(self.appDir)
            for appName in appNameList:
                try:
                    appList.append(APKWrapper(appName, theSdkPath=self.sdkPath, theLogger=self.log))
                except APKWrapperError, apkwErr:
                    aResultEntry = {'app' : appName,
                                    'errorList' : [apkwErr]}
                    self.resultVec.append(aResultEntry)
        elif not self.interactiveMode:
            raise TaintDroidRunnerError('Neither application nor application directory set')

        # Run
        if not self.interactiveMode:
            self.log.debug('The following apps are analyzed:')
            for app in appList:
                self.log.debug('- %s (%s)' % (app.getApkFileName(), app.getApkPath()))

            # Start threads
            runnerThread = RunnerThread(self, appList, self.log)
            runnerThread.daemon = True
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
            
        else: # self.interactivemode
            # Inits
            localAppList = appList
            localSimulationSteps = 2047 # all
            localNumMonkeyEvents = self.numMonkeyEvents

            while True:
                try:
                    self.log.write('####################')
                    self.log.write('# Interactive mode #')
                    self.log.write('####################')
                
                    if len(localAppList) == 0:
                        self.log.write('Current app: None')
                    else:
                        self.log.write('Current apps:')
                        for app in localAppList:
                            self.log.write('- %s (%s)' % (app.getApkFileName(), app.getApkPath()))
                
                    self.log.write('Current simulation steps: %d' % localSimulationSteps)
                    self.log.write('Current num monkey events: %d' % localNumMonkeyEvents)
                    self.log.write('\nChoose')
                    self.log.write('(0) Run')
                    self.log.write('(1) Choose apps')
                    self.log.write('(2) Choose app directory')
                    self.log.write('(3) Choose steps')
                    self.log.write('(4) Determine monkey events')
                    self.log.write('(9) Quit')
                    cmd = raw_input('Your choice: ')
                    cmd = int(cmd)
                    if cmd == 0: # run
                        runnerThread = RunnerThread(self, localAppList, self.log)
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
                    elif cmd == 1: # app
                        inputApp = str(raw_input('Set app: '))
                        try:
                            localAppList = [APKWrapper(inputApp, theSdkPath=self.sdkPath, theLogger=self.log)]
                        except APKWrapperError, apkwErr:
                            self.log.write('App %s could not be load: %s' % (inputApp, str(apkwErr)))
                    elif cmd == 2: # app dir
                        inputDir = str(raw_input('Set directory: '))
                        localAppList = []
                        appNameList = self._getAppListInDirectory(inputDir)
                        for appName in appNameList:
                            try:
                                localAppList.append(APKWrapper(appName, theSdkPath=self.sdkPath, theLogger=self.log))
                            except APKWrapperError, apkwErr:
                                self.log.write('Failed to add %s: %s' % (appName, str(apkwErr)))
                    elif cmd == 3: # steps
                        localSimulationSteps = int(raw_input('Simulations steps: '))
                    elif cmd == 4: # monkey events
                        localNumMonkeyEvents = int(raw_input('Number of monkey events: '))
                    elif cmd == 9: # quit
                        break
                    else:
                        self.log.write('Invalid command: %s...' % str(cmd))
                except ValueError, ve:
                    self.log.write('Invalid command...')


# ================================================================================
# Main method
# ================================================================================

def main():
    # Parse options
    parser = OptionParser(usage='usage: %prog [options]', version='%prog 0.1')    
    parser.add_option('-a', '--app', metavar='<app>', help='Set path to Android app to run in TaintDroid')
    parser.add_option('-d', '--appDir', metavar='<directory>', help='Set directory in which all Android apps should be run in TaintDroid')
    parser.add_option('', '--sdkPath', metavar='<path>', help='Set path to Android SDK')
    parser.add_option('-i', '--imageDirPath', metavar='<path>', help='Set path to the TaintDroid 2.3 image files zImage, system.img, ramdisk.img and sdcard.img')
    parser.add_option('-l', '--logDirPath', metavar='<path>', help='Set path to directory in which log files should be stored')
    
    parser.add_option('', '--numMonkeyEvents', metavar='#', help='Define number of monkey events to be executed (split into up to 5 separate runs).')
    parser.add_option('', '--runHeadless', action='store_true', dest='headless', default=False, help='Run emulator without window.')
    parser.add_option('', '--cleanUpImageDir', action='store_false', default=True, help='Set to false (0) if image dir should not be removed after run.')
    
    parser.add_option('', '--avdName', metavar='<name>', help='Set the name of the AVD to be used')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=False)
    parser.add_option('-q', '--quiet', action='store_false', dest='verbose')
    parser.add_option('', '--interactiveMode', action='store_true', default=False, help='Interactive mode.')
    
    (options, args) = parser.parse_args()

    # Run TaintDroidRunner
    if options.verbose:
        logger = Logger(LogLevel.DEBUG)
    else:
        logger = Logger()
    tdroidRunner = TaintDroidRunner(theLogger=logger)
    tdroidRunner.setApp(options.app)
    tdroidRunner.setAppDir(options.appDir)    
    tdroidRunner.setSdkPath(options.sdkPath)
    tdroidRunner.setImageDirPath(options.imageDirPath)
    tdroidRunner.setLogDirPath(options.logDirPath)
    
    tdroidRunner.setAvdName(options.avdName)
    tdroidRunner.setRunHeadless(options.headless)
    tdroidRunner.setInteractiveMode(options.interactiveMode)
    tdroidRunner.setNumMonkeyEvents(options.numMonkeyEvents)
    tdroidRunner.setCleanUpImageDir(options.cleanUpImageDir)
    
    tdroidRunner.run()
    

if __name__ == '__main__':
    main()

