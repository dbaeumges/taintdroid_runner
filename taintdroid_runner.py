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
from taintlog_analyzer import TaintLogAnalyzer
from utils import Logger, LogLevel

import datetime
import os
import shutil
import time


# ================================================================================
# TaintDroid Runner Error
# ================================================================================
class TaintDroidRunnerError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    
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
        self.runHeadless = False
        self.stopAfterInstall = False
        self.numMonkeyEvents = 500
        self.cleanUpImageDir = True

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

    def setRunHeadless(self, theFlag=True):
        """
        Set if emulator should run headless.
        """
        self.runHeadless = theFlag

    def setStopAfterInstall(self, theFlag=True):
        """
        Set if TaintDroid Runner should stop after installation
        and wait for user input.
        """
        self.stopAfterInstall = theFlag

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
    def _verifyParameters(self):
        """
        Verify the set parameters.
        """
        if self.app is None and self.appDir is None:
            raise TaintDroidRunnerError('Neither application nor application directory set')
        elif self.app is not None and self.appDir is not None:
            raise TaintDroidRunnerError('Both application and application directory set')

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
        newPath = '/tmp/%s_%d%d%d_%d%d%d' % (theAppName, time.year, time.month, time.day, time.hour, time.minute, time.second)
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
        # Verifiy parameters
        self._verifyParameters()
        
        # Build list of apps to be run        
        appList = []        
        if self.app is not None:
            try:
                appList.append(APKWrapper(self.app, theSdkPath=self.sdkPath, theLogger=self.log))
            except APKWrapperError, apkwErr:
                aResultEntry = {'app' : self.app,
                                'errorList' : [apkwErr]}
                self.resultVec.append(aResultEntry)
        else:
            appNameList = self._getAppListInDirectory(self.appDir)
            for appName in appNameList:
                try:
                    appList.append(APKWrapper(appName, theSdkPath=self.sdkPath, theLogger=self.log))
                except APKWrapperError, apkwErr:
                    aResultEntry = {'app' : appName,
                                    'errorList' : [apkwErr]}
                    self.resultVec.append(aResultEntry)

        self.log.debug('The following apps are analyzed:\n')
        for app in appList:
            self.log.debug('- %s (%s)' % (app.getApkFileName(), app.getApkPath()))

        # Run apps
        for app in appList:
            # Init clean image dir
            imageDirPath = self._initCleanImageDir(self.imageDirPath, app.getApkFileName())
            try:
                emulator = EmulatorClient(theSdkPath=self.sdkPath,
                                          theImageDirPath=imageDirPath,
                                          theAvdName=self.avdName,
                                          theRunHeadlessFlag=self.runHeadless,
                                          theLogger=self.log)
            
                # Start emulator
                emulator.start()

                # Run app
                resultEntry, keyboardInterruptFlag = self.runApp(emulator, app)
                self.resultVec.append(resultEntry)

                # Stop emulator
                emulator.stop()

                # Keyboard interrupt
                if keyboardInterruptFlag:
                    raise KeyboardInterrupt
                                
            except KeyboardInterrupt:
                pass
            except Exception, ex:
                raise ex
            finally:
                # CleanUp folder
                if self.cleanUpImageDir:
                    shutil.rmtree(imageDirPath)
                else:
                    self.log.info('Image dir \'%s\' will not be removed, cleanUpImageDir flag set to false.' % imageDirPath)

        # Print results
        self.printResult()
        

    def runApp(self, theEmulator, theApp):
        """
        Runs the application and does various simulations and monkey runs.
        Afterwards a result entry is returned.
        """       
        # Init
        errorList = []
        startTime = datetime.datetime.now()
        if self.numMonkeyEvents % 5 == 0:
            numMonkeyEventsFirst = self.numMonkeyEvents / 5
            numMonkeyEventsLast = numMonkeyEventsFirst
        else:
            numMonkeyEventsFirst = self.numMonkeyEvents / 5
            numMonkeyEventsLast = self.numMonkeyEvents - (numMonkeyEventsFirst * 4)
        
        # Clear log
        theEmulator.clearLog()

        # Install app
        try:            
            theEmulator.installApp(theApp.getApk())
        except EmulatorClientError, ecErr:
            if ecErr.getCode() != EmulatorClientError.INSTALLATION_ERROR_ALREADY_EXISTS:
                errorList.append(ecErr)

        # Start all services
        try:
            for service in theApp.getServiceNameList():
                theEmulator.startService(theApp.getPackage(), service)
        except EmulatorClientError, ecErr:
            errorList.append(ecErr)

        # Stop?
        if self.stopAfterInstall:
            raw_input('stopAfterInstall set. Wait for user input to go on.')

        # Run simulation
        keyboardInterruptFlag = False
        try:
            self.log.info('Run simulation')
            self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsFirst)
            self._runGsmSimulation(theEmulator.getTelnetClient())
            self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsFirst)
            self._runGeoSimulation(theEmulator.getTelnetClient())
            self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsFirst)
            self._runSmsSimulation(theEmulator.getTelnetClient())
            self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsFirst)
            self._runPowerSimulation(theEmulator.getTelnetClient())
            self._runMonkey(theEmulator, theApp.getPackage(), numMonkeyEventsLast)
        except KeyboardInterrupt:
            self.log.write('Keyboard interrupt detected: store log, postprocess, and finish')
            keyboardInterruptFlag = True
        except Exception, ex:
            errorList.append(ex)

        # End
        endTime = datetime.datetime.now()

        logAnalyzer = None
        try:
            # Store log in logfile
            log = theEmulator.getLog()
            logFile = open("logfile_%s.log" % theApp.getApkFileName(), "w")
            logFile.write(log)

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
        for result in self.resultVec:
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
        self.log.info('- SMS simulation')
        
        theTelnetClient.sendSms('+491702662662', 'Hi there. How are you? I am currently on a business trip in Germany. What about a short meeting?')
        time.sleep(3)
        theTelnetClient.sendSms('+491702662662', 'Ok. Fine. See you at 6pm in front of the cafe')
        time.sleep(3)

    def _runPowerSimulation(self, theTelnetClient):
        """
        Simulates Power
        """
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
# Main method
# ================================================================================

def main():
    # Parse options
    parser = OptionParser(usage='usage: %prog [options]', version='%prog 0.1')    
    parser.add_option('-a', '--app', metavar='<app>', help='Set path to Android app to run in TaintDroid')
    parser.add_option('-d', '--appDir', metavar='<directory>', help='Set directory in which all Android apps should be run in TaintDroid')

    parser.add_option('', '--numMonkeyEvents', metavar='#', help='Define number of monkey events to be executed (split into 5 separate runs).')
    parser.add_option('', '--runHeadless', action='store_true', dest='headless', default=False, help='Run emulator without window.')
    parser.add_option('', '--cleanUpImageDir', action='store_false', default=True, help='Set to false (0) if image dir should not be removed after run.')
    parser.add_option('', '--sdkPath', metavar='<path>', help='Set path to Android SDK')
    parser.add_option('', '--imageDirPath', metavar='<path>', help='Set path to the TaintDroid 2.3 image files zImage, system.img, ramdisk.img and sdcard.img')
    parser.add_option('', '--avdName', metavar='<name>', help='Set the name of the AVD to be used')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=False)
    parser.add_option('-q', '--quiet', action='store_false', dest='verbose')
    parser.add_option('', '--stopAfterInstall', action='store_true', dest='stopAfterInstall', default=False)
    
    (options, args) = parser.parse_args()

    # Run TaintDroidRunner
    if options.verbose:
        print 'verbose'
        logger = Logger(LogLevel.DEBUG)
    else:
        logger = Logger()
    tdroidRunner = TaintDroidRunner(theLogger=logger)
    tdroidRunner.setApp(options.app)
    tdroidRunner.setAppDir(options.appDir)    
    tdroidRunner.setSdkPath(options.sdkPath)
    tdroidRunner.setImageDirPath(options.imageDirPath)
    tdroidRunner.setAvdName(options.avdName)
    tdroidRunner.setRunHeadless(options.headless)
    tdroidRunner.setStopAfterInstall(options.stopAfterInstall)
    tdroidRunner.setNumMonkeyEvents(options.numMonkeyEvents)
    tdroidRunner.setCleanUpImageDir(options.cleanUpImageDir)
    tdroidRunner.run()
    

if __name__ == '__main__':
    main()

