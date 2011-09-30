################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
# Co-Author: mspreitz
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

from optparse import OptionParser

from emulator_client import *
from emulator_telnet_client import *
from taintlog_analyzer import TaintLogAnalyzer

import datetime
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
    def __init__(self, theVerboseFlag=True):
        self.verbose = theVerboseFlag
        self.app = None
        self.appPackage = None
        self.appDir = None

        self.emulatorPath = ''
        self.imageDirPath = ''
        self.adbPath = ''
        self.avdName = None
        
        self.emulator = None

        self.resultVec = []

    def setApp(self, theApp, thePackage=None):
        """
        Set app to analyze with TaintDroid
        """
        self.app = theApp
        self.appPackage = thePackage

    def setAppDir(self, theAppDir):
        """
        Set directory in which apps should be run with TaintDroid
        """
        self.appDir = theAppDir

    def setEmulatorPath(self, thePath):
        """
        Set path to emulator binary.
        Do ot include the emulator binary itself.
        """
        self.emulatorPath = thePath

    def setImageDirPath(self, thePath):
        """
        Set path to the TaintDroid 2.3 image files like
        zImage, system.img, ramdisk.img, and sdcard.img.
        """
        self.imageDirPath = thePath

    def setAdbPath(self, thePath):
        """
        Set path to Android debug bridge.
        Do not include the adb binary in the path.
        """
        self.adbPath = thePath

    def setAvdName(self, theName):
        """
        Set name of AVD to be used.
        """
        self.avdName = theName

    def _verifyParameters(self):
        """
        Verify the set parameters
        """
        if self.app is None:
            raise TaintDroidRunnerError('No application set')

    def init(self):
        """
        Init TaintDroid Runner.
        Check parameters and build emulator client instance
        """
        self._verifyParameters()
        self.emulator = EmulatorClient(theEmulatorPath=self.emulatorPath,
                                       theImageDirPath=self.imageDirPath,
                                       theAdbPath=self.adbPath,
                                       theAvdName=self.avdName,
                                       theVerboseFlag=self.verbose)

    def run(self, theRestartFlag=False):
        """
        Run TaintDroid and analyze the provided applications
        """
        #if theRestartFlag:
        self.emulator.start()

        startTime = datetime.datetime.now()
        logString = self.runApp(self.emulator, self.app, self.appPackage, theUninstallPackageFlag=True)
        
        endTime = datetime.datetime.now()
        logAnalyzer = TaintLogAnalyzer()
        logAnalyzer.setLogString(logString)
        logAnalyzer.extractLogEntries()
        logAnalyzer.cleanUpLogObjects()
        resultEntry = {'app' : self.app,
                       'appPackage' : self.appPackage,
                       'startTime' : startTime,
                       'endTime': endTime,
                       'log' : logAnalyzer}
        if self.appPackage is None:
            resultEntry['appPackage'] = ''
        self.resultVec.append(resultEntry)
            
        #if theRestartFlag:
        self.emulator.stop()

        self.printResult()
        

    def runApp(self, theEmulator, theApp, theAppPackage=None, theUninstallPackageFlag=False):
        """
        Runs the application and does various simulations and monkey runs.
        Afterwards the log is returned.
        """
        theEmulator.clearLog()
        
        theEmulator.installApp(theApp)

        try:
            self._runMonkey(theEmulator, theAppPackage, 1)
            self._runGsmSimulation(theEmulator.getTelnetClient())
            self._runMonkey(theEmulator, theAppPackage, 1)
            self._runGeoSimulation(theEmulator.getTelnetClient())
            self._runMonkey(theEmulator, theAppPackage, 1)
            self._runSmsSimulation(theEmulator.getTelnetClient())
            self._runMonkey(theEmulator, theAppPackage, 1)
            self._runPowerSimulation(theEmulator.getTelnetClient())
            self._runMonkey(theEmulator, theAppPackage, 5)
        except KeyboardInterrupt:
            pass
        except Exception, ex:
            raise ex
        finally:
            if theUninstallPackageFlag and not theAppPackage is None:
                theEmulator.uninstallPackage(theAppPackage)

        log = theEmulator.getLog()
        tempList = theApp.split('/')
        appName = tempList[len(tempList)-1]
        logFile = open("logfile_%s.log" % appName, "w")
        logFile.write(log)
        
        return log

    def printResult(self):
        """
        Print results
        """
        print "Results", "-------"
        for result in self.resultVec:
            print '- App: %s (package: %s)' % (result['app'], result['appPackage'])
            print '- Time: %d-%d-%d %d:%d:%d - %d:%d:%d' % (result['startTime'].year, result['startTime'].month, result['startTime'].day, result['startTime'].hour, result['startTime'].minute, result['startTime'].second, result['endTime'].hour, result['endTime'].minute, result['endTime'].second)
            result['log'].printOverview()
    
    def _runGsmSimulation(self, theTelnetClient):
        """
        Simulates incoming calls
        """       
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
        theTelnetClient.sendSms('+491702662662', 'Hi there. How are you? I am currently on a business trip in Germany. What about a short meeting?')
        time.sleep(3)
        theTelnetClient.sendSms('+491702662662', 'Ok. Fine. See you at 6pm in front of the cafe')
        time.sleep(3)

    def _runPowerSimulation(self, theTelnetClient):
        """
        Simulates Power
        """
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
        try:
            theEmulator.useMonkey(thePackage, theEventCount)
        except EmulatorClientError, ecErr:
            if ecErr.getCode() == EmulatorClientError.MONKEY_ERROR and not thePackage is None:
                if self.verbose:
                    print 'Monkey abort detected. Restart monkey run without package.'
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
    parser.add_option('', '--appPackage', metavar='<package>', help='Set application package')
    parser.add_option('', '--appDir', metavar='<directory>', help='Set directory in which all Android apps should be run in TaintDroid')
    
    parser.add_option('', '--emulatorPath', metavar='<path>', help='Set path to emulator binary')
    parser.add_option('', '--imageDirPath', metavar='<path>', help='Set path to the TaintDroid 2.3 image files zImage, system.img, ramdisk.img and sdcard.img')
    parser.add_option('', '--adbPath', metavar='<path>', help='Set path to Android Debug Bridge binary')
    parser.add_option('', '--avdName', metavar='<name>', help='Set the name of the AVD to be used')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=True)
    parser.add_option('-q', '--quiet', action='store_false', dest='verbose')
    
    (options, args) = parser.parse_args()

    # Run TaintDroidRunner
    tdroidRunner = TaintDroidRunner(theVerboseFlag=options.verbose)
    tdroidRunner.setApp(options.app, options.appPackage)
    tdroidRunner.setEmulatorPath(options.emulatorPath)
    tdroidRunner.setImageDirPath(options.imageDirPath)
    tdroidRunner.setAdbPath(options.adbPath)
    tdroidRunner.setAvdName(options.avdName)
    tdroidRunner.init()
    tdroidRunner.run()
    

if __name__ == '__main__':
    main()

