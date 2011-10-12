################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
# Co-Author: mspreitz
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

from emulator_telnet_client import EmulatorTelnetClient
from utils import Logger, Utils

import os
import signal
import subprocess
import time


# ================================================================================
# Emulator Client Error
# ================================================================================
class EmulatorClientError(Exception):
    GENERAL_ERROR = 0
    GENERAL_INSTALLATION_ERROR = 1
    INSTALLATION_ERROR_ALREADY_EXISTS = 2
    GENERAL_UNINSTALLATION_ERROR = 3
    START_EMULATOR_ERROR = 4
    ADB_RUN_ERROR = 5
    MONKEY_ERROR = 6
    
    def __init__(self, theValue, theCode=GENERAL_ERROR, theBaseError=None):        
        self.value = theValue
        self.code = theCode
        self.baseError = theBaseError

    def __str__(self):
        return repr(self.value)

    def getCode(self):
        return self.code


# ================================================================================
# Helper
# ================================================================================
def _overwriteSignalsForProcess():
    """
    Ignore the SIGINT signal by setting the handler to the standard
    signal handler SIG_IGN.
    """
    os.setpgrp()

        
# ================================================================================
# Emulator Client
# ================================================================================
class EmulatorClient:
    def __init__(self, theSdkPath='',
                       thePort=5554,
                       theImageDirPath='',
                       theRunHeadlessFlag=False,
                       theAvdName=None,
                       theLogger=Logger()):
        self.sdkPath = Utils.addSlashToPath(theSdkPath)
        self.port = thePort
        self.imageDirPath = Utils.addSlashToPath(theImageDirPath)
        self.runHeadless = theRunHeadlessFlag
        self.log = theLogger
        
        self.avdName = theAvdName

        self.emulator = None        

    def __del__(self):
        if not self.emulator is None:
            self.emulator.kill()    

    def setSdkPath(self, thePath):
        """
        Set path to Android SDK.
        """
        self.sdkPath = Utils.addSlashToPath(thePath)

    def setImageDirPath(self, thePath):
        """
        Set path to the TaintDroid 2.3 image files like
        zImage, system.img, ramdisk.img, and sdcard.img.
        """
        self.imageDirPath = Utils.addSlashToPath(thePath)    

    def setAvdName(self, theName):
        """
        Set name of AVD to be used.
        """
        self.avdName = theName    

    def start(self):
        """
        Starts the emulator with TaintDroid images
        """
        self.log.info('Start emulator')
        try:
            args = ['%semulator' % Utils.getEmulatorPath(self.sdkPath)]
            if self.avdName is not None:
                args.extend(['-avd', self.avdName])
            args.extend(['-kernel',  '%szImage' % self.imageDirPath])
            args.extend(['-system',  '%ssystem.img' % self.imageDirPath])
            args.extend(['-ramdisk', '%sramdisk.img' % self.imageDirPath])
            args.extend(['-sdcard',  '%ssdcard.img' % self.imageDirPath])
            args.extend(['-data',    '%suserdata.img' % self.imageDirPath])
            args.extend(['-port',    str(self.port)])
            if self.runHeadless:
                args.extend(['-no-window'])
            self.emulator = subprocess.Popen(args,
                                             stdout=subprocess.PIPE,
                                             stdin=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             preexec_fn=_overwriteSignalsForProcess)
        except OSError, osErr:
            raise EmulatorClientError('Failed to start emulator \'%s\': %s' % (args, osErr.strerror),
                                      theCode=EmulatorClientError.START_EMULATOR_ERROR,
                                      theBaseError=osErr)
        #if self.verbose:
        #    print self.emulator.communicate()
        
        # Wait until started
        self.runAdbCommand(['wait-for-device'])

        # Set portable mode
        self.runAdbCommand(['shell', 'setprop', 'dalvik.vm.execution-mode', 'int:portable'])

        # Wait
        time.sleep(45)

    def stop(self):
        """
        Stops the emulator
        """
        if self.emulator is None:
            raise EmulatorClientError('Emulator not startet')
        self.emulator.terminate()
        self.emulator = None

    def getTelnetClient(self):
        """
        Returns an instance of the EmulatorTelnetClient for the started emulator
        """
        return EmulatorTelnetClient(thePort=self.port, theLogger=self.log)

    def installApp(self, theApp):
        """
        Installs the provided app on the emulator
        """
        retval = self.runAdbCommand(['install', theApp])
        if retval[0].find('Success') == -1:
            if retval[0].find('INSTALL_FAILED_ALREADY_EXISTS') != -1:
                raise EmulatorClientError('Application %s already exists.' % theApp, EmulatorClientError.INSTALLATION_ERROR_ALREADY_EXISTS)
            else:
                raise EmulatorClientError('Failed to install %s: %s' % (theApp, retval[0]), EmulatorClientError.GENERAL_INSTALLATION_ERROR)

    def startAction(self, thePackage, theActivity):
        """
        Starts the specified action (without intent).
        """
        args = ['shell', 'am', 'start',
                '-n', '%s/%s' % (thePackage, theActivity)]
        self.runAdbCommand(args)
        # adb shell am start -a android.intent.action.MAIN -n com.android.browser/.BrowserActivity

    def startService(self, thePackage, theService):
        """
        Starts the specified service (without intent).
        """
        args = ['shell', 'am', 'startservice',
                '-n', '%s/%s' % (thePackage, theService)]
        self.runAdbCommand(args)
        # adb shell am startservice -c android.intent.category.defult -n com.nicky.lyyws.xmall/.MainService
    
    def uninstallPackage(self, thePackage):
        """
        Removes the provided package from the emulator.
        """
        retval = self.runAdbCommand(['uninstall', thePackage])
        if retval[0].find('Success') == -1:
            raise EmulatorClientError('Failed to uninstall %s: %s' % (thePackage, retval[0]), EmulatorClientError.UNINSTALLATION_ERROR)

    def useMonkey(self, thePackage=None, theEventCount=10000):
        """
        Runs monkey on the provided package
        """
        if thePackage is None:
            if self.log.isDebug():
                retval = self.runAdbCommand(['shell', 'monkey', '-v', str(theEventCount)])
            else:
                retval = self.runAdbCommand(['shell', 'monkey', str(theEventCount)])
        else:
            if self.log.isDebug():
                retval = self.runAdbCommand(['shell', 'monkey', '-v', '-p', thePackage, str(theEventCount)])
            else:
                retval = self.runAdbCommand(['shell', 'monkey', '-p', thePackage, str(theEventCount)])

            if retval[0].find('monkey aborted') != -1:
                raise EmulatorClientError('Failed to run monkey on %s: %s' % (thePackage, retval[0]), EmulatorClientError.MONKEY_ERROR)

    def getLog(self):
        """
        Returns the (full) logcat output
        """
        args = ['shell', 'logcat', '-d', '&&',
                '%sadb' % Utils.getAdbPath(self.sdkPath), 'shell', 'logcat', '-b', 'events', '-d', '&&',
                '%sadb' % Utils.getAdbPath(self.sdkPath), 'shell', 'logcat', '-b', 'radio', '-d']
        logcat = self.runAdbCommand(args)[0]
        return logcat

    def clearLog(self):
        """
        Clears the logcat output
        """
        self.runAdbCommand(['logcat', '-c'])
    

    def runAdbCommand(self, theArgs):
        """
        Runs a simple adb command
        """
        args = ['%sadb' % Utils.getAdbPath(self.sdkPath)]
        args.extend(theArgs)
        self.log.debug('Exec adb command: %s' % args)
        try:
            adb = subprocess.Popen(args,
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        except OSError, osErr:
            raise EmulatorClientError('Failed to run adb command \'%s\': %s' % (args, osErr.strerror),
                                      theCode=EmulatorClientError.ADB_RUN_ERROR,
                                      theBaseError=osErr)
        retval = adb.communicate()
        adb.wait()        
        self.log.debug('Result: %s' % str(retval))
        return retval
