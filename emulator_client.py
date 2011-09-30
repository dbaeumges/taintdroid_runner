################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
# Co-Author: mspreitz
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

from emulator_telnet_client import EmulatorTelnetClient
import os
import subprocess
import time


# ================================================================================
# Emulator Client Error
# ================================================================================
class EmulatorClientError(Exception):
    GENERAL_ERROR = 0
    INSTALLATION_ERROR = 1
    UNINSTALLATION_ERROR = 2
    MONKEY_ERROR = 3
    
    def __init__(self, value, code=GENERAL_ERROR):
        self.code = code
        self.value = value

    def __str__(self):
        return repr(self.value)

    def getCode(self):
        return self.code

    
# ================================================================================
# Emulator Client
# ================================================================================
class EmulatorClient:
    def __init__(self, theEmulatorPath='',
                 thePort=5554,
                 theImageDirPath='',
                 theAdbPath='',
                 theAvdName=None,
                 theVerboseFlag=True):
        self.emulatorPath = self.__addSlashToPath(theEmulatorPath)
        self.port = thePort
        self.imageDirPath = self.__addSlashToPath(theImageDirPath)
        self.adbPath = self.__addSlashToPath(theAdbPath)
        self.verbose = theVerboseFlag
        
        self.avdName = theAvdName

        self.emulator = None        

    def __del__(self):
        if not self.emulator is None:
            self.emulator.kill()

    def __addSlashToPath(self, thePath):
        if thePath == '':
            return thePath
        if thePath[len(thePath)-1] != '/':
            return thePath + '/'

    def setEmulatorPath(self, thePath):
        """
        Set path to emulator binary.
        Do ot include the emulator binary itself.
        """
        self.emulatorPath = self.__addSlashToPath(thePath)

    def setImageDirPath(self, thePath):
        """
        Set path to the TaintDroid 2.3 image files like
        zImage, system.img, ramdisk.img, and sdcard.img.
        """
        self.imageDirPath = self.__addSlashToPath(thePath)

    def setAdbPath(self, thePath):
        """
        Set path to Android debug bridge.
        Do not include the adb binary in the path.
        """
        self.adbPath = self.__addSlashToPath(thePath)

    def setAvdName(self, theName):
        """
        Set name of AVD to be used.
        """
        self.avdName = theName

    def start(self):
        """
        Starts the emulator with TaintDroid images
        """
        args = ['%semulator' % self.emulatorPath]
        if self.avdName is not None:
            args.extend(['-avd', self.avdName])
        args.extend(['-kernel',  '%szImage' % self.imageDirPath])
        args.extend(['-system',  '%ssystem.img' % self.imageDirPath])
        args.extend(['-ramdisk', '%sramdisk.img' % self.imageDirPath])
        args.extend(['-sdcard',  '%ssdcard.img' % self.imageDirPath])
        args.extend(['-data',  '%suserdata.img' % self.imageDirPath])
        args.extend(['-port',    str(self.port)])
        self.emulator = subprocess.Popen(args,
                                         stdout=subprocess.PIPE,
                                         stdin=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        #if self.verbose:
        #    print self.emulator.communicate()
        
        # Wait until started
        self.runSimpleAdbCommand(['wait-for-device'])

        # Set portable mode
        self.runSimpleAdbCommand(['shell', 'setprop', 'dalvik.vm.execution-mode', 'int:portable'])

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
        return EmulatorTelnetClient(thePort=self.port, theVerboseFlag=self.verbose)

    def installApp(self, theApp):
        """
        Installs the provided app on the emulator
        """
        retval = self.runSimpleAdbCommand(['install', theApp])
        if retval[0].find('Success') == -1:
            raise EmulatorClientError('Failed to install %s: %s' % (theApp, retval[0]), EmulatorClientError.INSTALLATION_ERROR)

    def uninstallPackage(self, thePackage):
        """
        Removes the provided package from the emulator
        """
        retval = self.runSimpleAdbCommand(['uninstall', thePackage])
        if retval[0].find('Success') == -1:
            raise EmulatorClientError('Failed to uninstall %s: %s' % (thePackage, retval[0]), EmulatorClientError.UNINSTALLATION_ERROR)

    def useMonkey(self, thePackage=None, theEventCount=10000):
        """
        Runs monkey on the provided package
        """
        if thePackage is None:
            if self.verbose:
                retval = self.runSimpleAdbCommand(['shell', 'monkey', '-v', str(theEventCount)])
            else:
                retval = self.runSimpleAdbCommand(['shell', 'monkey', str(theEventCount)])
        else:
            if self.verbose:
                retval = self.runSimpleAdbCommand(['shell', 'monkey', '-v', '-p', thePackage, str(theEventCount)])
            else:
                retval = self.runSimpleAdbCommand(['shell', 'monkey', '-p', thePackage, str(theEventCount)])

            if retval[0].find('monkey aborted') != -1:
                raise EmulatorClientError('Failed to run monkey on %s: %s' % (thePackage, retval[0]), EmulatorClientError.MONKEY_ERROR)

    def getLog(self):
        """
        Returns the (full) logcat output
        """
        log = subprocess.Popen(['%sadb' % self.adbPath, 'shell', 'logcat', '-d', '&&',
                                '%sadb' % self.adbPath, 'shell', 'logcat', '-b', 'events', '-d', '&&',
                                '%sadb' % self.adbPath, 'shell', 'logcat', '-b', 'radio', '-d'],
                               stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        logcat = log.communicate()[0]
        log.wait()
        return logcat

    def clearLog(self):
        """
        Clears the logcat output
        """
        self.runSimpleAdbCommand(['logcat', '-c'])
    

    def runSimpleAdbCommand(self, theArgs):
        """
        Runs a simple adb command
        """
        args = ['%sadb' % self.adbPath]
        args.extend(theArgs)
        if self.verbose:
            print 'Exec adb command: %s' % args
            
        adb = subprocess.Popen(args,
                               stdout=subprocess.PIPE,
                               stdin=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        retval = adb.communicate()
        adb.wait()
        
        if self.verbose:
            print retval        
        return retval
