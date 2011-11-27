################################################################################
# (c) 2011
# Author: Daniel Baeumges dbaeumges@googlemail.com
#
# This program is distributed WITHOUT ANY WARRANTY.
#
################################################################################

from common import Logger

import telnetlib


# ================================================================================
# Emulator Telnet Client Error Obejct
# ================================================================================ 
class EmulatorTelnetClientError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# ================================================================================
# Constant/State Classes
# ================================================================================
class GsmState:
    """
    Class with constants for GPRS and GSM state
    """
    UNREGISTERED = 'unregistered' # no network available (off)
    OFF          = 'off'          # no network available (off)
    HOME         = 'home'         # on local network, non-roaming (on)
    ON           = 'on'           # on local network, non-roaming (on)
    ROAMING      = 'roaming'      # on roaming network
    SEARCHING    = 'searching'    # searching networks
    DENIED       = 'denied'       # emergency calls only

    ALLOWED_VALUES = ['unregistered', 'off', 'home', 'on', 'roaming', 'searching', 'denied']

    @staticmethod
    def isValidValue(theValue):
        if theValue in GsmState.ALLOWED_VALUES:
            return True
        return False

class BatteryPowerState:
    """
    Class with constants for battery power state
    """
    UNKOWN       = 'unkown'
    CHARGING     = 'charging'
    DISCHARGING  = 'discharging'
    NOT_CHARGING = 'not-charging'
    FULL         = 'full'

    ALLOWED_VALUES = ['unkown', 'charging', 'discharging', 'not-charging', 'full']

    @staticmethod
    def isValidValue(theValue):
        if theValue in BatteryPowerState.ALLOWED_VALUES:
            return True
        return False

class BatteryHealthState:
    """
    Class with constants for battery health state
    """
    UNKNOWN     = 'unkown'
    GOOD        = 'good'
    OVERHEAT    = 'overheat'
    DEAD        = 'dead'
    OVERVOLTAGE = 'overvoltage'
    FAILURE     = 'failure'

    ALLOWED_VALUES = ['unkown', 'good', 'overheat', 'dead', 'overvoltage', 'failure']

    @staticmethod
    def isValidValue(theValue):
        if theValue in BatteryHealthState.ALLOWED_VALUES:
            return True
        return False

# ================================================================================
# Emulator Telnet Client
# ================================================================================ 
class EmulatorTelnetClient:
    def __init__(self, theHost='localhost', thePort=5554, theLogger=Logger()):        
        self.host = theHost
        self.port = thePort
        self.log = theLogger
        self.tn = telnetlib.Telnet()


    # ================================================================================
    # GSM (Calls)
    # ================================================================================ 
    def call(self, thePhoneNumber):
        """
        'gsm call <phonenumber>'
        Simulate new inbound phone call.
        """
        self.__runCommand('gsm call %s' % str(thePhoneNumber))

    def acceptCall(self, theRemoteNumber):
        """
        'gsm accept <remoteNumber>'
        Change the state of a call to 'active'. This is only possible
        if the call is in the 'waiting' or 'held' state.
        """
        self.__runCommand('gsm accept %s' % str(theRemoteNumber))

    def cancelCallAsBusy(self, theRemoteNumber):
        """
        'gsm busy <remoteNumber>'
        Closes an outbound call, reporting the remote phone as busy.
        Only possible if the call is 'waiting'.
        """
        self.__runCommand('gsm busy %s' % str(theRemoteNumber))

    def cancelCall(self, thePhoneNumber):
        """
        'gsm cancel <phonenumber>'
        Simulate the end of an inbound or outbound call
        """
        self.__runCommand('gsm cancel %s' % str(thePhoneNumber))

    def holdCall(self, theRemoteNumber):
        """
        'gsm hold <remoteNumber>'
        Change the state of a call to 'held'. This is only possible
        if the call in the 'waiting' or 'active' state
        """
        self.__runCommand('gsm hold %s' % str(theRemoteNumber))

    def changeGPRSState(self, theState):
        """
        'gsm data <state>'
        Change the state of the GPRS connection.
        Allowed values for the state can be found in GsmState class.
        """
        if not GsmState.isValidValue(theState):
            raise ValueError('GPRS state has to be one of the following values: %s' % GsmState.ALLOWED_VALUES)
        self.__runCommand('gsm data %s' % theState)
        
    def changeGSMState(self, theState):
        """
        'gsm voice <state>'
        Change the state of the GSM connection.
        Allowed values for the state can be found in GsmState class.
        """
        if not GsmState.isValidValue(theState):
            raise ValueError('GSM state has to be one of the following values: %s' % GsmState.ALLOWED_VALUES)
        self.__runCommand('gsm voice %s' % theState)


    # ================================================================================
    # SMS
    # ================================================================================
    def sendSms(self, thePhoneNumber, theMessage):
        """
        'sms send <phonenumber> <message>'
        Simulate new inbound SMS message.
        """
        self.__runCommand('sms send %s %s' % (str(thePhoneNumber), theMessage))


    # ================================================================================
    # Geo
    # ================================================================================
    def changeLocationNmea(self, theSentence):
        """
        'geo nmea <sentence>'
        Sends a NMEA 0183 sentence, as if it came from an emulated GPS modem.
        <sentence> must begin with '$GP'. Only '$GPGGA' and '$GPRCM' sentences
        are supported at the moment.
        """
        self.__runCommand('geo nmea %s' % theSentence)

    def changeLocation(self, theLongitude, theLatitude, theAltitude=''):
        """
        'geo fix <longitude> <latitude> [<altitude>]'
        Send a simple GPS fix.
        <longitude>   longitude, in decimal degrees
        <latitude>    latitude, in decimal degrees
        <altitude>    optional altitude in meters
        """
        self.__runCommand('geo fix %s %s %s' % (str(theLongitude), str(theLatitude), str(theAltitude)))

        
    # ================================================================================
    # Power
    # ================================================================================
    def setBatteryPowerState(self, theState):
        """
        'power status <state>'
        Set battery status.
        Allowed values for the state can be found in PowerState class
        """
        if not BatteryPowerState.isValidValue(theState):
            raise ValueError('Battery power state has to be one of the following values: %s' % BatteryPowerState.ALLOWED_VALUES)
        self.__runCommand('power status %s' % theState)

    def setBatteryHealthState(self, theState):
        """
        'power health <state>'
        Set health status.
        Allowed values for the state can be found in BatteryHealthState class
        """
        if not BatteryHealthrState.isValidValue(theState):
            raise ValueError('Battery health state has to be one of the following values: %s' % BatteryHealthState.ALLOWED_VALUES)
        self.__runCommand('power health %s' % theState)

    def setBatteryCapacity(self, theCapacity):
        """
        'power capacity <capacity>'
        Set battery capacity to a value 0-100
        """
        try:
            capacity = int(theCapacity)
        except ValueError:
            raise ValueError('Capacity has to be a numeric value between 0 and 100')
        if capacity < 0 or capacity > 100:
            raise ValueError('Capacity has to be a numeric value between 0 and 100')
        self.__runCommand('power capacity %d' % capacity)


    # ================================================================================
    # Helpers
    # ================================================================================
    def __runCommand(self, theCmd):
        self.tn.open(self.host, self.port)
        self.log.debug('Command to sent: %s\n' % theCmd)
        self.tn.write('%s\n' % theCmd)
        self.tn.write('exit\n')
        aTnOutStr = self.tn.read_all()
        self.tn.close()
        self.log.debug('Command out:\n%s' % aTnOutStr)
        aTnOutLineVec = aTnOutStr.rsplit('\n', 2)
        if aTnOutLineVec[2] == '':
            if aTnOutLineVec[1].startswith('OK'):
                pass
            else:
                raise EmulatorTelnetClientError('Failed to run command %s' % theCmd)
        elif aTnOutLineVec[2].startswith('OK'):
            pass
        else:
            raise EmulatorTelnetClientError('Failed to run command %s' % theCmd)        
