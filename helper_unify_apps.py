from apk_wrapper import APKWrapper, APKWrapperError
from common import Utils
from optparse import OptionParser

import os
import shutil

# ================================================================================
# Main method
# ================================================================================

def copyApp(theApp, theTargetAppDir, theRunningNumber):
    if theTargetAppDir is None:
        return
    
    targetPath = os.path.join(theTargetAppDir, '%03d_%s.apk'% (theRunningNumber, theApp.getMd5Hash()))
    shutil.copy2(theApp.getApk(), targetPath)


def main():
    # Get directory
    parser = OptionParser(usage='usage: %prog [options] sourceDir targetDir')
    parser.add_option('', '--sdkPath', metavar='<path>', default='', help='Set path to Android SDK')
    (options, args) = parser.parse_args()

    targetAppDir = None
    if len(args) < 1:
        raise ValueError('Provide a directory')
    if len(args) == 2:
        targetAppDir = args[1]
        if not os.path.exists(targetAppDir):
            os.mkdir(targetAppDir)
       
    sourceAppDir = args[0]
    

    # Get app names    
    appNameList = Utils._getAppListInDirectory(sourceAppDir)
    print 'Get APK Wrapper of %d apps' % len(appNameList)
    initialAppList = []
    errorAppList = []
    for appName in appNameList:
        try:
            initialAppList.append(APKWrapper(appName, theSdkPath=options.sdkPath))
        except APKWrapperError, apkwErr:
            errorAppList.append((appName, apkwErr))

    print 'Check for duplicates of %d apps' % len(initialAppList)
    runningNumber = 0
    appMap = {}
    for app in initialAppList:
        hashValue = app.getMd5Hash()
        if appMap.has_key(hashValue):
            appMap[hashValue].append(app)
        else:
            appMap[hashValue] = [app]
            runningNumber += 1
            copyApp(app, targetAppDir, runningNumber)            
        
    # Print result
    print '\n\nErrornous apps:\n'
    for app in errorAppList:
        print '- %s: %s\n' % (app[0], str(app[1]))

    print 'Number of apps: %d' % len(initialAppList)
    print 'Number of distinct apps: %d' % len(appMap)

    print 'Duplicate apps:'
    for hashValue, appList in appMap.iteritems():
        if len(appList) > 1:
            appListStr = ''
            for tempApp in appList:
                appListStr += tempApp.getApk() + ', '
            appListStr = appListStr[:-2]
            print '- %s\n' % appListStr

if __name__ == '__main__':
    main()
