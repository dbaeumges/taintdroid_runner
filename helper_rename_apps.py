from apk_wrapper import APKWrapper, APKWrapperError
from common import Utils
from optparse import OptionParser

import helper_analyzer

import os
import shutil

def renameApp(theApp, theSdkPath):
    apk = APKWrapper(theApp, theSdkPath)
    
    newName = '%s/%s-%s.apk' % (apk.getApkPath(), apk.getPackage(), apk.getMd5Hash())
    print '- Rename from %s to %s' % (theApp, newName)
    shutil.move(theApp, newName)

def main():
    # Get directory
    parser = OptionParser(usage='usage: %prog [options] dir targetDir')
    parser.add_option('-m', '--mode', metavar='#', default=0)
    parser.add_option('', '--sdkPath', metavar='<path>', default='', help='Set path to Android SDK')
    (options, args) = parser.parse_args()

    if len(args) < 1:
        raise ValueError('Provide a directory')
    aDir = args[0]
    targetDir = None
    if len(args) > 1:
        targetDir = args[1]

    # Get app names
    if int(options.mode) == 0:
        appNameList = Utils._getAppListInDirectory(aDir)
        print 'Get APK Wrapper of %d apps' % len(appNameList)
        for appName in appNameList:
            renameApp(appName, options.sdkPath)

    # Goodware
    if int(options.mode) == 1:
        if targetDir is None:
            raise ValueError('Provide a target directory')
        analyzer = helper_analyzer.Analyzer([aDir], theSdkPath=options.sdkPath)
        analyzer.baseAppDir = '/home/daniel/Documents/MarketApps/apps'
        appList = analyzer.generateList()
        for app in appList:
            oldName = os.path.join('/home/daniel/Documents/MarketApps/apps', app[1].getApkFileName())
            newName = os.path.join(targetDir, app[0])
            print '- Copy app form %s to %s' % (oldName, newName)
            shutil.copy2(oldName, newName)
            
if __name__ == '__main__':
    main()
