################################################################################
#
# Copyright (c) 2011-2012, Daniel Baeumges (dbaeumges@googlemail.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

from sqlite3 import dbapi2 as sqlite
from common import Logger, LogLevel, Utils

import datetime


# ================================================================================
# MobileSandbox DB Interface Error
# ================================================================================
class MsDbInterfaceError(Exception):
    GENERAL_ERROR = 0
    FATAL_ERROR = 1

    def __init__(self, theValue, theCode=GENERAL_ERROR):
        self.value = theValue
        self.code = theCode

    def __str__(self):
        return ('%d: ' % self.code) + repr(self.value)

    def getCode(self):
        return self.code


# ================================================================================
# Mobile Sandbox DB Interface
# ================================================================================
class MsDbInterface:
    
    def __init__(self, theDb, theLogger=Logger()):
        self.db = theDb
        self.log = theLogger

        self.conn = None

    def __del__(self):
        try:
            self.close()
        except Exception, ex:
            pass            

    def connect(self):
        """
        Connect to database.
        """
        if not self.conn is None:
            raise MsDbInterfaceError('Already connected to %s' % self.db)
        self.conn = sqlite.connect(self.db)

    def close(self):
        """
        Close connection
        """
        if not self.conn is None:
            self.conn.close()
        self.conn = None

    def storeSample(self, theApkName, thePackageName, theMd5Value=None, theSha256Value=None, theFilesystemPosition=None, theMalwareFamily=None, theOs=None):
        """
        Stores sample information in Sample table and returns the sample id.
        If the sample is already existing the appropriate sample id is returned.
        
        CREATE TABLE Sample (
          id INTEGER PRIMARY KEY,
          apk_name VARCHAR(255),
          package_name VARCHAR(255),
          md5 VARCHAR(255),
          sha256 VARCHAR(255),
          filesystem_position VARCHAR(255),
          maleware_family VARCHAR(255),
          os VARCHAR(255)
        );
        """
        columns = 'apk_name, package_name'
        values = '"%s", "%s"' % (theApkName, thePackageName)
        where = 'apk_name = "%s" and package_name = "%s"' % (theApkName, thePackageName)
        columns, values, where = self.__addItem('md5', theMd5Value, columns, values, where)
        columns, values = self.__addItem('sha256', theSha256Value, columns, values)
        columns, values = self.__addItem('filesystem_position', theFilesystemPosition, columns, values)
        columns, values = self.__addItem('maleware_family', theMalwareFamily, columns, values)
        columns, values = self.__addItem('os', theOs, columns, values)
        return self.__insert('Sample', columns, values, where)
          

    def storeReport(self, theSampleId, theFilesystemPosition, theTypeOfReport=None, theAnalyzerId=None, theOs=None, thePassword=None, theStatus=None, theStartTime=None, theEndTime=None):
        """
        Stored report information in Reports table and returns the report id.
        If the report information is already existing the appropriate report id is returned.
        
        CREATE TABLE Reports (
          id INTEGER PRIMARY KEY,
          sample_id INTEGER,
          filesystem_position VARCHAR(255),
          type_of_report VARCHAR(255),
          analyzer_id INTEGER,
          os VARCHAR(255),
          password VARCHAR(255),
          status VARCHAR(255),
          start_of_analysis TIME,
          end_of_analysis TIME)
        """
        columns = 'sample_id, filesystem_position'
        values = '%d, "%s"' % (theSampleId, theFilesystemPosition)
        where = 'sample_id = %d and filesystem_position = "%s"' % (theSampleId, theFilesystemPosition)
        columns, values = self.__addItem('type_of_report', theTypeOfReport, columns, values)
        columns, values = self.__addItem('analyzer_id', theAnalyzerId, columns, values, theType='int')
        columns, values = self.__addItem('os', theOs, columns, values)
        columns, values = self.__addItem('password', thePassword, columns, values)
        columns, values = self.__addItem('status', theStatus, columns, values)
        columns, values = self.__addItem('start_of_analysis', theStartTime, columns, values)
        columns, values = self.__addItem('end_of_analysis', theEndTime, columns, values)
        return self.__insert('Reports', columns, values, where)

    def storeReportData(self, theReportId, theUsedPermissions=None, theUsedIntents=None, theUsedServices=None, theUsedActivities=None, theUsedApis=None):
        """
        Stores report data in Report_Data table and returns the report data id.
        If the report data information is already existing the appropriate report data id is returned.
        
        CREATE TABLE Report_Data (
          id INTEGER PRIMARY KEY,
          report_id INTEGER,
          used_permissions TEXT,
          used_intents TEXT,
          used_services_and_receivers TEXT,
          used_activities TEXT,
          used_apis TEXT)
        """
        columns = 'report_id'
        values = '%d' % (theReportId)
        where = 'report_id = %d' % (theReportId)
        columns, values = self.__addItem('used_permissions', theUsedPermissions, columns, values)
        columns, values = self.__addItem('used_intents', theUsedIntents, columns, values)
        columns, values = self.__addItem('used_services_and_receivers', theUsedServices, columns, values)
        columns, values = self.__addItem('used_activities', theUsedActivities, columns, values)
        columns, values = self.__addItem('used_apis', theUsedApis, columns, values)
        return self.__insert('Report_Data', columns, values, where)

    def addAnalyzer(self, theName, theType=None, theOs=None, theToolsIntegrated=None, theMachineId=None):
        """
        Adds analyzer information in Analyzer table and returns the analyzer id.
        If the analyzer is already existing the appropriate analyzer id is returned.
        
        CREATE TABLE Analyzer (
          id INTEGER PRIMARY KEY,
          name VARCHAR(255),
          type VARCHAR(255),
          os VARCHAR(255),
          tools_integrated VARCHAR(255),
          machine_id INTEGER)
        """
        columns = 'name'
        values = '"%s"' % (theName)
        where = 'name = "%s"' % (theName)
        columns, values = self.__addItem('type', theType, columns, values)
        columns, values = self.__addItem('os', theOs, columns, values)
        columns, values = self.__addItem('tools_integrated', theToolsIntegrated, columns, values)
        columns, values = self.__addItem('machine_id', theMachineId, columns, values, theType='int')
        return self.__insert('Analyzer', columns, values, where)

    def commit(self):
        """
        Commit
        """
        self.conn.commit()
    
    
    def _cleanUp(self):
        """
        CleanUp tables
        """
        for table in ['Sample', 'Reports', 'Report_Data', 'Analyzer']:
            sql = """TRUNCATE TABLE %s""" % table
            self.__execSql(sql)

    def __addItem(self, theColumn, theValue, theColumnList, theValueList, theWhereClause=None, theType='string'):
        columnList = theColumnList
        valueList = theValueList
        whereClause = theWhereClause
        if not theValue is None:
            if columnList != '':
                columnList += ', '
                valueList += ', '
            columnList += theColumn
            if theType == 'string':
                valueList += '"%s"' % theValue
            elif theType == 'int':
                valueList += '%d' % theValue
            
            if not whereClause is None:
                if columnList != '':
                    whereClause += ' and '
                if theType == 'string':
                    whereClause += '%s = "%s"' % (theColumn, theValue)
                elif theType == 'int':
                    whereClause += '%s = %d' % (theColumn, theValue)
        if not whereClause is None:
            return (columnList, valueList, whereClause)
        else:
            return (columnList, valueList)

    def __insert(self, theTable, theColumns, theValues, theWhere):
        insertSql = 'INSERT INTO %s(%s) VALUES(%s)' % (theTable, theColumns, theValues)
        selectSql = 'SELECT id FROM %s WHERE %s' % (theTable, theWhere)

        # Check if entry is existing
        result = self.__execSelect(selectSql)
        if len(result) == 1:
            return result[0][0]
        elif len(result) > 1:
            raise
        
        # Insert
        self.__execSql(insertSql)

        # Get primary key
        result = self.__execSelect(selectSql)
        if len(result) == 0:
            raise
        if len(result) > 1:
            raise
        return result[0][0]    
        
    def __execSelect(self, theSql):
        """
        Executes a select statement and returns the result.
        """
        return self.__execSql(theSql, theFetchFlag=True)
        
    def __execSql(self, theSql, theFetchFlag=False):
        """
        Execute SQL statement
        """
        result = []
        cursor = self.conn.cursor()
        self.log.debug('Exec SQL: \'%s\'' % theSql)
        cursor.execute(theSql)
        if theFetchFlag:
            result = cursor.fetchall()
            self.log.debug('Result: %s' % result)
            return result

# ================================================================================
# Main method
# ================================================================================
def main():
    # Parse options
    #parser = OptionParser(usage='usage: %prog [options] apk', version='%prog 0.1')    
    #parser.add_option('', '--sdkPath', metavar='<path>', help='Set path to Android SDK')
    #parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=True)
    #parser.add_option('-q', '--quiet', action='store_false', dest='verbose')
    #(options, args) = parser.parse_args()

    # Run
    time = datetime.datetime.now()
    logger = Logger(LogLevel.DEBUG)
    db = MsDbInterface(logger)    
    #db._cleanUp()
    
    sampleId = db.storeSample('apk1', 'apk1', 'md5', 'sha256', 'ospos', 'bad', 'x64')
    reportId = db.storeReport(sampleId, 'fspos', 'tdrun', 1, 'x64', 'pw', 'ok', time, time)
    reportDataId = db.storeReportData(reportId, 'viele', 'viele', 'viele', 'viele', 'viele')
    analyzerId = db.addAnalyzer('tdrunner', 'dynamic', 'x64', 'no', 21)
    db.commit()
    
if __name__ == '__main__':
    main()
    
