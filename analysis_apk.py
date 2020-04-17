import sys
import os
import pickle
import json
import numpy as np

class Analysis:

    def __init__(self, apk, dex, sensitiveAPICalls, sensitiveStrings):
        self.apk = apk
        self.dex = dex
        self.featureList = []
        self.sensitiveAPICalls = sensitiveAPICalls
        self.sensitiveStrings = sensitiveStrings


    #get the number of permissions
    def getPermissionsAmount(self):
        permissionsAmount = self.apk.get_permissions()
        self.featureList.append(len(permissionsAmount))

    #get the number of dangerous permissions
    def getDangerousPermissionsAmount(self):
        counter = 0
        detailedPermissions = self.apk.get_details_permissions()
        for k, v in detailedPermissions.items():
            if v[0] == 'dangerous':
                counter += counter
        self.featureList.append(counter)


    #get the number of APIs that have been called
    def findMethodInformation(self, dex, className, methodName):
        amountOfCalls = 0
        for meth in dex.find_methods(classname = "L" + className + ";", methodname = methodName):
            callOrigin = meth.get_xref_from()
            amountOfCalls = len(callOrigin)
        return amountOfCalls


    def findStringInformation(self, dex, stringName):
        amountOfCalls = 0
        for str in dex.find_strings(string = stringName):
            callOrigin = str.get_xref_from()
            amountOfCalls = len(callOrigin)
        return amountOfCalls


    #use the classes and methods in the json file  (sensitive API calls)
    def getAPICallsAmount(self):
        totalAmountOfApiCalls = 0
        totalAmountOfDifferentApiCalls = 0
        for className, methodArray in self.sensitiveAPICalls.items():
            for methodName in methodArray:
                calls = self.findMethodInformation(self.dex, className, methodName)
                if calls > 1:
                    totalAmountOfApiCalls = totalAmountOfApiCalls + calls
                    totalAmountOfDifferentApiCalls += 1
        self.featureList.append(totalAmountOfApiCalls)
        self.featureList.append(totalAmountOfDifferentApiCalls)


    def getSensitiveStringsAmount(self):
        totalAmountofSensitiveStringsCalls = 0
        totalAmountOfUniqueSensitiveStrings = 0
        for stringType, stringsArray in self.sensitiveStrings.items():
            for stri in stringsArray:
                calls = self.findStringInformation(self.dex, stri)
                if calls > 0:
                    totalAmountofSensitiveStringsCalls = totalAmountofSensitiveStringsCalls + calls
                    totalAmountOfUniqueSensitiveStrings += 1
        self.featureList.append(totalAmountofSensitiveStringsCalls)
        self.featureList.append(totalAmountOfUniqueSensitiveStrings)




    def testAPK(self):
        shapedArray = np.array(self.featureList)
        finalShape = shapedArray.reshape(1, -1)
        filename = 'svm_trained_model.sav'
        loaded_model = pickle.load(open(filename, 'rb'))
        result = loaded_model.predict(finalShape)
        if int(result) == 1:
            return 'malware'
        else:
            return 'benign'


    def inspectAPK(self):
        self.getPermissionsAmount()
        self.getDangerousPermissionsAmount()
        self.getAPICallsAmount()
        self.getSensitiveStringsAmount()
        result = self.testAPK()
        return result
