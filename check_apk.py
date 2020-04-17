import sys
import os
import json
from androguard.misc import AnalyzeAPK
from analysis_apk import Analysis

if len(sys.argv) != 2:
    print('Usage: check_apk.py <apk_path>')
    sys.exit()

apk_file = sys.argv[1]
cwd = os.getcwd()


#get data from the json file
with open(os.getcwd() + '/sensitiveAPICalls.json') as f:
    sensitiveAPICalls = json.load(f)

#get data from the string file
with open(os.getcwd() + '/sensitiveStrings.json') as f:
    sensitiveStrings = json.load(f)


def examine(apk):
    apk, dvm, dex = AnalyzeAPK(apk)
    analysis = Analysis(apk, dex, sensitiveAPICalls, sensitiveStrings)
    result = analysis.inspectAPK()
    return result

try:
    print("Processing  ->  " + apk_file)
    result = examine(apk_file)
    print("The application is "+ result)
finally:
    print("Done Successfully !!")
