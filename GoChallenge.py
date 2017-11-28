#!/usr/bin/python
#-*- coding:utf-8 -*-
import os
import re
import sys
import zipfile
import hashlib
import magic
import subprocess
from apk_parse.apk import APK


exceptFile = ['classes.dex', 'AndroidManifest.xml', 'resources.arsc']

def main():
    path = sys.argv[1]
    malicious = sys.argv[2]
    result = {}
    if not os.path.exists(path):
        return False, "File is not exists"
    apk = APK(path)
    if not apk.is_valid_APK():
        return False, "APK file is wrong"
    result = {} 
    ### APK File Info
    result['Apk'] = {}
    result['Apk']['path'] = path
    result['Apk']['malicious'] = malicious
    result['Apk']['md5'] = apk.file_md5
    result['Apk']['sha256'] = apk.file_sha256
    result['Apk']['size'] = apk.file_size
    result['Apk']['magic'] = magic.Magic().from_file(path)
    result['Apk']['icon_files'] = apk.get_icon_files()
    
    ### Certificate Information
    result['Certificate'] = {}
    result['Certificate']['md5'] = apk.cert_md5
    result['Certificate']['text'] = apk.cert_text
    
    ### AndroidManifiest.xml Information
    result['AndroidManifest'] = {}
    result['AndroidManifest']['androidversion_code'] = apk.get_androidversion_code()
    result['AndroidManifest']['androidversion_name'] = apk.get_androidversion_name()
    result['AndroidManifest']['min_sdk_version'] = apk.get_min_sdk_version()
    result['AndroidManifest']['target_sdk_version'] = apk.get_target_sdk_version()
    result['AndroidManifest']['libraries'] = apk.get_libraries()
    result['AndroidManifest']['main_activitiy'] = apk.get_main_activity()
    result['AndroidManifest']['activities'] = {}
    for activity in apk.get_activities():
        result['AndroidManifest']['activities'][activity] = apk.get_intent_filters('activity', activity)
    result['AndroidManifest']['services'] = {}
    for service in apk.get_services():
        result['AndroidManifest']['services'][service] = apk.get_intent_filters('service', service)
    result['AndroidManifest']['receivers'] = {}
    for receiver in apk.get_receivers():
        result['AndroidManifest']['receivers'][receiver] = apk.get_intent_filters('receiver', receiver)
    result['AndroidManifest']['permissions'] = {}
    for permission in apk.get_permissions():
        result['AndroidManifest']['permissions'][permission] = apk.get_intent_filters('permission', permission)
    result['AndroidManifest']['providers'] = apk.get_providers()
    
    ### APK File Information and File Magic Data
    result['Files'] = {}
    image_extension_list = ['png', 'jpeg', 'jpg', 'gif']
    image_magic_list = ['PNG image data', 'JPEG image data']
    for file in apk.get_files():
        result['Files'][file] = {}
        fileData = apk.get_file(filename = file)
        result['Files'][file]['icon'] = False
        result['Files'][file]['size'] = len(fileData)
        result['Files'][file]['md5'] = hashlib.md5(fileData).hexdigest()
        result['Files'][file]['sha256'] = hashlib.sha256(fileData).hexdigest()
        result['Files'][file]['magic'] = magic.Magic().from_buffer(fileData)
        result['Files'][file]['file_name'] = None
        result['Files'][file]['file_extension'] = None
        result['Files'][file]['image_resource'] = False
        if '/' in file:
            result['Files'][file]['file_name'] = file.split('/')[-1]
        else:
            result['Files'][file]['file_name'] = file

        if '.' in result['Files'][file]['file_name']:
            result['Files'][file]['file_extension'] = result['Files'][file]['file_name'].split('.')[-1].lower()
        if file in apk.get_icon_files():
            result['Files'][file]['icon'] = True
        if result['Files'][file]['file_extension'] in image_extension_list:
            result['Files'][file]['image_resource'] = get_image_resource(file_magic = result['Files'][file]['magic'], image_magic_list = image_magic_list)
        if get_image_resource(file_magic = result['Files'][file]['magic'], image_magic_list = image_magic_list) and result['Files'][file]['file_extension'] not in image_extension_list:
            continue
            #print "[+] This file is strange %s %s" % (file, result['Files'][file]['magic'])
            fd = open('./temp/' + file.replace('/', '_'), 'wb')
            fd.write(apk.get_file(file))
            fd.close()
    
    ### decompile
    proc = subprocess.Popen(['java', '-jar', 'apktool_2.3.0.jar', 'd', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if '/' in path:
        path = path.split('/')[-1]
    result['Class'] = {}
    for root, dirs, files in os.walk('./' + path + '.out' + os.sep + 'smali'):
        for file in files:
            filepath = root + os.sep + file
            className = filepath.split('/smali/')[-1].split('.smali')[0].replace('/','.')
            result['Class'][className] = {}
            result['Class'][className]['Method'] = {}
            result['Class'][className]['interfaces'] = []
            result['Class'][className]['Fields'] = []
            fd = open(filepath, 'rb')
            data = fd.read()
            fd.close()
            index = 0
            for line in data.split('\n'):
                if not line:
                    continue
                line = line.strip()
                if line.startswith('.super '):
                    result['Class'][className]['super_class'] = line[8:-1].replace('/','.')
                    #print result['Class'][className]['super_class']
                elif line.startswith('.method '):
                    ### Method Info
                    try:
                        methodName, parameters, returnType = re.search('\.method\s.+\s(.+)\((.*)\)(.+)', line).groups()
                    except AttributeError:
                        methodName, parameters, returnType = re.search('\.method\s(.+)\((.*)\)(.+)', line).groups()
                    result['Class'][className]['Method'][methodName] = {}
                    result['Class'][className]['Method'][methodName]['parameters'] = []
                    result['Class'][className]['Method'][methodName]['strings'] = []
                    result['Class'][className]['Method'][methodName]['call-api'] = []
                    result['Class'][className]['Method'][methodName]['returnType'] = None
                    result['Class'][className]['Method'][methodName]['flags'] = None
                    #if returnType not in ['Z','B','C','D','F','I','J','V']:
                    #    print line, returnType
                    #    raw_input()
                    ### Method Parameter
                    for parameter in parameters.split(';'):
                        result['Class'][className]['Method'][methodName]['parameters'].append(parameter[1:].replace('/','.'))
                    if returnType == 'Z':
                        returnType = 'boolean'
                    elif returnType == 'B':
                        returnType = 'byte'
                    elif returnType == 'C':
                        returnType = 'char'
                    elif returnType == 'D':
                        returnType = 'double'
                    elif returnType == 'F':
                        returnType = 'float'
                    elif returnType == 'I':
                        returnType = 'int'
                    elif returnType == 'J':
                        returnType == 'long'
                    elif returnType == 'V':
                        returnType = 'void'
                    elif returnType.startswith('L') and returnType.endswith(';'):
                        returnType = returnType[1:-1].replace('/', '.')
                    result['Class'][className]['Method'][methodName]['returnType'] = returnType
                    #if '[' in returnType:
                elif line.startswith('const-string'):
                    result['Class'][className]['Method'][methodName]['strings'].append(re.search('\"(.*)\"', line).groups()[0])
                ### target = {'class', 'method', 'parameters' = []}
                elif line.startswith('invoke-virtual') or line.startswith('invoke-static') or line.startswith('invoke-interfaces'):
                    targetClass, targetMethod, targetMethodParameters, targetMethodReturnType = re.search('invoke\-.+\s\{.*\}\,\sL(.+)\-\>(.+)\((.*)\)(.*)', line).groups()
                    target = {}
                    target['class'] = targetClass
                    target['mehtod'] = targetMethod
                    target['parameters'] = []
                    if targetMethodParameters.count(';') > 1:
                        for parameter in targetMethodParameters.split(';'):
                            target['parameters'].append(parameter[1:].replace('/','.'))
                    else:
                        target['parameters'].append(targetMethodParameters.replace('/','.'))
                    result['Class'][className]['Method'][methodName]['call-api'].append(target)
                index += 1
        shutil.rmtree('./' + path + '.out')
    return True, ""


def get_image_resource(file_magic, image_magic_list):
    for image_magic in image_magic_list:
        if file_magic.startswith(image_magic):
            return True
    return False

if __name__ == '__main__':
    main()

