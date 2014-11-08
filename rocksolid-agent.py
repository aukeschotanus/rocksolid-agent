#!/usr/bin/env python

# Agent parameters
__version__     = '1.0.8'
__author__      = 'bjbuijs'
__author__      = 'aukeschotanus'

# Copyright rocksolid.io 2013,2014 (c) All rights reserved.
# created by Bart Jan Buijs & Auke Schotanus

# Todo Tested with Python 2.x ... not with 3.x yet
# Todo Need to replace dict.iteritems() with .items() ??

# Consider https://github.com/benhoyt/scandir

def module_exists(module_name):
    try:
        __import__(module_name)
    except ImportError:
        # print '[rocksolid-agent] Python module %s missing. Please install ... trying to continue without this module.' % module_name
        # modules_missing.append(module_name)
        return False
    else:
        return True


if module_exists('datetime')    : from datetime import datetime
if module_exists('os')          : import os
if module_exists('fnmatch')     : import fnmatch
if module_exists('platform')    : import platform
if module_exists('urllib')      : import urllib
if module_exists('urllib2')     : import urllib2
if module_exists('re')          : import re
if module_exists('sys')         : import sys
if module_exists('socket')      : import socket
if module_exists('subprocess')  : import subprocess
if module_exists('math')        : import math


# Add any() function for lower Python version (< 2.4)
try:
    any
except NameError:
    def any(s):
        for v in s:
            if v:
                return True
            return False


# Check we're not using an old version of Python. Do this before anything else
# We need 2.4 above because some modules (like subprocess) were only introduced in 2.4.
if sys.version_info < (2,4):
    print '[rocksolid-agent] You are using an outdated version of Python. Please update to v2.4 or above (v3 is not supported). For newer OSs, you can update Python without affecting your system install. See http://blog.boxedice.com/2010/01/19/updating-python-on-rhelcentos/ If you are running RHEl 4 / CentOS 4 then you will need to compile Python manually.'
    sys.exit(1)

def set_proc_name(newname):
    if module_exists('c_type') :
        from ctypes import cdll, byref, create_string_buffer

        libc = cdll.LoadLibrary('libc.so.6')
        buff = create_string_buffer(len(newname) + 1)
        buff.value = newname
        libc.prctl(15, byref(buff), 0, 0, 0)
    else :
        print "[rocksolid-agent] Unable to set proc name. Module ctype missing. please install the module for optimal functionality."


def get_proc_name():
    if module_exists('c_type') :
        from ctypes import cdll, byref, create_string_buffer

        libc = cdll.LoadLibrary('libc.so.6')
        buff = create_string_buffer(128)
        # 16 == PR_GET_NAME from <linux/prctl.h>
        libc.prctl(16, byref(buff), 0, 0, 0)
        return buff.value
    else :
        print "[rocksolid-agent] Unable to set proc name. Module ctype missing, please install the module for optimal functionality."
        return 0


# returns the elapsed milliseconds since the start of the program
def detect_runtime():
    dt = datetime.now() - analytics['starttime']
    sec = ((dt.days * 24 * 60 * 60 + dt.seconds) * 1000 + dt.microseconds / 1000.0) / 1000.0
    return sec


def detect_os():
    return platform.system()


def detect_release():
    return platform.release()


def get_interface_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('www.rocksolid.io', 80))
    ip = sock.getsockname()[0]
    sock.close()
    return ip


# Determine external ip address. Should be replaced by our own url that returns ip's.
def get_external_ip():
    site = urllib.urlopen("http://gw.rocksolid.io/ip/").read()
    grab = re.findall('\d{2,3}.\d{2,3}.\d{2,3}.\d{2,3}', site)
    try:
        address = grab[0]
    except Exception, e:
        address = '0.0.0.0'

    return address


def get_user(targetfile):
    user = targetfile.split('/')
    return user[2]


def get_domain(cp, targetfile):
    domain = ''
    try:
        tmpvar = targetfile.split('/')
        user = tmpvar[2]

        if   (cp == 'cpanel'):
            # Lookup in user config file
            lines = open('/var/cpanel/users/%s' % user[2], 'r').read(512000)
            result = re.search('DNS=(.*?)', lines)
            if result:
                domain = result.group(1)
        elif (cp == 'directadmin'):
            # Lookup in domainowners file
            lines = open('/etc/virtual/domainowners', 'r').read(512000)
            result = re.search('(.*?) :%s' % user, lines)
            if result:
                domain = result.group(1)
            else:
                # Fall back on pathname
                domain = tmpvar[4]
        elif (cp == 'ensim'):
            if module_exists('os'):
                domain = os.popen('/usr/bin/sitelookup -s %s 2>&1' % user[2]).read()
                domain = domain.split(',')
                domain = domain[0]
        elif (cp == 'plesk'):
            # Domain is part of the directory
            domain = user[4]
        elif (cp == 'syncer'):
            # Lookup in Apache vhost file
            lines = open('/usr/local/syncer/vhost.conf', 'r').read(512000)
            result = re.search('ServerName (.*?)\n.*?/var/www/%s' % user, lines)
            if result:
                domain = result.group(1)
    except Exception, e:
        # Failed to lookup domain
        pass

    return domain


def get_email(cp, user):
    email = ''
    try:
        if   (cp == 'cpanel'):
            # Lookup in user config file
            lines = open('/var/cpanel/users/%s' % user[2], 'r').read(512000)
            result = re.search('CONTACTEMAIL=(.*?)', lines)
            if result:
                email = result.group(1)
        elif (cp == 'directadmin'):
            # Lookup in domainowners file
            conf = '/usr/local/directadmin/data/users/' + user + '/user.conf'
            lines = open(conf, 'r').read(512000)
            result = re.search('email=(.*?)\n', lines)
            if result:
                email = result.group(1)
    except Exception, e:
        # Failed to lookup domain
        pass

    return email


def detect_controlpanel():
    try:
        if   ( os.path.exists('/var/cpanel/users')):
            return 'cpanel'   # cpanel/WHM
        elif ( os.path.exists('/etc/virtual/domainowners')):
            return 'directadmin'
        elif ( os.path.exists('/home/virtual/FILESYSTEMTEMPLATE')):
            return 'ensim'
        elif ( os.path.exists('/etc/rc.d/init.d/epld')):
            return 'plesk'
        elif ( os.path.exists('/usr/local/syncer')):
            return 'syncer'
        else:
            return 'Unsupported'
    except OSError:
        # OS error
        pass


def detect_controlpanel_version(cp):
    version = 'Unknown'

    try:
        if   (cp == 'cpanel'):
            version = open('/usr/local/cpanel/version', 'r').read(512000)
        elif (cp == 'directadmin'):
            if module_exists('os'):
                version = os.popen('/usr/local/directadmin/directadmin v').read()
                version = version.split(' ')
                version = version[2].rsplit()
        elif (cp == 'ensim'):
            version = open('/usr/lib/opcenter/VERSION', 'r').read(512000)
        elif (cp == 'plesk'):
            version = open('/usr/local/psa/version', 'r').read(512000)
        elif (cp == 'syncer'):
            version = open('/usr/local/syncer/version', 'r').read(512000)
    except Exception, e:
        # Failed to lookup cp
        pass

    return version


def detect_php():
    phpv = ''

    try:
        # Use the newer subprocess.Popen as it is considered to be safer then os.popen
        cmd = subprocess.Popen(["php", "-v"], stdout=subprocess.PIPE)
        phpv, _ = cmd.communicate()
        phpv = phpv.split("\n")
        phpv = phpv[0]
    except Exception, e:
        # Failed to lookup cp
        pass

    return phpv


def cal_longeststring(sample):
    # Determine the longest string in the sample to determine obfuscated code
    longeststring = 0

    words = re.split("[s,n,r]", sample)
    if words:
        for word in words:
            if len(word) > longeststring:
                longeststring = len(word)

    return longeststring


def cal_entropy(sample):
    # (Claude E.) Shannon entropy check. Determine uncertainty of the sample to detect encrypted code
    entropy = 0
    #try:
    for x in range(256):
        if len(sample) > 0:
            p_x = float(sample.count(chr(x)))/len(sample)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
    #except Exception, e:
    #    pass

    return entropy


def get_agent_parameters():
    agent = {}

    agent['version']       = __version__
    agent['hostname']      = platform.node()
    agent['interfaceip']   = get_interface_ip()
    agent['externalip']    = get_external_ip()
    agent['nameos']        = detect_os()
    agent['namecp']        = detect_controlpanel()
    agent['versionos']     = detect_release()
    agent['versioncp']     = detect_controlpanel_version(agent['namecp'])
    agent['versionpython'] = ''.join([str(sys.version_info[2]), '.', str(sys.version_info[1])])
    agent['versionphp']    = detect_php()

    return agent


def cal_md5_file(targetfile):
    # Hashlib introduced in 2.5, md5 module deprecated
    # Try Hashlib, fall back on md5 module if hashlib is missing
    if module_exists('hashlib'):
        import hashlib
        checksum = hashlib.md5(open(targetfile, 'rb').read(512000)).hexdigest()
    elif module_exists('md5'):
        import md5
        m = md5.new()
        m.update(open(targetfile, 'rb').read(512000))
        checksum = m.hexdigest()
    else:
        return 0

    return checksum



def load_definitions():
    # Load definitions into the agent
    #targetfiles = {}
    definitions = {}
    nr = 0

    f = open('rocksolid-agent.def')
    lines = f.readlines()
    f.close()

    for line in lines:
        # strip EOL
        line = line.rstrip()

        # put columns in array
        definition = line.split(":::", 3)

        # Use dictionary to store results (NEW)
        definitions[nr] = {'type':definition[0], 'name':definition[1], 'file':definition[2].decode("base64"), 'regex':definition[3]}
        nr = nr + 1

        # print '[rocksolid-agent] Loaded %s definition for %s (    %s    %s    )' % (definition[0], definition[1], definition[2].decode("base64"), definition[3])

    print '[rocksolid-agent] Loaded definitions into memory';

    return definitions


def scan_packages ( catalog ):
    if catalog['apps']['pac']  == False:
        # Modules check disabled, return to main
        packages = []
        return packages

    print "[rocksolid-agent] Scanning packages"

    #out, err = subprocess.Popen(['/bin/rpm','-qa'], stdout=subprocess.PIPE).communicate()
    #packages = out.splitlines()

    cmd = subprocess.Popen(["/bin/rpm", "-qa"], stdout=subprocess.PIPE)
    packagesraw, _ = cmd.communicate()
    packagesraw = packagesraw.rstrip()
    packages = packagesraw.split("\n")

    return packages


def scan_ports (  ):
    if catalog['apps']['prt']  == False:
        # Modules check disabled, return to main
        results = []
        return results

    print "[rocksolid-agent] Probing ports"
    #ports = os.popen('/bin/netstat -ntulp | grep :::').read()
    #ports = ports.split()

    if module_exists('subprocess'):
        out, err = subprocess.Popen(['/bin/netstat','-ntlp'], stdout=subprocess.PIPE).communicate()
        lines = out.splitlines()

        i = 0
        while i < len(lines):
            try:
                ports = lines[i].split()
                print "[rocksolid-agent] Found open port %s (%s %s %s)" % (ports[3], ports[0], ports[5], ports[6])
            except Exception, e:
                pass
            i += 1
    results = []

    return results


def scan_modules ( catalog, definitions, results ):
    if catalog['apps']['mod']  == False:
        # Modules check disabled, return to main
        return results

    # Find additional modules to CMS systems
    i = 0

    print "[rocksolid-agent] Scanning modules"

    for hit,file in results.iteritems():
        j = 0
        while j < len(definitions):
            # MOD: Linked to SRC name, SRC can have multiple MOD defs... therefore while loop
            if definitions[j]['type'] == 'MOD' and definitions[j]['name'] == file['name']:
                # Determine basedir of this module definition\
                old,new,ext = definitions[j]['file'].split('|')
                basedir  = file['path'].replace(old, new)

                # List the modules folder
                if len(basedir) > 0 and os.path.isdir(basedir):
                    print '[rocksolid-agent] Checking for %s plugins in %s' % (file['name'], basedir)
                    # Create multi-dimensional dict
                    file['modules'] = {}

                    for basename in os.listdir(basedir):
                        if os.path.isdir(os.path.join(basedir, basename)):
                            # Do the magic
                            filename = basedir + basename + '/' + basename + ext
                            if os.path.exists(filename):
                                content = open(filename, 'rb').read(512000)  # Read maximum of 500KB into memory
                                result = re.search(definitions[j]['regex'], content, flags=re.DOTALL)  # re.DOTALL = multiline search
                                if result:
                                    # Call group only if we've got a hit to avoid crash and strip non-digits (aka: Magento notation)
                                    module_version = ".".join(re.findall(r'\d+', result.group(1)))
                                else:
                                    module_version = "unknown"

                            file['modules'][basename]   = module_version
                            i += 1

            j += 1

    print '[rocksolid-agent] Gevonden modules : %s' % i

    return results


def get_load_avg():
    if module_exists('os'):
        return str(os.getloadavg())
    else:
        return 'null'


def fetch_catalog( customerkey ):
    # Catalog contains instructions and parameters
    print "[rocksolid-agent] Fetching catalog with customer customerkey, please wait...."

    # Prepare the data
    query_args = { 'task'        : 'fetchcatalog',
                   'customerkey' : customerkey }

    # Query the rocksolid cloud
    try:
        data = urllib.urlencode(query_args)
        inst = urllib.urlopen("http://gw.rocksolid.io/agents/?%s" % data).read()
        print "[rocksolid-agent] Received catalog. Extracting instructions and parameters"
    except Exception, e:
        print "[rocksolid-agent] Unable to fetch catalog ... where did the cloud go?"
        sys.exit(1)

    # The catalog
    catalog = {}
    catalog['apps'] = {
        'hex': False,             # HEX (regex) based signature check
        'mat': False,             # Mathematical checks to detect obfuscated and encrypted files
        'md5': False,             # MD5 based signature check
        'src': False,             # Sourcecode check
        'mod': False,             # Sourcecode module check (requires source check to be enabled)
        'pac': True,              # Packages check (supports rpm/yum (rpm -qa) and apt)
        'prt': False,             # Analyse open ports aka listening sockets and firewall rules
        'cnf': False,             # Check system configuration files for possible weaknesses
    }
    catalog['param'] = {
        'debug_level' : 5,
        'debug_limit' : 1,
        'user_limit'  : 1,       # Limit number of hits per unique userdir
        'user_basedir': '/home',
    }

    return catalog


def run_apps( catalog, definitions ):
    print "[rocksolid-agent] Running the apps based on instructions and parameters in the catalog, please wait...."
    # Do source and signature based scan (combined in one run to avoid duplicate tree walk)

    results = {}

    # Initiate all the file based apps (combined in one run to open files only ones)
    # hex, mat, md5, src
    results['fil'] = scan_files( catalog, definitions )

    # mod (adds context)
    results['fil'] = scan_modules( catalog, definitions, results['fil'] )

    # pac
    results['pac'] = scan_packages( catalog )

    # prt
    results['prt'] = scan_ports()

    # cnf
    #results['cnf'] = scan_config()

    print "Finished apps, processing"

    return results




def scan_files( catalog, definitions ):
    if catalog['apps']['mat'] == False and catalog['apps']['src'] == False and catalog['apps']['hex'] == False:
        # Modules check disabled, return to main
        results = {}
        return results

    # Analyse CMS systems and scan for viruses, trojans and hacks
    # Definitions stored in rocksolid-definitions.txt
    results = {}
    nr_scanned = 0
    nr_userdir_found = {}
    nr_userdir_scanned = 0
    nr_found = 0
    pb_ctr = 0
    mat_patterns = ['*.php', '*.asp']
    openfilename = ''
    scanstart = datetime.now()

    print "[rocksolid-agent] Scanning files started at %s" % bcolors.OKBLUE + str(datetime.now()) + bcolors.ENDC

    nr_userdirs = len(list(os.walk(catalog['param']['user_basedir']).next()[1]))
    print "[rocksolid-agent] Total number of userdirs to be scanned is %s" % nr_userdirs

    pb = ProgressBar("[rocksolid-agent] Scanning files", nr_userdirs)
    pb.setAndPlot(nr_userdir_scanned, "Pass " + bcolors.OKGREEN + str(0) + bcolors.ENDC + ", hits " + bcolors.WARNING + str(0) + bcolors.ENDC)

    # Walk the folder
    for root, dirs, files in os.walk(catalog['param']['user_basedir']):
        # Logic for userdir limit
        dirstruct = root.split("/")
        try:
            if userdir != dirstruct[2]:
		nr_userdir_scanned += 1
            userdir = dirstruct[2]
        except Exception, e:
            userdir = catalog['param']['user_basedir']

        for basename in files:
            filename  = os.path.join(root, basename)
            nr_scanned += 1

            # Update progress bar on each 1000 files
            dt = datetime.now() - scanstart;
            sec = ((dt.days * 24 * 60 * 60 + dt.seconds) * 1000 + dt.microseconds / 1000.0) / 1000.0
            #pb_ctr +=1
            if sec >= 1:
		pb.setAndPlot(nr_userdir_scanned, "Pass " + bcolors.OKGREEN + str(nr_scanned) + bcolors.ENDC + ", hits " + bcolors.WARNING + str(nr_found) + bcolors.ENDC)
		#pb_ctr = 0
		scanstart = datetime.now()

            if catalog['apps']['mat'] == True and any(fnmatch.fnmatch(filename, p) for p in mat_patterns):
                # Do the MAT checks
                # Calculate entropy to check for obfuscation
                content = open(filename, 'rb').read(10240) # Read maximum of 10KB into memory
                openfilename = filename

                # Skip further processing on empty files
                if len(content) == 0:
                    break

                entropy = cal_entropy(content)
                # Everything above 6 is to be considered an anolomy
                if entropy > 6:
                    print '[rocksolid-agent] Entropy value for file %s = %s' % (filename, entropy)

                # Check for long strings to check for encrypted code
                longeststring = cal_longeststring(content)
                if longeststring > 1000:
                    if not re.search('Zend', content, flags=re.DOTALL):
                        print '[rocksolid-agent] Possible encrypted code in file %s = %s' % (filename, longeststring)

            # Match against all definitions
            i = 0
            while i < len(definitions):
                # SRC: Sourcecode recognition with version lookup
                # HEX: Signature based filtering to identify harmful and infected files
                # Load matching patterns
                patterns = definitions[i]['file'].split("|")

                if any(fnmatch.fnmatch(filename, p) for p in patterns):
                    if definitions[i]['type'] == 'SRC' and catalog['apps']['src'] == True:
                        # Source code match, lookup version
                        # Read entire file into memory
                        content = open(filename, 'rb').read(512000) # Read maximum of 500KB into memory  << re-open because need larger sample
                        openfilename = filename

                        result = re.search(definitions[i]['regex'], content, flags=re.DOTALL)  # re.DOTALL = multiline search
                        if result:
                            # Call group only if we've got a hit to avoid crash and strip non-digits (aka: Magento notation)
                            cms_version = ".".join(re.findall(r'\d+', result.group(1)))

                        #print '[rocksolid-agent] Hit %s on file %s, detected %s version %s' % (nr_found, filename, definitions[i]['name'], cms_version)

                        # Count number of hits in this userdir
                        nr_userdir_found[userdir] = nr_userdir_found.get(userdir, 0) + 1

                        # Only store result for further processing if user limit is not reached yet
                        if nr_userdir_found[userdir] < catalog['param']['user_limit']:
                            nr_found += 1
                            user   = get_user(filename)
                            domain = get_domain(agent['namecp'], filename)
                            email  = get_email(agent['namecp'], user)
                            results[nr_found] = {'type': 'SRC', 'path': filename, 'name': definitions[i]['name'], 'version': cms_version, 'user': user, 'domain': domain, 'email': email, 'md5': cal_md5_file(filename), 'mtime': os.path.getmtime(filename), 'atime': os.path.getatime(filename), 'ctime': os.path.getctime(filename)}
                        #else:
                           # print '[rocksolid-agent] Skipping hit %s because userdir limit is reached' % filename


                    if definitions[i]['type'] == 'HEX' and catalog['apps']['hex'] == True:
                        # scan file for trojans and hacks
                        # compile regex (use in future release, might save resources
                        # sig  = re.compile(definitions[i]['regex'] , flags=re.IGNORECASE)
                        if filename != openfilename:
                            content = open(filename, 'rb').read(10240) # Read maximum of 10KB into memory
                            openfilename = filename

                        if re.search(definitions[i]['regex'], content, flags=re.DOTALL):  # re.DOTALL = multiline search
                            #print '[rocksolid-agent] Hit %s on file %s, detected %s' % (nr_found, filename, definitions[i]['name'])

                            # Count number of hits in this userdir
                            nr_userdir_found[userdir] = nr_userdir_found.get(userdir, 0) + 1

                            # Only store result for further processing if user limit is not reached yet
                            if nr_userdir_found[userdir] < catalog['param']['user_limit']:
                                nr_found += 1
                                user   = get_user(filename)
                                domain = get_domain(agent['namecp'], filename)
                                email  = get_email(agent['namecp'], user)
                                results[nr_found] = {'type': 'SIG', 'path': filename, 'name': definitions[i]['name'], 'version': '', 'user': user, 'domain': domain, 'email': email, 'md5': cal_md5_file(filename), 'mtime': os.path.getmtime(filename), 'atime': os.path.getatime(filename), 'ctime': os.path.getctime(filename)}
                            #else:
                               # print '[rocksolid-agent] Skipping hit %s because userdir limit is reached' % filename

                            #break # Don't scan file again using other signatures... mistake... can hit on multiple signatures

                #next
                i += 1

            # Handle runtime limits
            if (nr_found == catalog['param']['debug_limit']):
                print "\n[rocksolid-agent] Debug limit of %s reached: returning results" % catalog['param']['debug_limit']
                analytics['nrscanned'] = nr_scanned
                analytics['nrfound']   = nr_found
                return results

    # Set progressbar to 100% and destroy
    pb.setAndPlot(nr_userdir_scanned, "Pass " + bcolors.OKGREEN + str(0) + bcolors.ENDC + ", hits " + bcolors.WARNING + str(0) + bcolors.ENDC)
    del pb

    # Store analytical data
    analytics['nrscanned'] = nr_scanned
    analytics['nrfound']   = nr_found

    print "[rocksolid-agent] Scanning files finished at %s (%s files scanned, %s files found)" % (datetime.now(), nr_scanned, nr_found)

    return results


def upload_results(agent, results):
    xml  = "<rocksolid-agent>\n"
    xml += "   <agent>\n"
    for k, v in agent.iteritems():
        xml += "      <%s>%s</%s>\n" % (k, v, k)
    xml += "      <missingpythonmodules>\n"
    i = 0
    while i < len(modules_missing):
        xml += "         <module>%s</module>\n" % modules_missing[i]
        i += 1
    xml += "      </missingpythonmodules>\n"
    xml += "   </agent>\n"

    # File based app (SRC,MOD)
    try:
        xml += "   <files>\n"

        # mtime = Last modified time aka creation date
        # atime = Last accessed time
        # ctime = Last changed time

        xmlTemplate = """         <path>%(path)s</path>
         <type>%(type)s</type>
         <name>%(name)s</name>
         <version>%(version)s</version>
         <user>%(user)s</user>
         <domain>%(domain)s</domain>
         <email>%(email)s</email>
         <md5>%(md5)s</md5>
         <mtime>%(mtime)s</mtime>
         <atime>%(atime)s</atime>
         <ctime>%(ctime)s</ctime>\n"""

        for hit,file in results['fil'].iteritems():
            print '[rocksolid-agent] File %s %s' % (hit, file)
            xml += '      <file>\n'
            xml += xmlTemplate%file
            xml += '         <modules>\n'
            try:
                for k, v in file['modules'].iteritems():
                    xml += '            <module>\n'
                    xml += '               <name>%s</name>\n' % k
                    xml += '               <version>%s</version>\n' % v
                    xml += '            </module>\n'
            except Exception, e:
                xml += ''
            xml += '         </modules>\n'
            xml += '      </file>\n'

        xml += "   </files>\n"
    except:
        pass

    # Packages app
    xml += "   <packages>\n"
    try:
        for package in results['pac']:
            xml += "      <package>%s</package>\n" % package
    except:
        pass

    xml += "   </packages>\n"
    xml += "   <analytics>\n"
    for k, v in analytics.iteritems():
        xml += "      <%s>%s</%s>\n" % (k, v, k)
    xml += "   </analytics>\n"

    xml += "</rocksolid-agent>"

    print "[rocksolid-agent] XML output"
    print xml

    # Communicate
    mydata   = [('xml',xml),('apikey',sys.argv[2])]  #The first is the var name the second is the value
    mydata   = urllib.urlencode(mydata)
    path     = 'http://gw.rocksolid.io/report/'   #the url you want to POST to
    req      = urllib2.Request(path, mydata)
    req.add_header("Content-type", "application/x-www-form-urlencoded")

    try:
        response = urllib2.urlopen(req).read()
        print '[rocksolid-agent] Uploaded data to rocksolid cloud. Processing....\n%s' % response
    except urllib2.HTTPError, error:
        response = error.read()
        print '[rocksolid-agent] Unable to upload data to rocksolid cloud.\n%s' % response

    return 'finished'


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


class ProgressBar:
    DEFAULT_BAR_LENGTH = float(45)

    def __init__(self, desc, end, start=0):
	import time
        self.desc   = desc
        self.end    = end
        self.start  = start
        self._barLength = ProgressBar.DEFAULT_BAR_LENGTH
        self.ts     = int(time.time())
	self.eta    = "..:.."
        self.info   = ""
        self.curper = 0

        self.setLevel(self.start)
        self._plotted = False
        os.system('setterm -cursor off')

    def setLevel(self, level, initial=False):
        self._level = level
        if level < self.start:  self._level = self.start
        if level > self.end:    self._level = self.end

        self._ratio = float(self._level - self.start) / float(self.end - self.start)
        self._levelChars = int(self._ratio * self._barLength)

    def plotProgress(self):
        import time
        import datetime

        # Start calculating > 3%
        if int(self._ratio * 100.0) > 3:
            self.sectoeta = ((int(time.time()) - self.ts) / int(self._ratio * 100.0) * 100) - (int(time.time()) - self.ts)   # Calculate total time - minus elapsed time
            self.eta      = time.strftime("%M:%S", time.gmtime(self.sectoeta))

        if int(self._ratio * 100.0) == 100:
            self.eta      = "00:00"

        # Print bar
        sys.stdout.write("\r%s %3i%% [%s%s%s%s]   ETA %s   %s" %(
            self.desc,
            int(self._ratio * 100.0),
            bcolors.OKBLUE,
            '=' * int(self._levelChars),
            ' ' * int(self._barLength - self._levelChars),
            bcolors.ENDC,
            self.eta,
            self.info,
        ))
        sys.stdout.flush()
        self._plotted = True

    def setAndPlot(self, level, info):
        oldChars = self._levelChars
        self.setLevel(level)
        self.info = info
        #if (not self._plotted) or (oldChars != self._levelChars):
        self.plotProgress()

    def __del__(self):
        os.system('setterm -cursor on')
        sys.stdout.write("\n")
        sys.stdout.flush()



# Start the proces
if __name__ == '__main__':
    # Set process name when running on Linux
    if detect_os() == 'Linux':
        set_proc_name('rocksolid-agent')

    # Set timing
    global analytics
    global modules_missing
    global packages
    modules_missing = []
    packages = []
    analytics = {}
    analytics['starttime'] = datetime.now()

    # Get the number of arguments passed
    argLen = len(sys.argv)

    if argLen > 1:
        if sys.argv[1] == 'run':
            # Require customerkey
            if argLen == 2:
                print "[rocksolid-agent] Please provide your customer key: %s run [customerkey]" % sys.argv[0]
                sys.exit(1)

            # Store server load at start
            analytics['startload'] = get_load_avg()

            # Set agent parameters
            agent       = get_agent_parameters()

            print '[rocksolid-agent] Starting security scan at %s'               %  bcolors.OKBLUE + str(analytics['starttime']) + bcolors.ENDC
            print '[rocksolid-agent] System load upon start = %s'                %  bcolors.OKBLUE + str(analytics['startload']) + bcolors.ENDC
            print '[rocksolid-agent] Detected hostname = %s'                     %  bcolors.OKBLUE + str(agent['hostname'])      + bcolors.ENDC
            print '[rocksolid-agent] Detected interface ip = %s'                 %  bcolors.OKBLUE + str(agent['interfaceip'])   + bcolors.ENDC
            print '[rocksolid-agent] Detected external ip = %s'                  %  bcolors.OKBLUE + str(agent['externalip'])    + bcolors.ENDC
            print '[rocksolid-agent] Detected operating system = %s, release %s' % (bcolors.OKBLUE + str(agent['nameos']), str(agent['versionos']) + bcolors.ENDC)
            print '[rocksolid-agent] Detected control panel = %s'                %  bcolors.OKBLUE + str(agent['namecp'])        + bcolors.ENDC
            print '[rocksolid-agent] Detected control panel version = %s'        %  bcolors.OKBLUE + str(agent['versioncp'])     + bcolors.ENDC
            print '[rocksolid-agent] Detected python version = %s'               %  bcolors.OKBLUE + str(agent['versionpython']) + bcolors.ENDC
            print '[rocksolid-agent] Detected PHP version = %s'                  %  bcolors.OKBLUE + str(agent['versionphp'])    + bcolors.ENDC

            # Load definitions
            definitions = load_definitions()

            # Fetch catalog (instructions and parameters)
            catalog     = fetch_catalog(sys.argv[2])                             # Pass customerkey

            # Run apps based on catalog
            results     = run_apps(catalog, definitions)

            # Analytical data
            analytics['endtime'] = datetime.now()
            analytics['runtime'] = detect_runtime()
            analytics['endload'] = get_load_avg()
            modules_missing      = sorted(set(modules_missing))                  # !?!?!?? is this the right place?

            # Upload results
            upload_results(agent, results)

            # Output footer
            i = 0
            while i < len(modules_missing):
                print '[rocksolid-agent] Module %s is missing. Please install for optimal usage of the agent' % modules_missing[i]
                i += 1
            print '[rocksolid-agent] Finished security scan at %s (in %s seconds)' % (analytics['endtime'], analytics['runtime'])
            print '[rocksolid-agent] System load upon finish = %s' % analytics['endload']

        elif sys.argv[1] == 'help':
            print '\n                           Welcome to rocksolid.\n'
            print '***********************************************************************************************\n'
            print 'To use this software agent, you can use the following commands:'
            print ' -run [customerkey]: run the agent; find the [customerkey] on http://www.rocksolid.io/dashboard'
            print ' -help: this screen'
            print ' -update: check for updates of the agent and or signature file'
            print '\n***********************************************************************************************'

        elif sys.argv[1] == 'update':
            __location__  = 'http://gw.rocksolid.io/agent/'                     # Sourcecode location
            __ratifymd5__ = 'http://ratify.rocksolid.io/agent/'                 # Sourcecode validation location

            # Package file list
            files = []
            files.append('rocksolid-agent.py')                                  # Agent file
            files.append('rocksolid-agent.def')                                 # Definition file

            # MD5 latest == MD5 current ... already up to date
            # MD5 latest != MD5 current but MD5 latest == MD5 cloud ... download and update
            # MD5 latest != MD5 current and MD5 latest != MD5 cloud ... don't continue... compromised!?

            i = 0
            while i < len(files):
                print '[rocksolid-agent] Downloading latest version %s' % files[i]
                try:
                    current_md5 = cal_md5_file(files[i])                        # MD5 of current version
                    ratify_md5  = urllib.urlopen(__ratifymd5__ + files[i])      # MD5 of latest version on validation server
                    tmpfile     = urllib.URLopener()
                    tmpfile.retrieve(__location + files[i], '.tmp' + files[i])  # Download new version to temporary file
                    tmpfile_md5 = cal_md5_file('.tmp' + files[i])               # Calculate checksum tmpfile
                    if tmpfile_md5 == current_md5:
                        status = 'Already up to date'
                    elif tmpfile_md5 != current_md5:
                        if tmpfile_md5 == ratify_md5:
                            status = 'Updated succesfully'
                            os.rename('.tmp' + files[i], files[i])              # All okay, overwrite local file
                        else:
                            # This is bad! Cloud compromised?
                            status = 'Update failed. MD5 checksum invalid'

                    print '[rocksolid-agent] Update $s:' % status
                except Exception, e:
                    print '[rocksolid-agent] Download %s failed' % files[i]
                i += 1
    else:
        print 'usage: %s run [customerkey]|help|update' % sys.argv[0]
        sys.exit(1)

