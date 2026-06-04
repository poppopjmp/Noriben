# Noriben Malware Analysis Sandbox
#
# Directions:
# Just copy Noriben.py to a Windows-based VM alongside the SysInternals Procmon.exe
#
# Run Noriben.py, then run your executable.
# When the executable has completed its processing, stop Noriben and view a
# clean text report and timeline
#
# Changelog:
# Version 2.5.0 - 04 Jun 2026 (poppopjmp fork)
#       Consolidated multi-run analysis:
#           --merge aggregates several *.iocs.json reports (files, globs, or a
#           folder) into one summary, showing which IOCs and ATT&CK techniques
#           are shared across runs vs unique to a sample - useful for profiling
#           a malware family. Writes Noriben_consolidated.{txt,json,html}
# Version 2.4.0 - 04 Jun 2026 (poppopjmp fork)
#       Detection-engineering exports:
#           --gen-sigma writes Sigma detection rules (*.sigma.yml) for dropped
#           executables, registry persistence, network endpoints, named pipes,
#           and suspicious command lines, tagged with MITRE ATT&CK
#           Stronger suggested YARA rules (now also include autostart/Run value
#           names that commonly appear in the binary)
#           --diff now also writes a self-contained HTML diff report
#           (*.diff.html) alongside the in-report text diff
# Version 2.3.0 - 04 Jun 2026 (poppopjmp fork)
#       More reverse-engineering value:
#           Extract named pipes and mutexes (infection markers) from activity
#           --gen-yara writes a suggested YARA rule built from behavioral
#           indicators (dropped file names, mutexes, pipes, network hosts)
#           --diff <baseline.iocs.json> shows what changed between two runs
#           (added/removed processes, files, hashes, registry, hosts, pipes,
#           mutexes, and ATT&CK techniques)
#           --stix exports IOCs as a STIX 2.1 bundle; --misp exports a MISP
#           event, both for ingestion by threat-intel platforms
# Version 2.2.0 - 04 Jun 2026 (poppopjmp fork)
#       New feature: automated triage for reverse engineers
#           Added a "Behavioral Summary & Indicators of Compromise" section at
#           the top of every report: activity counts, dropped-file hashes, and
#           network endpoints at a glance
#           Heuristic MITRE ATT&CK tagging of registry, file, and command-line
#           activity (persistence, service creation, scheduled tasks, LOLBINs,
#           recovery inhibition, defense evasion, etc.)
#           Added --json to emit a structured, machine-readable *.iocs.json
#           report (processes, files, registry, network, IOCs, ATT&CK) for
#           ingestion by other tooling. The IOC summary is also fed to the AI
#           analysis so its assessment is better grounded
# Version 2.1.0 - 04 Jun 2026 (poppopjmp fork)
#       New feature: AI-assisted report analysis
#           Added --ai to send the generated report to an OpenAI-compatible
#           Chat Completions endpoint (local Ollama, OpenAI, LM Studio, vLLM,
#           LiteLLM, etc.) for an automated behavioral analysis and risk
#           assessment. Configurable via --ai-provider/--ai-model/--ai-url or
#           the [Noriben] ai_* config keys. Output is appended to the report
#           and saved as a standalone *_AI_Analysis.md file
#           All AI failures are non-fatal; the standard report is unaffected
#       Added --version flag
#       Maintenance/support refresh:
#           Fixed crash in NoribenRead.py from leftover Python 2 unicode() call;
#           now decodes archive bytes correctly on Python 3
#           Fixed bug where a missing 'requests' module clobbered the stdlib
#           json module, breaking VirusTotal debug dumps
#           Cleaned up dead/unused variables flagged by pyflakes
#           Added requirements.txt, pyproject.toml, .gitignore, unit tests, and
#           GitHub Actions CI (byte-compile + pyflakes + tests on Py 3.8-3.12)
#       Aligned with upstream through v2.0.4 (logging library, full --cmd line,
#           non-Windows CSV reprocessing, --disable-file-hash, regular-file
#           checks, chunked hashing, IPv6-safe host parsing, Win11 filters)
#       Hardened during integration:
#           Added missing 'import stat' used by file_exists()
#           --disable-file-hash now sets the same config key parse_csv reads
#           --pml resolves procmon before use (fixes reference-before-set) while
#           keeping --csv procmon-free so non-Windows CSV reprocessing works
# Version 2.0.4 - 26 Mar 2026 (upstream)
#       Fixed bug of procmon variable referenced before set
#       Fixed server hostname parsing
# Version 2.0.3 - 25 Mar 2026
#       Change file checking to only approve regular files
#       Changed file hashing to now read in chunks instead of all at once
# Version 2.0.2 - 23 Mar 2026
#       Allow execution on Non-Windows solely for processing premade CSV files
#       Added disable-file-hash to avoid hashing created files
# Version 2.0.1 - November 2023
#       Logging is now based upon standard logging library
#       Now supports --cmd as a full command line to allow arguments. e.g.:
#       --cmd "c:\tools\malware.exe -r C:\"
# Version 2.0.0 - August 2023
#       Major changes to NoribenSandbox host script
#           Updated many of the functions, such as properly deleting files in guest
#           Remove unneeded or obtuse options
#       Move everything to all major settings to a configuration file
#       Many formatting changes
#
# Version 1.8.8 - 20 Jan 23
#       Replaced subprocess .wait() to .communicate() due to known process exec issue
#       which causes deadlocks in a small amount of cases
#       Added hardcoded timeout period for cases where it hangs
#       Thanks to Roman Hussy of abuse.ch for identifying and suggesting fix
# Version 1.8.7 - 30 Aug 22
#       Replaced csv.reader with csv.DictReader to have better forward and backward
#       compatibility. Small changes in style, PEP8
# Version 1.8.6 - 26 May 21
#       Fixed a long-standing bug that crashed the script when encountering certain
#       binary data in a registry key
# Version 1.8.5 - 02 May 21
#       Changed terminology from whitelist to approvelist. Updated filters. Added quick
#       fix related to issue #29/#44 for errant ticks in data
# Version 1.8.4 - 22 Nov 19
#       Minor updates. Added ability to run a non-executable, such as a Word document
# Version 1.8.3 - 26 Nov 18
#       Fixed minor bugs in reading hash files and in sleeping between VirusTotal queries
# Version 1.8.2 - 28 Jun 18
#       Fixed minor bug that would crash upon writing out CSV
# Version 1.8.1 - 14 Jun 18
#       Added additional config options, such as output_folder. Added value
#       global_whitelist_append to allow additional filters
# Version 1.8.0 - 9 Jun 18
#       Really, truly, dropping Python 2 support now. Added --config file option to load
#       global variables from external files. Now uses CSV library. Code cleanup
# Version 1.7.6 - 12 Apr 18 -
#       Some auto PEP-8 formatting. Fixed bug where specific output dir wouldn't add
#       to files when specifying a PML or CSV file. Added configuration of new txt
#       extension in cases where ransomware was encrypting files. CSV, however, cannot
#       be changed due to limitations in ProcMon
# Version 1.7.5 - 10 Mar 18 -
#       Another bug fix related to global use of renamed procmon binary. Edge case fix
# Version 1.7.4 - 28 Feb 18 -
#       More bug fixes related to global use of renamed procmon binary. Added filters
# Version 1.7.3b - 7 Jan 18 -
#       Implemented --troubleshoot option to pause the program upon exit so that the
#       error messages can be seen manually
# Version 1.7.3 - 26 Dec 17 -
#       Fixed bug where a changed procmon binary was not added to the whitelist, and
#       would therefore be included in the output
# Version 1.7.2 - 21 Apr 17 -
#       Fixed Debug output to go to a log file continually, so output is stored if
#       unexpected exit. Check for PML and Config file between executions to account
#       for destructive malware that erases during runtime. Added headless option for
#       automated runs, so that screenshot can be grabbed w/o output on screen
# Version 1.7.1 - 3 Apr 17 -
#       Small updates. Change --filter to not find default if a bad one is specified
# Version 1.7.0 - 4 Feb 17 -
#       Default hash method is now SHA256. An argument and global var allow to
#       override hash. Numerous filters added. PEP8 cleanup, multiple small fixes to
#       code and implementation styles
# Version 1.6.4 - 7 Dec 16 -
#       A handful of bug fixes related to bad Internet access. Small variable updates.
# Version 1.6.3 - 13 Jan 16 -
#       Bug fixes to handle path joining. Bug fixes for spaces in all directory
#       names. Added support to find default PMC from script working directory.
# Version 1.6.2 - 9 Apr 15 -
#       Created debug output to file. This now includes full VirusTotal dumps.
#       Currently Noriben only displays number of hits, but additional meta is now
#       dumped for further analysis by users.
# Version 1.6.1 - 16 Mar 15 -
#       Soft fails on Requests import. Lack of module now just disables VirusTotal.
#       Added better YARA handling. Instead of failing over a single error, it
#       will skip the offending file. You can now hard-set the YARA signature
#       folder in the script.
# Version 1.6 - 14 Mar 15 -
#       Long delayed and now forked release. This will be the final release for
#       Python 2.X except for updated rules. Now requires 3rd party libraries.
#       VirusTotal API scanning implemented. Added better filters.
#       Added controls for some registry writes that had size but no data.
#       Added whitelist for MD5 hashes and --hash option for hash file.
#       Renamed 'blacklist' to 'whitelist' because it's supposed to be. LOL
#       Change file handling due to 'read entire file' bug in FileInput.
# Version 1.5b - 1 Oct 13 -
#       Ninja edits to fix a few small bug fixes and change path generalization
#       to an ordered list instead of an unordered dictionary. This lets you
#       prioritize resolutions.
# Version 1.5 - 28 Sep 13 -
#       Standardized to single quotes, added YARA scanning of resident files,
#       reformatted function comments to match appropriate docstring format,
#       fixed bug with generalize paths - now generalizes after getting MD5
# Version 1.4 - 16 Sep 13 -
#       Fixed string generalization on file rename and now supports ()'s in
#       environment name (for 64-bit systems), added ability to Ctrl-C from
#       a timeout, added specifying malware file from command line, added an
#       output directory
# Version 1.3 - 13 Sep 13 -
#       Option to generalize file paths in output, option to use a timeout
#       instead of Ctrl-C to end monitoring, only writes RegSetValue entries
#       if Length > 0
# Version 1.2 - 28 May 13 -
#       Now reads CSV files line-by-line to handle large files, keep
#       unsuccessful registry deletes, compartmentalize sections, creates CSV
#       timeline, can reparse PMLs, can specify alternative PMC filters,
#       changed command line arguments, added global approvelist
# Version 1.1a - 1 May 13 -
#       Revamped regular expression support. Added Python 3.x forward
#       compatibility
# Version 1.1 - 21 Apr 13 -
#       Much improved filters and filter parsing
# Version 1.0 - 10 Apr 13 - @bbaskin - brian [@] thebaskins.com
#       Gracious edits, revisions, and corrections by Daniel Raygoza
#

import argparse
import codecs
import csv
import datetime
import glob
import hashlib
import ipaddress
import json
import logging
import os
import re
import shlex
import stat
import subprocess
import string
import sys
import time
import traceback
import uuid

try:
    import yara  # pip yara-python

    has_yara = True
except ImportError:
    yara = None
    has_yara = False

try:
    import requests

    has_internet = True
except ImportError:
    requests = None
    has_internet = False

try:
    import configparser
except ImportError:
    print('[!] Python module "configparser" not found. Python 3 required.')
    configparser = None

# Below are global internal variables. Do not edit these. ################
__VERSION__ = '2.5.0'
use_pmc = False
use_virustotal = False
vt_results = {}
vt_dump = []
debug_messages = []
exe_cmdline = ''
time_exec = 0
time_process = 0
script_cwd = ''
debug_file = ''
config = {}
global_approvelist = ''
reg_approvelist = ''
file_approvelist = ''
cmd_approvelist = ''
net_approvelist = ''
hash_approvelist = ''
path_general_list = []

valid_hash_types = ['MD5', 'SHA1', 'SHA256']
##########################################################################


noriben_errors = {
    0: 'Successful execution',
    1: 'PML file was not found',
    2: 'Unable to find procmon.exe',
    3: 'Unable to create output directory',
    4: 'Windows is refusing execution based upon permissions',
    5: 'Could not create CSV',
    6: 'Could not find malware file',
    7: 'Error converting PML to CSV',
    8: 'Error creating PML',
    9: 'Unknown error',
    10: 'Invalid arguments given',
    11: 'Missing Python module',
    12: 'Error in host module configuration',
    13: 'Required file not found',
    14: 'Configuration issue',
    50: 'General error'
}


def get_error(code):
    """
    Looks up a given code in dictionary set of errors of noriben_errors.

    Arguments:
        code: Integer that corresponds to a pre-set entry
    Returns:
         string value of a error code
    """
    if code in noriben_errors:
        return noriben_errors[code]
    return 'Unexpected Error'


def read_config(config_filename):
    """
    Parse an external configuration file.

    Arguments:
        config_filename: String of filename, predetermined if exists
    Returns:
        none
    """
    global global_approvelist, reg_approvelist, file_approvelist, cmd_approvelist
    global net_approvelist, hash_approvelist

    config = {}
    try:
        file_config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
        with codecs.open(config_filename, 'r', encoding='utf-8') as f:
            file_config.read_file(f)

        config = {}
        options = file_config.options('Noriben')
        for option in options:
            config[option] = file_config.get('Noriben', option)
            if config[option].lower() in ['true', 'false']:
                config[option] = file_config.getboolean('Noriben', option)
            if config[option] == -1:
                print('[*] Invalid configuration option detected: {}'.format(option))

        global_approvelist = file_config.get('Filters', 'global_approvelist').replace('\n','').split(',')
        reg_approvelist = file_config.get('Filters', 'reg_approvelist').replace('\n','').split(',')
        file_approvelist = file_config.get('Filters', 'file_approvelist').replace('\n','').split(',')
        cmd_approvelist = file_config.get('Filters', 'cmd_approvelist').replace('\n','').split(',')
        net_approvelist = file_config.get('Filters', 'net_approvelist').replace('\n','').split(',')
        hash_approvelist = file_config.get('Filters', 'hash_approvelist').replace('\n','').split(',')

        # Throwing a large one in here to ignore anything that the configured procmon executable creates
        global_approvelist.append(config['procmon'])
        global_approvelist.append(config['procmon'].split('.')[0] + '64.exe')  # Procmon drops embed as <name>+64

    except configparser.MissingSectionHeaderError:
        print('[!] Error found in reading config file. Invalid section header detected.')
        sys.exit(12)
    except Exception as e:
        print(e)
        time.sleep(5)
        sys.exit(12)

    # Apply defaults for optional/newer settings so older config files keep working
    optional_defaults = {
        'disable-file-hash': False,
        'json_report': False,
        'gen_yara': False,
        'gen_sigma': False,
        'stix_export': False,
        'misp_export': False,
        'ai_enabled': False,
        'ai_provider': 'ollama',
        'ai_base_url': '',
        'ai_model': '',
        'ai_api_key': '',
        'ai_timeout': '120',
        'ai_max_chars': '60000'
    }
    for opt_key, opt_value in optional_defaults.items():
        config.setdefault(opt_key, opt_value)

    return config


def human():
    """
    Implemented basic human emulation code. This performs minor interaction
    with the OS that could help bypass anti-analysis in some malware families

    Arguments:
        none
    Returns:
        none
    """
    try:
        import pyautogui
    except ImportError:
        return None

    screenwidth, screenheight = pyautogui.size()
    x_pos = screenwidth/2
    y_pos = screenheight/2
    log_debug('[*] Performing human mouse emulation. Starting coordinates: {}, {}'.format(x_pos, y_pos))

    for i in range(5):
        pyautogui.moveTo(x_pos, y_pos, duration = 0.1)

        pyautogui.moveTo(x_pos+250, y_pos+250, duration = 0.1)
        pyautogui.moveTo(x_pos-250, y_pos, duration = 0.1)

        pyautogui.moveTo(x_pos-500, y_pos, duration = 0.1)
        pyautogui.moveTo(x_pos-250, y_pos+500, duration = 0.1)


def network_split_host_port(server):
    """
    Split servers to unique host and port values.
    A standard split breaks IPv6

    Arguments:
        server: String of server with optional port
    Returns:
        string of host, string of port
    """
    server = server.strip()

    if server.startswith("["):  # [IPv6]:port
        host, _, rest = server[1:].partition("]")
        return host, (rest[1:] if rest.startswith(":") and rest[1:].isdigit() else None)

    try:  # plain IPv4 or IPv6
        ipaddress.ip_address(server)
        return server, None
    except ValueError:
        pass

    host, sep, port = server.rpartition(":")
    return (host, port) if sep and port.isdigit() else (server, None)


def terminate_self(error):
    """
    Implemented for better troubleshooting.

    Arguments:
        error: Int of error code to return to system parent
    Returns:
        none
    """
    if error != 0:
        print(f'[*] Exiting with error code: {error}: {get_error(error)}')
    if config['troubleshoot']:
        errormsg = '[*] Configured to pause for troubleshooting. Press enter to close Noriben.'
        input(errormsg)
    sys.exit(error)


def log_debug(msg, override=False):
    """
    Logs a passed message. Results are printed and stored in
    a list for later writing to the debug log.
    Debug filename may not be set until later in execution. To avoid
    out-of-order messages, if debug_file is not set, then messages
    will be appended to a debug_messages buffer. Once debug_file is set
    these are written to the log, then cleared and that buffer is never
    used again.

    Arguments:
        msg: Text string of message
        override: optional value that forces the output even if debug is not set
    Returns:
        none
    """
    global debug_messages

    if msg and (config['debug'] or override):
        if debug_file:
            if debug_messages:
                # If file is now set, and there's a buffer, treat this is
                # first time log entries are written.
                logging.basicConfig(filename=debug_file, encoding='utf-8', level=logging.DEBUG)

                for item in debug_messages:
                    logging.debug(item)

                debug_messages = []

            logging.debug(msg)
        else: # No debug file set, so add to temp buffer for now
            debug_messages.append(msg)


def generalize_vars_init():
    """
    Initialize a dictionary with the local system's environment variables.
    Returns via a global variable, path_general_list

    Arguments:
        none
    Returns:
        none
    """
    envvar_list = [r'%AllUsersProfile%',
                   r'%LocalAppData%',
                   r'%AppData%',
                   r'%CommonProgramFiles%',
                   r'%ProgramData%',
                   r'%ProgramFiles%',
                   r'%ProgramFiles(x86)%',
                   r'%Public%',
                   r'%Temp%',
                   r'%UserProfile%',
                   r'%WinDir%']

    log_debug('[*] Enabling Windows string generalization.')

    for env in envvar_list:
        try:
            # ProgramFiles is handled specially in 64-bit environments
            # It's real value is in ProgramW6432
            if env == '%ProgramFiles%':
                resolved = os.path.expandvars('%ProgramW6432%').replace("\\", "\\\\")
            else:
                resolved = os.path.expandvars(env).replace("\\", "\\\\")

            path_general_list.append([env, resolved])
        except TypeError:
            if resolved in locals():
                log_debug('[!] generalize_vars_init(): Unable to parse var: {}'.format(resolved))
            continue


def generalize_var(path_string):
    """
    Generalize a given string to include its environment variable

    Arguments:
        path_string: string value to generalize
    Returns:
        string value of a generalized string
    """
    # For running script in Non-Windows, it cannot eval env vars. Skip
    if sys.platform in ('linux' ,'darwin'):
        return path_string

    if path_general_list:
        generalize_vars_init()  # For edge cases when this isn't previously called.

    for item in path_general_list:
        path_string = re.sub(item[1], item[0], path_string)

    return path_string


def read_hash_file(hash_filename):
    """
    Read a given file of SHA256 hashes and add them to the hash approvelist.

    Arguments:
        hash_filename: path to a text file containing hashes (either flat or sha256deep)
    """
    hash_file_handle = open(hash_filename, newline='', encoding='utf-8')
    reader = csv.DictReader(hash_file_handle)
    for hash_line in reader:
        hashval = hash_line[0]
        try:
            if int(hashval, 16) and (len(hashval) == 32 or len(hashval) == 40 or len(hashval) == 64):
                hash_approvelist.append(hashval)
        except (TypeError, ValueError):
            pass


def virustotal_upload_file(path):
    """
    Submit a given file to VirusTotal to retrieve number of alerts

    Arguments:
        path: string path to the file to be queried
    """
    if not has_internet:
        return False

    vt_url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    data = open(path, 'rb').read()

    response = requests.post(vt_url, files={'file': (path, data)}, params={'apikey': config['virustotal_api_key']})

    log_debug('[*] VirusTotal upload results for hash {}'.format(path))
    if response.json()['response_code'] != 1:
        log_debug('[!] Error uploading file to VirusTotal: {}'.format(response['verbose_msg']))
        return False
    return True


def virustotal_query_hash(hashval, path):
    """
    Submit a given hash to VirusTotal to retrieve number of alerts

    Arguments:
        hashval: string of SHA256 hash to a given file
        path: string path to the file to be queried
    """
    # VirusTotal v2 API "response_code" values used below.
    # (Other documented codes -1, -3..-10 are not acted on by Noriben.)
    VT_NOT_EXIST = 0
    VT_SUCCESS = 1
    VT_IN_QUEUE = -2

    result = ''

    if not has_internet:
        return ''
    try:
        if not (int(hashval, 16) and (len(hashval) == 32 or len(hashval) == 40 or len(hashval) == 64)):
            return ''
    except (TypeError, ValueError):
        pass

    try:
        previous_result = vt_results[hashval]
        log_debug('[*] VT scan already performed for {}. Returning previous: {}'.format(hashval, previous_result))
        return previous_result
    except KeyError:
        pass

    vt_query_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    post_params = {'apikey': config['virustotal_api_key'],
                   'resource': hashval}

    log_debug('[*] Querying VirusTotal for hash: {}'.format(hashval))

    data = {}

    try:
        http_response = requests.post(vt_query_url, post_params)
    except requests.exceptions.RequestException:
        return ''  # null string to append to output

    if http_response.status_code == 204:
        print('[!] VirusTotal Rate Limit Exceeded. Sleeping for 60 seconds.')
        time.sleep(60)
        return virustotal_query_hash(hashval, path)

    elif http_response.status_code == 404:
        log_debug('[*] File not available on VirusTotal. Submitting.')
        upload_complete = virustotal_upload_file(path)
        if not upload_complete:
            return ''

        return virustotal_query_hash(hashval, path)

    elif http_response.status_code == 200:
        try:
            data = http_response.json()
        except ValueError:
            result = 'Error'

        if data['response_code'] == VT_IN_QUEUE:
            print('[*] {} queued by VT for analysis. Retrying in 30 seconds.'.format(hashval))
            time.sleep(30)
            return virustotal_query_hash(hashval, path)

        elif data['response_code'] == VT_NOT_EXIST:
            log_debug('[*] File not available on VirusTotal. Submitting.')
            upload_complete = virustotal_upload_file(path)
            time.sleep(10)
            return virustotal_query_hash(hashval, path)

        elif data['response_code'] == VT_SUCCESS:
            if data['total']:
                vt_dump.append(data)
                result = ' [VT: {}/{}]'.format(data['positives'], data['total'])
            else:
                result = ' [VT: Unknown Error {}]'.format(data['response_code'])

        vt_results[hashval] = result
        log_debug('[*] VirusTotal result for hash {}: {}'.format(hashval, result))
        return result
    else:
        # Unknown return status code
        # TODO
        return False


def yara_rule_check(yara_files):
    """
    Scan a dictionary of YARA rule files to determine
    which are valid for compilation.

    Arguments:
        yara_files: path to folder containing rules
    """
    result = {}
    for yara_id in yara_files:
        fname = yara_files[yara_id]
        try:
            yara.compile(filepath=fname)
            result[yara_id] = fname
        except yara.SyntaxError:
            log_debug('[!] Syntax Error found in YARA file: {}'.format(fname))
            log_debug(traceback.format_exc())
    return result


def yara_import_rules(yara_path):
    """
    Import a folder of YARA rule files

    Arguments:
        yara_path: path to folder containing rules
    Returns:
        rules: a yara.Rules structure of available YARA rules
    """
    yara_files = {}
    if not yara_path[-1] == '\\':
        yara_path += '\\'

    print('[*] Loading YARA rules from folder: {}'.format(yara_path))
    files = os.listdir(yara_path)

    for file_name in files:
        file_extension = os.path.splitext(file_name)[1]
        if '.yar' in file_extension:
            yara_files[file_name.split(os.sep)[-1]] = os.path.join(yara_path, file_name)

    yara_files = yara_rule_check(yara_files)
    rules = ''
    if yara_files:
        try:
            rules = yara.compile(filepaths=yara_files)
            print('[*] YARA rules loaded. Total files imported: {}'.format(len(yara_files)))
        except yara.SyntaxError:
            print('[!] YARA: Unknown Syntax Errors found.')
            print('[!] YARA rules disabled until all Syntax Errors are fixed.')
            log_debug('[!] YARA: Unknown Syntax Errors found.')
            log_debug('[!] YARA rules disabled until all Syntax Errors are fixed.')
    return rules


def yara_filescan(file_path, rules):
    """
    Scan a given file to see if it matches a given set of YARA rules

    Arguments:
        file_path: full path to a file to scan
        rules: a yara.Rules structure of available YARA rules
    Returns:
        results: a string value that's either null (no hits)
                 or formatted with hit results
    """
    if not rules:
        return ''
    if os.path.isdir(file_path):
        return ''

    try:
        matches = rules.match(file_path)
    except yara.Error:  # If can't open file
        log_debug('[!] YARA can\'t open file: {}'.format(file_path))
        return ''
    if matches:
        results = '\t[YARA: {}]'.format(', '.join(str(x) for x in matches))
    else:
        results = ''
    return results


def open_file_with_assoc(fname):
    """
    Opens the specified file with its associated application

    Arguments:
        fname: full path to a file to open
    Returns:
        integer value for command return code
    """
    log_debug('[*] Opening with OS associated application: {}'.format(fname))

    # In headless/automated runs we never want to pop a viewer window
    if config.get('headless'):
        log_debug('[*] Headless mode enabled; not opening {}'.format(fname))
        return None

    try:
        if sys.platform == 'darwin':
            return subprocess.call(('open', fname))
        if os.name == 'nt':
            # os.startfile(fname)
            return subprocess.call(('start', fname), shell=True)
        if sys.platform.startswith('linux'):
            return subprocess.call(('xdg-open', fname))
        if os.name == 'posix':
            return subprocess.call(('open', fname))
    except (OSError, subprocess.SubprocessError) as err:
        # Common when reprocessing a CSV on a headless/non-desktop host
        log_debug('[!] Could not open {} with associated application: {}'.format(fname, err))

    return None


def file_exists(fname):
    """
    Determine if a file exists and is a regular file

    Arguments:
        fname: path to a file
    Returns:
        boolean value if file exists
    """

    log_debug('[*] Checking for existence of file: {}'.format(fname))
    try:
        st = os.stat(fname)
        return stat.S_ISREG(st.st_mode)  # Only true for regular files
    except (FileNotFoundError, PermissionError):
        return False


def check_procmon():
    """
    Finds the local path to Procmon

    Returns:
        folder path to procmon executable
    """
    log_debug('[*] Checking for procmon in the following location: {}'.format(config['procmon']))
    procmon_exe = config['procmon']

    if file_exists(procmon_exe):
        return procmon_exe

    for path in os.environ['PATH'].split(os.pathsep):
        procmon_path = os.path.join(path.strip('"'), procmon_exe)

        if file_exists(procmon_path):
            return procmon_path

    if file_exists(os.path.join(script_cwd, procmon_exe)):
        return os.path.join(script_cwd, procmon_exe)

    return ''


def hash_file(fname):
    """
    Given a filename, returns the hex hash value

    Arguments:
        fname: path to a file
    Returns:
        hex hash value of file's contents as a string
    """
    log_debug('[*] Performing {} hash on file: {}'.format(config['hash_type'], fname))
    # Skip non-regular files
    if not file_exists(fname):
        log_debug('[!] Skipping non-regular file: {}'.format(fname))
        return None

    # choose hash type
    if config['hash_type'] == 'MD5':
        hasher = hashlib.md5()
    elif config['hash_type'] == 'SHA1':
        hasher = hashlib.sha1()
    elif config['hash_type'] == 'SHA256':
        hasher = hashlib.sha256()
    else:
        return ''

    # Read file in chunks
    try:
        with open(fname, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        log_debug(f"[!] Could not hash file {fname}: {e}")
        return None


def get_session_name():
    """
    Returns current date and time stamp for file name

    Returns:
        string value of a current timestamp to apply to log file names
    """
    return datetime.datetime.now().strftime('%d_%b_%y__%H_%M_%f')


def protocol_replace(text):
    """
    Replaces text name resolutions from domain names

    Arguments:
        text: string of domain with resolved port name
    Returns:
        string value with resolved port name in decimal format
    """
    replacements = [(':https', ':443'),
                    (':http', ':80'),
                    (':domain', ':53')]
    for find, replace in replacements:
        text = text.replace(find, replace)
    return text


def approvelist_scan(approvelist, data):
    """
    Given a approvelist and data string, see if data is in approvelist

    Arguments:
        approvelist: list of items to ignore
        data: string value to compare against approvelist
    Returns:
        boolean value of if item exists in approvelist
    """
    for event in data.values():
        for good_item in approvelist + global_approvelist:
            good_item = os.path.expandvars(good_item).replace('\\', '\\\\')
            try:
                search_result = re.search(good_item, event, flags=re.IGNORECASE)
                if search_result:
                    return True
            except re.error:
                log_debug('[!] Error found while processing filters.\r\nFilter:\t{}\r\nEvent:\t{}'.format(good_item, event))
                log_debug(traceback.format_exc())
                return False
    return False


def process_pml_to_csv(procmonexe, pml_file, pmc_file, csv_file):
    """
    Uses Procmon to convert the PML to a CSV file

    Arguments:
        procmonexe: path to Procmon executable
        pml_file: path to Procmon PML output file
        pmc_file: path to PMC filter file
        csv_file: path to output CSV file
    Returns:
        None
    """
    global time_process
    time_convert_start = time.time()

    log_debug('[*] Converting session to CSV: {}'.format(csv_file))
    if not file_exists(pml_file):
        print('[!] Error detected. PML file was not found: {}'.format(pml_file))
        terminate_self(1)
    cmdline = '"{}" /OpenLog "{}" /SaveApplyFilter /saveas "{}"'.format(procmonexe, pml_file, csv_file)
    if use_pmc and file_exists(pmc_file):
        cmdline += ' /LoadConfig "{}"'.format(pmc_file)
    log_debug('[*] Running cmdline: {}'.format(cmdline))
    process = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    time_convert_end = time.time()
    time_process = time_convert_end - time_convert_start


def launch_procmon_capture(procmonexe, pml_file, pmc_file):
    """
    Launch Procmon to begin capturing data

    Arguments:
        procmonexe: path to Procmon executable
        pml_file: path to Procmon PML output file
        pmc_file: path to PMC filter file
    Returns:
        None
    """
    global time_exec
    time_exec = time.time()

    cmdline = '"{}" /BackingFile "{}" /Quiet /Minimized'.format(procmonexe, pml_file)
    if use_pmc and file_exists(pmc_file):
        cmdline += ' /LoadConfig "{}"'.format(pmc_file)
    log_debug('[*] Running cmdline: {}'.format(cmdline))
    subprocess.Popen(cmdline)
    time.sleep(3)


def terminate_procmon(procmonexe):
    """
    Terminate Procmon cleanly

    Arguments:
        procmonexe: path to Procmon executable
    Returns:
        None
    """
    global time_exec
    time_exec = time.time() - time_exec

    cmdline = '"{}" /Terminate'.format(procmonexe)
    log_debug('[*] Running cmdline: {}'.format(cmdline))
    process = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        process.wait(timeout=600)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()


# Regexes used to turn Noriben's human-readable report lines back into
# structured records for IOC extraction and JSON export.
_TAGGED_LINE_RE = re.compile(r'^\[(?P<tag>[^\]]+)\]\s+(?P<proc>.+?):(?P<pid>\d+)\s+>\s+(?P<rest>.*)$')
_HASH_RE = re.compile(r'\[(?:MD5|SHA1|SHA256):\s*(?P<hash>[0-9a-fA-F]{32,64})\]')
_CHILD_PID_RE = re.compile(r'\[Child PID:\s*(\d+)\]')
# Named pipes and mutexes (mutants) frequently show up in created-file paths
_NAMED_PIPE_RE = re.compile(r'(?:\\Device\\NamedPipe\\|\\\\\.\\pipe\\|\\pipe\\)(?P<name>[^\t]+)', re.I)
_MUTEX_RE = re.compile(r'\\BaseNamedObjects\\(?P<name>[^\t]+)', re.I)

# Heuristic MITRE ATT&CK rules. Each entry: (compiled_regex, technique_id, name)
# Applied to registry keys, created-file paths, and process command lines.
_REGISTRY_ATTACK_RULES = [
    (re.compile(r'\\CurrentVersion\\Run(Once)?\b', re.I), 'T1547.001', 'Registry Run Keys / Startup Folder'),
    (re.compile(r'\\Policies\\Explorer\\Run\b', re.I), 'T1547.001', 'Registry Run Keys / Startup Folder'),
    (re.compile(r'\\CurrentVersion\\Windows\\(Load|Run)\b', re.I), 'T1547.001', 'Registry Run Keys / Startup Folder'),
    (re.compile(r'\\Winlogon\b', re.I), 'T1547.004', 'Winlogon Helper DLL'),
    (re.compile(r'\\CurrentControlSet\\Services\\', re.I), 'T1543.003', 'Create or Modify System Process: Windows Service'),
    (re.compile(r'\\Image File Execution Options\\', re.I), 'T1546.012', 'Image File Execution Options Injection'),
    (re.compile(r'AppInit_DLLs', re.I), 'T1546.010', 'AppInit DLLs'),
    (re.compile(r'\\CurrentVersion\\Explorer\\(User Shell Folders|Shell Folders)\b', re.I), 'T1547.001', 'Registry Run Keys / Startup Folder'),
]
_FILE_ATTACK_RULES = [
    (re.compile(r'\\Start Menu\\Programs\\Startup\\', re.I), 'T1547.001', 'Registry Run Keys / Startup Folder'),
    (re.compile(r'\\System32\\Tasks\\|\\Windows\\Tasks\\', re.I), 'T1053.005', 'Scheduled Task'),
]
_CMDLINE_ATTACK_RULES = [
    (re.compile(r'\bschtasks\b', re.I), 'T1053.005', 'Scheduled Task'),
    (re.compile(r'\bsc(\.exe)?\b.*\bcreate\b', re.I), 'T1543.003', 'Create or Modify System Process: Windows Service'),
    (re.compile(r'\bpowershell\b', re.I), 'T1059.001', 'Command and Scripting Interpreter: PowerShell'),
    (re.compile(r'(?:^|\s)-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}', re.I), 'T1027', 'Obfuscated Files or Information'),
    (re.compile(r'\bcmd(\.exe)?\b\s+/c\b', re.I), 'T1059.003', 'Command and Scripting Interpreter: Windows Command Shell'),
    (re.compile(r'\b(wscript|cscript)\b', re.I), 'T1059.005', 'Command and Scripting Interpreter: Visual Basic'),
    (re.compile(r'\bvssadmin\b.*\bdelete\b', re.I), 'T1490', 'Inhibit System Recovery'),
    (re.compile(r'\bwmic\b.*shadowcopy.*delete', re.I), 'T1490', 'Inhibit System Recovery'),
    (re.compile(r'\bbcdedit\b', re.I), 'T1490', 'Inhibit System Recovery'),
    (re.compile(r'\brundll32\b', re.I), 'T1218.011', 'System Binary Proxy Execution: Rundll32'),
    (re.compile(r'\bregsvr32\b', re.I), 'T1218.010', 'System Binary Proxy Execution: Regsvr32'),
    (re.compile(r'\bmshta\b', re.I), 'T1218.005', 'System Binary Proxy Execution: Mshta'),
    (re.compile(r'\bcertutil\b', re.I), 'T1140', 'Deobfuscate/Decode Files or Information'),
    (re.compile(r'\bbitsadmin\b', re.I), 'T1197', 'BITS Jobs'),
    (re.compile(r'\bnetsh\b.*firewall', re.I), 'T1562.004', 'Impair Defenses: Disable or Modify System Firewall'),
    (re.compile(r'\battrib\b.*\+h', re.I), 'T1564.001', 'Hide Artifacts: Hidden Files and Directories'),
    (re.compile(r'\b(taskkill|net\s+stop)\b', re.I), 'T1562.001', 'Impair Defenses: Disable or Modify Tools'),
]


def analyze_indicators(process_output, file_output, reg_output, net_output, remote_servers, hash_type='SHA256'):
    """
    Turn Noriben's categorized report lines into structured indicators that
    are useful to a reverse engineer: created/deleted/renamed files (with
    hashes), registry writes, network endpoints, and a deduplicated list of
    dropped-file hashes.

    Arguments:
        process_output, file_output, reg_output, net_output: lists of report
            lines produced by parse_csv
        remote_servers: list of unique remote host strings
        hash_type: configured hash algorithm name (for labeling)
    Returns:
        dict of structured indicators
    """
    indicators = {
        'processes': [],
        'files_created': [],
        'files_deleted': [],
        'files_renamed': [],
        'registry': [],
        'network_hosts': sorted({protocol_replace(s).strip() for s in remote_servers if s.strip()}),
        'network_connections': list(net_output),
        'dropped_file_hashes': [],
        'named_pipes': [],
        'mutexes': []
    }

    for line in process_output:
        match = _TAGGED_LINE_RE.match(line)
        if not match:
            continue
        rest = match.group('rest')
        # parse_csv wraps the command line in literal quotes; drop them
        cmdline = rest.split('\t')[0].strip().strip('"')
        child = _CHILD_PID_RE.search(rest)
        indicators['processes'].append({
            'process': match.group('proc').strip(),
            'pid': match.group('pid'),
            'command_line': cmdline,
            'child_pid': child.group(1) if child else None
        })

    seen_hashes = set()
    for line in file_output:
        match = _TAGGED_LINE_RE.match(line)
        if not match:
            continue
        tag = match.group('tag')
        rest = match.group('rest')
        path = rest.split('\t')[0].strip()
        if tag == 'CreateFile':
            pipe_match = _NAMED_PIPE_RE.search(path)
            mutex_match = _MUTEX_RE.search(path)
            if pipe_match:
                pipe = pipe_match.group('name').strip()
                if pipe not in indicators['named_pipes']:
                    indicators['named_pipes'].append(pipe)
                continue
            if mutex_match:
                mutex = mutex_match.group('name').strip()
                if mutex not in indicators['mutexes']:
                    indicators['mutexes'].append(mutex)
                continue
            hash_match = _HASH_RE.search(rest)
            hashval = hash_match.group('hash') if hash_match else None
            indicators['files_created'].append({'path': path, 'hash': hashval})
            if hashval and hashval not in seen_hashes:
                seen_hashes.add(hashval)
                indicators['dropped_file_hashes'].append(
                    {'path': path, 'hash': hashval, 'hash_type': hash_type})
        elif tag == 'DeleteFile':
            indicators['files_deleted'].append(path)
        elif tag == 'RenameFile':
            if ' => ' in path:
                src, dst = path.split(' => ', 1)
                indicators['files_renamed'].append({'from': src.strip(), 'to': dst.strip()})
            else:
                indicators['files_renamed'].append({'from': path, 'to': None})

    for line in reg_output:
        match = _TAGGED_LINE_RE.match(line)
        if not match:
            continue
        rest = match.group('rest')
        key = rest.split('  =  ')[0].strip()
        data = rest.split('  =  ', 1)[1].strip() if '  =  ' in rest else None
        indicators['registry'].append({'operation': match.group('tag'), 'key': key, 'data': data})

    return indicators


def detect_attack_techniques(indicators):
    """
    Apply heuristic MITRE ATT&CK rules to structured indicators.

    Arguments:
        indicators: dict produced by analyze_indicators()
    Returns:
        list of {'id', 'technique', 'evidence'} dicts, sorted by technique id
    """
    techniques = {}

    def add(tid, name, evidence):
        entry = techniques.setdefault(tid, {'id': tid, 'technique': name, 'evidence': []})
        if evidence and evidence not in entry['evidence'] and len(entry['evidence']) < 5:
            entry['evidence'].append(evidence)

    for item in indicators['registry']:
        for pattern, tid, name in _REGISTRY_ATTACK_RULES:
            if pattern.search(item['key']):
                add(tid, name, item['key'])

    for item in indicators['files_created']:
        for pattern, tid, name in _FILE_ATTACK_RULES:
            if pattern.search(item['path']):
                add(tid, name, item['path'])

    for item in indicators['processes']:
        for pattern, tid, name in _CMDLINE_ATTACK_RULES:
            if pattern.search(item['command_line']):
                add(tid, name, item['command_line'])

    if indicators['files_deleted']:
        add('T1070.004', 'Indicator Removal: File Deletion', indicators['files_deleted'][0])
    if indicators['network_hosts']:
        add('T1071', 'Application Layer Protocol', indicators['network_hosts'][0])

    return sorted(techniques.values(), key=lambda t: t['id'])


def format_analysis_section(indicators, techniques):
    """
    Render a concise, human-readable "Behavioral Summary & IOCs" section for
    the top of the text report.

    Arguments:
        indicators: dict from analyze_indicators()
        techniques: list from detect_attack_techniques()
    Returns:
        list of report line strings
    """
    lines = ['Behavioral Summary & Indicators of Compromise:',
             '==================',
             '[*] Processes created: {}   Files created: {}   Files deleted: {}   '
             'Registry writes: {}   Network hosts: {}'.format(
                 len(indicators['processes']), len(indicators['files_created']),
                 len(indicators['files_deleted']), len(indicators['registry']),
                 len(indicators['network_hosts'])),
             '']

    if techniques:
        lines.append('MITRE ATT&CK techniques observed (heuristic):')
        for technique in techniques:
            lines.append('  [{}] {}'.format(technique['id'], technique['technique']))
            for evidence in technique['evidence']:
                lines.append('      - {}'.format(evidence[:160]))
    else:
        lines.append('No notable ATT&CK techniques detected by built-in heuristics.')
    lines.append('')

    if indicators['dropped_file_hashes']:
        lines.append('Dropped file hashes:')
        for dropped in indicators['dropped_file_hashes']:
            lines.append('  {}  {}'.format(dropped['hash'], dropped['path']))
        lines.append('')

    if indicators['network_hosts']:
        lines.append('Network endpoints:')
        for host in indicators['network_hosts']:
            lines.append('  {}'.format(host))
        lines.append('')

    if indicators.get('mutexes'):
        lines.append('Mutexes (potential infection markers):')
        for mutex in indicators['mutexes']:
            lines.append('  {}'.format(mutex))
        lines.append('')

    if indicators.get('named_pipes'):
        lines.append('Named pipes:')
        for pipe in indicators['named_pipes']:
            lines.append('  {}'.format(pipe))
        lines.append('')

    return lines


def build_json_report(indicators, techniques, metadata):
    """
    Assemble a machine-readable report suitable for ingestion by other tooling.

    Arguments:
        indicators: dict from analyze_indicators()
        techniques: list from detect_attack_techniques()
        metadata: dict of run metadata (version, timestamp, command line, etc.)
    Returns:
        dict ready to be serialized to JSON
    """
    return {
        'noriben': metadata,
        'summary': {
            'processes': len(indicators['processes']),
            'files_created': len(indicators['files_created']),
            'files_deleted': len(indicators['files_deleted']),
            'files_renamed': len(indicators['files_renamed']),
            'registry_writes': len(indicators['registry']),
            'network_hosts': len(indicators['network_hosts']),
            'named_pipes': len(indicators.get('named_pipes', [])),
            'mutexes': len(indicators.get('mutexes', [])),
            'attack_techniques': len(techniques)
        },
        'attack_techniques': techniques,
        'processes': indicators['processes'],
        'files': {
            'created': indicators['files_created'],
            'deleted': indicators['files_deleted'],
            'renamed': indicators['files_renamed']
        },
        'registry': indicators['registry'],
        'network': {
            'hosts': indicators['network_hosts'],
            'connections': indicators['network_connections']
        },
        'named_pipes': indicators.get('named_pipes', []),
        'mutexes': indicators.get('mutexes', []),
        'iocs': {
            'file_hashes': indicators['dropped_file_hashes'],
            'hosts': indicators['network_hosts'],
            'mutexes': indicators.get('mutexes', []),
            'named_pipes': indicators.get('named_pipes', [])
        }
    }


def build_yara_rule(indicators, rule_name='Noriben_Suspected_Sample', hash_type='SHA256'):
    """
    Generate a *suggested* YARA rule from the run's behavioral indicators
    (dropped file names, mutexes, named pipes, network hosts). These are
    behavioral strings that often appear inside the sample; the rule is a
    starting point for an analyst, not a vetted detection.

    Arguments:
        indicators: dict from analyze_indicators()
        rule_name: identifier for the generated rule
        hash_type: configured hash algorithm name (for the meta block)
    Returns:
        string of YARA rule text, or '' if there is nothing worth matching
    """
    strings = []
    seen = set()
    counters = {'file': 0, 'mutex': 0, 'pipe': 0, 'net': 0, 'reg': 0}

    def add_string(kind, value):
        value = (value or '').strip()
        if not value or value in seen or len(value) < 4:
            return
        seen.add(value)
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        ident = '${}{}'.format(kind, counters[kind])
        counters[kind] += 1
        strings.append('        {} = "{}" ascii wide nocase'.format(ident, escaped))

    for entry in indicators.get('files_created', []):
        basename = entry['path'].rstrip('\\').split('\\')[-1].split('/')[-1]
        if basename and '.' in basename:
            add_string('file', basename)
    for mutex in indicators.get('mutexes', []):
        add_string('mutex', mutex)
    for pipe in indicators.get('named_pipes', []):
        add_string('pipe', pipe)
    for host in indicators.get('network_hosts', []):
        add_string('net', host)
    # Autostart value names (e.g. the leaf of a Run key) often appear verbatim
    # in the binary, so they make useful YARA strings.
    for item in indicators.get('registry', []):
        key = item.get('key', '')
        if any(pattern.search(key) for pattern, _tid, _name in _REGISTRY_ATTACK_RULES):
            leaf = key.rstrip('\\').split('\\')[-1]
            add_string('reg', leaf)

    if not strings:
        return ''

    meta = ['        author = "Noriben v{}"'.format(__VERSION__),
            '        description = "Auto-suggested from dynamic analysis - review before use"',
            '        date = "{}"'.format(datetime.datetime.now().strftime('%Y-%m-%d'))]
    for dropped in indicators.get('dropped_file_hashes', [])[:5]:
        meta.append('        {} = "{}"'.format(dropped.get('hash_type', hash_type).lower(), dropped['hash']))

    return ('rule {}\n{{\n'.format(re.sub(r'[^A-Za-z0-9_]', '_', rule_name)) +
            '    meta:\n' + '\n'.join(meta) + '\n' +
            '    strings:\n' + '\n'.join(strings) + '\n' +
            '    condition:\n        any of them\n}\n')


def diff_reports(old_report, new_report):
    """
    Compare two JSON IOC reports (as produced by build_json_report) and return
    what is new and what disappeared between the runs.

    Arguments:
        old_report: previously saved report dict (baseline)
        new_report: current report dict
    Returns:
        dict mapping each category to {'added': [...], 'removed': [...]}
    """
    def sets(report):
        return {
            'processes': {p['command_line'] for p in report.get('processes', []) if p.get('command_line')},
            'files_created': {f['path'] for f in report.get('files', {}).get('created', [])},
            'file_hashes': {h['hash'] for h in report.get('iocs', {}).get('file_hashes', [])},
            'registry': {x['key'] for x in report.get('registry', [])},
            'network_hosts': set(report.get('network', {}).get('hosts', [])),
            'mutexes': set(report.get('mutexes', [])),
            'named_pipes': set(report.get('named_pipes', [])),
            'attack_techniques': {t['id'] for t in report.get('attack_techniques', [])}
        }

    old_sets, new_sets = sets(old_report), sets(new_report)
    diff = {}
    for category in old_sets:
        diff[category] = {
            'added': sorted(new_sets[category] - old_sets[category]),
            'removed': sorted(old_sets[category] - new_sets[category])
        }
    return diff


def format_diff_section(diff, baseline_name):
    """
    Render a run-to-run diff as report lines.

    Arguments:
        diff: dict from diff_reports()
        baseline_name: name/path of the baseline report, for the header
    Returns:
        list of report line strings
    """
    lines = ['Run-to-Run Diff (baseline: {}):'.format(baseline_name),
             '==================']
    labels = [('attack_techniques', 'ATT&CK techniques'), ('processes', 'Processes'),
              ('files_created', 'Files created'), ('file_hashes', 'File hashes'),
              ('registry', 'Registry keys'), ('network_hosts', 'Network hosts'),
              ('mutexes', 'Mutexes'), ('named_pipes', 'Named pipes')]
    any_change = False
    for key, label in labels:
        added = diff.get(key, {}).get('added', [])
        removed = diff.get(key, {}).get('removed', [])
        if not added and not removed:
            continue
        any_change = True
        lines.append('{}:'.format(label))
        for item in added:
            lines.append('  [+] {}'.format(item[:160]))
        for item in removed:
            lines.append('  [-] {}'.format(item[:160]))
    if not any_change:
        lines.append('No differences from baseline.')
    lines.append('')
    return lines


def build_stix_bundle(indicators, metadata):
    """
    Assemble a minimal STIX 2.1 bundle of Indicator objects for the run's IOCs
    (file hashes, network hosts, mutexes). No external library required.

    Arguments:
        indicators: dict from analyze_indicators()
        metadata: dict of run metadata (used for timestamps)
    Returns:
        dict representing a STIX 2.1 bundle
    """
    now = metadata.get('generated') or datetime.datetime.now().isoformat(timespec='seconds')
    timestamp = now if now.endswith('Z') else now + 'Z'
    stix_hash_names = {'MD5': 'MD5', 'SHA1': 'SHA-1', 'SHA256': 'SHA-256'}
    objects = []

    def indicator(name, pattern):
        return {
            'type': 'indicator',
            'spec_version': '2.1',
            'id': 'indicator--{}'.format(uuid.uuid4()),
            'created': timestamp,
            'modified': timestamp,
            'name': name,
            'pattern': pattern,
            'pattern_type': 'stix',
            'valid_from': timestamp
        }

    for dropped in indicators.get('dropped_file_hashes', []):
        hash_name = stix_hash_names.get(dropped.get('hash_type', 'SHA256'), 'SHA-256')
        objects.append(indicator('Dropped file {}'.format(dropped['hash']),
                                  "[file:hashes.'{}' = '{}']".format(hash_name, dropped['hash'])))
    for host in indicators.get('network_hosts', []):
        try:
            ipaddress.ip_address(host.split(':')[0])
            pattern = "[ipv4-addr:value = '{}']".format(host.split(':')[0])
        except ValueError:
            pattern = "[domain-name:value = '{}']".format(host)
        objects.append(indicator('Network host {}'.format(host), pattern))
    for mutex in indicators.get('mutexes', []):
        escaped_mutex = mutex.replace('\\', '\\\\').replace("'", "\\'")
        objects.append(indicator('Mutex {}'.format(mutex),
                                  "[mutex:name = '{}']".format(escaped_mutex)))

    return {
        'type': 'bundle',
        'id': 'bundle--{}'.format(uuid.uuid4()),
        'objects': objects
    }


def build_misp_event(indicators, metadata):
    """
    Assemble a MISP event (JSON) describing the run's IOCs, ready for import
    via the MISP "Import from... MISP JSON" feature.

    Arguments:
        indicators: dict from analyze_indicators()
        metadata: dict of run metadata
    Returns:
        dict representing a MISP event
    """
    misp_hash_types = {'MD5': 'md5', 'SHA1': 'sha1', 'SHA256': 'sha256'}
    attributes = []

    def attribute(attr_type, category, value):
        attributes.append({'type': attr_type, 'category': category,
                           'value': value, 'to_ids': True})

    for dropped in indicators.get('dropped_file_hashes', []):
        attribute(misp_hash_types.get(dropped.get('hash_type', 'SHA256'), 'sha256'),
                  'Payload delivery', dropped['hash'])
    for entry in indicators.get('files_created', []):
        basename = entry['path'].rstrip('\\').split('\\')[-1].split('/')[-1]
        if basename:
            attribute('filename', 'Payload delivery', basename)
    for host in indicators.get('network_hosts', []):
        bare = host.split(':')[0]
        try:
            ipaddress.ip_address(bare)
            attribute('ip-dst', 'Network activity', bare)
        except ValueError:
            attribute('domain', 'Network activity', host)
    for item in indicators.get('registry', []):
        attribute('regkey', 'Persistence mechanism', item['key'])
    for mutex in indicators.get('mutexes', []):
        attribute('mutex', 'Artifacts dropped', mutex)
    for pipe in indicators.get('named_pipes', []):
        attribute('named pipe', 'Artifacts dropped', pipe)

    generated = metadata.get('generated', datetime.datetime.now().isoformat(timespec='seconds'))
    return {
        'Event': {
            'info': 'Noriben dynamic analysis {}'.format(metadata.get('command_line') or '').strip(),
            'date': generated.split('T')[0],
            'analysis': '2',
            'threat_level_id': '2',
            'Attribute': attributes
        }
    }


def _sigma_attack_tags(technique_ids):
    """Convert MITRE technique ids (e.g. 'T1547.001') into Sigma attack tags."""
    return ['attack.{}'.format(tid.lower()) for tid in technique_ids]


def build_sigma_rules(indicators, techniques, metadata):
    """
    Generate Sigma detection rules from the run's indicators. Produces targeted
    rules for dropped executables, registry persistence, network endpoints,
    named pipes, and suspicious process command lines.

    Arguments:
        indicators: dict from analyze_indicators()
        techniques: list from detect_attack_techniques()
        metadata: dict of run metadata
    Returns:
        list of Sigma rule dicts (each a complete rule)
    """
    date = (metadata.get('generated') or datetime.datetime.now().isoformat()).split('T')[0].replace('-', '/')
    author = 'Noriben v{}'.format(__VERSION__)
    technique_ids = [t['id'] for t in techniques]
    rules = []

    def new_rule(title, description, category, selection, tags, level='medium'):
        return {
            'title': title,
            'id': str(uuid.uuid4()),
            'status': 'experimental',
            'description': description,
            'author': author,
            'date': date,
            'logsource': {'category': category, 'product': 'windows'},
            'detection': {'selection': selection, 'condition': 'selection'},
            'falsepositives': ['Unknown'],
            'level': level,
            'tags': tags
        }

    dropped_exes = sorted({entry['path'].rstrip('\\').split('\\')[-1].split('/')[-1]
                           for entry in indicators.get('files_created', [])
                           if entry['path'].lower().endswith(('.exe', '.dll', '.scr', '.sys'))})
    if dropped_exes:
        rules.append(new_rule(
            'Noriben - Dropped Executable Created',
            'Creation of an executable observed during dynamic analysis.',
            'file_event',
            {'TargetFilename|endswith': ['\\' + name for name in dropped_exes]},
            ['attack.execution']))

    persistence_keys = sorted({item['key'] for item in indicators.get('registry', [])
                               if any(p.search(item['key']) for p, _i, _n in _REGISTRY_ATTACK_RULES)})
    if persistence_keys:
        rules.append(new_rule(
            'Noriben - Registry Persistence Modification',
            'Modification of an autostart/persistence registry location.',
            'registry_set',
            {'TargetObject|contains': persistence_keys},
            ['attack.persistence'] + _sigma_attack_tags(
                [tid for tid in technique_ids if tid.startswith(('T1547', 'T1543', 'T1546'))]),
            level='high'))

    domains = [h for h in indicators.get('network_hosts', []) if not _is_ip(h.split(':')[0])]
    ips = [h.split(':')[0] for h in indicators.get('network_hosts', []) if _is_ip(h.split(':')[0])]
    net_selection = {}
    if domains:
        net_selection['DestinationHostname'] = domains
    if ips:
        net_selection['DestinationIp'] = ips
    if net_selection:
        rules.append(new_rule(
            'Noriben - Network Connection to Observed Host',
            'Network connection to an endpoint contacted during dynamic analysis.',
            'network_connection',
            net_selection,
            ['attack.command_and_control', 'attack.t1071']))

    if indicators.get('named_pipes'):
        rules.append(new_rule(
            'Noriben - Named Pipe Created',
            'Creation of a named pipe observed during dynamic analysis.',
            'pipe_created',
            {'PipeName|contains': sorted(indicators['named_pipes'])},
            ['attack.defense_evasion']))

    cmd_tokens = sorted({item['command_line'] for item in indicators.get('processes', [])
                         if any(p.search(item['command_line']) for p, _i, _n in _CMDLINE_ATTACK_RULES)})
    if cmd_tokens:
        rules.append(new_rule(
            'Noriben - Suspicious Process Command Line',
            'Process command line matching a suspicious pattern seen during analysis.',
            'process_creation',
            {'CommandLine|contains': cmd_tokens},
            ['attack.execution'] + _sigma_attack_tags(
                [tid for tid in technique_ids if tid.startswith(('T1059', 'T1218', 'T1053', 'T1490', 'T1562'))])))

    return rules


def _is_ip(value):
    """True if value parses as an IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _yaml_scalar(value):
    """Render a scalar as a safely single-quoted YAML string (or bare int)."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return str(value)
    return "'{}'".format(str(value).replace("'", "''"))


def _yaml_dump(value, indent=0):
    """
    Minimal YAML emitter for the controlled Sigma rule structure (nested maps,
    lists of scalars, and scalar values). Avoids a hard PyYAML dependency.
    """
    pad = '    ' * indent
    lines = []
    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(val, (dict, list)) and val:
                lines.append('{}{}:'.format(pad, key))
                lines.extend(_yaml_dump(val, indent + 1))
            elif isinstance(val, (dict, list)):
                lines.append('{}{}: []'.format(pad, key) if isinstance(val, list)
                             else '{}{}: {{}}'.format(pad, key))
            else:
                lines.append('{}{}: {}'.format(pad, key, _yaml_scalar(val)))
    elif isinstance(value, list):
        for item in value:
            lines.append('{}- {}'.format(pad, _yaml_scalar(item)))
    return lines


def sigma_rules_to_yaml(rules):
    """Serialize a list of Sigma rule dicts to a multi-document YAML string."""
    documents = ['\n'.join(_yaml_dump(rule)) for rule in rules]
    return '\n---\n'.join(documents) + ('\n' if documents else '')


def build_diff_html(diff, baseline_name, metadata):
    """
    Render a run-to-run diff as a small self-contained HTML page.

    Arguments:
        diff: dict from diff_reports()
        baseline_name: name of the baseline report
        metadata: dict of run metadata
    Returns:
        HTML string
    """
    def esc(text):
        return (str(text).replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;').replace('"', '&quot;'))

    labels = [('attack_techniques', 'ATT&CK techniques'), ('processes', 'Processes'),
              ('files_created', 'Files created'), ('file_hashes', 'File hashes'),
              ('registry', 'Registry keys'), ('network_hosts', 'Network hosts'),
              ('mutexes', 'Mutexes'), ('named_pipes', 'Named pipes')]

    body = []
    for key, label in labels:
        added = diff.get(key, {}).get('added', [])
        removed = diff.get(key, {}).get('removed', [])
        if not added and not removed:
            continue
        body.append('<h2>{}</h2><ul>'.format(esc(label)))
        for item in added:
            body.append('<li class="add">+ {}</li>'.format(esc(item)))
        for item in removed:
            body.append('<li class="del">- {}</li>'.format(esc(item)))
        body.append('</ul>')
    if not body:
        body.append('<p>No differences from baseline.</p>')

    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">\n'
        '<title>Noriben Diff vs {baseline}</title>\n'
        '<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:2em;color:#222}}'
        'h1{{font-size:1.4em}}h2{{font-size:1.1em;border-bottom:1px solid #ccc;padding-bottom:2px}}'
        'ul{{list-style:none;padding-left:0}}li{{font-family:Consolas,monospace;padding:1px 0}}'
        '.add{{color:#0a7d00}}.del{{color:#b00020}}.meta{{color:#666;font-size:.9em}}</style>'
        '</head><body>\n'
        '<h1>Noriben run-to-run diff</h1>\n'
        '<p class="meta">Baseline: {baseline} &middot; Noriben v{version} &middot; {generated}</p>\n'
        '{body}\n</body></html>\n'
    ).format(baseline=esc(baseline_name), version=esc(metadata.get('version', '')),
             generated=esc(metadata.get('generated', '')), body='\n'.join(body))


# Categories aggregated when consolidating multiple runs, mapped to an
# extractor that pulls the comparable values out of a JSON IOC report.
_CONSOLIDATE_CATEGORIES = [
    ('attack_techniques', 'ATT&CK techniques',
     lambda r: ['{} {}'.format(t.get('id', ''), t.get('technique', '')).strip()
                for t in r.get('attack_techniques', [])]),
    ('processes', 'Process command lines',
     lambda r: [p['command_line'] for p in r.get('processes', []) if p.get('command_line')]),
    ('files_created', 'Files created',
     lambda r: [f['path'] for f in r.get('files', {}).get('created', [])]),
    ('file_hashes', 'File hashes',
     lambda r: [h['hash'] for h in r.get('iocs', {}).get('file_hashes', [])]),
    ('registry', 'Registry keys',
     lambda r: [x['key'] for x in r.get('registry', [])]),
    ('network_hosts', 'Network hosts',
     lambda r: r.get('network', {}).get('hosts', [])),
    ('mutexes', 'Mutexes', lambda r: r.get('mutexes', [])),
    ('named_pipes', 'Named pipes', lambda r: r.get('named_pipes', []))
]


def consolidate_reports(named_reports):
    """
    Aggregate IOCs across multiple runs to spot what is shared (e.g. a malware
    family fingerprint) versus what is unique to one sample.

    Arguments:
        named_reports: list of (name, report_dict) tuples, where report_dict is
            a JSON IOC report produced by build_json_report()
    Returns:
        dict with run names and, per category, a list of
        {'value', 'count', 'runs'} entries sorted by frequency
    """
    run_names = [name for name, _report in named_reports]
    categories = {}
    for key, _label, extractor in _CONSOLIDATE_CATEGORIES:
        counter = {}
        for name, report in named_reports:
            for value in set(extractor(report)):
                counter.setdefault(value, set()).add(name)
        items = [{'value': value, 'count': len(runs), 'runs': sorted(runs)}
                 for value, runs in counter.items()]
        items.sort(key=lambda entry: (-entry['count'], entry['value']))
        categories[key] = items
    return {'runs': run_names, 'run_count': len(run_names), 'categories': categories}


def format_consolidated_section(consolidated):
    """
    Render a consolidated multi-run summary as report lines, highlighting IOCs
    shared across every run.

    Arguments:
        consolidated: dict from consolidate_reports()
    Returns:
        list of report line strings
    """
    run_count = consolidated['run_count']
    lines = ['Consolidated Multi-Run Report ({} runs):'.format(run_count),
             '==================']
    for name in consolidated['runs']:
        lines.append('  - {}'.format(name))
    lines.append('')

    for key, label, _extractor in _CONSOLIDATE_CATEGORIES:
        items = consolidated['categories'].get(key, [])
        if not items:
            continue
        lines.append('{} ({} unique):'.format(label, len(items)))
        for entry in items:
            marker = ' [SHARED]' if entry['count'] == run_count and run_count > 1 else ''
            lines.append('  ({}/{}){} {}'.format(entry['count'], run_count, marker, entry['value'][:150]))
        lines.append('')
    return lines


def build_consolidated_html(consolidated, metadata):
    """Render the consolidated multi-run report as a self-contained HTML page."""
    def esc(text):
        return (str(text).replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;').replace('"', '&quot;'))

    run_count = consolidated['run_count']
    body = ['<h1>Noriben consolidated multi-run report</h1>',
            '<p class="meta">{} runs &middot; Noriben v{} &middot; {}</p>'.format(
                run_count, esc(metadata.get('version', '')), esc(metadata.get('generated', ''))),
            '<p class="meta">Runs: {}</p>'.format(esc(', '.join(consolidated['runs'])))]
    for key, label, _extractor in _CONSOLIDATE_CATEGORIES:
        items = consolidated['categories'].get(key, [])
        if not items:
            continue
        body.append('<h2>{} <span class="meta">({} unique)</span></h2>'.format(esc(label), len(items)))
        body.append('<table><tr><th>Seen</th><th>Indicator</th></tr>')
        for entry in items:
            shared = ' class="shared"' if entry['count'] == run_count and run_count > 1 else ''
            body.append('<tr{}><td>{}/{}</td><td>{}</td></tr>'.format(
                shared, entry['count'], run_count, esc(entry['value'])))
        body.append('</table>')

    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">\n'
        '<title>Noriben consolidated report</title>\n'
        '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2em;color:#222}'
        'h1{font-size:1.4em}h2{font-size:1.1em;border-bottom:1px solid #ccc}'
        'table{border-collapse:collapse;margin-bottom:1em}td,th{border:1px solid #ddd;'
        'padding:2px 8px;font-family:Consolas,monospace;font-size:.9em;text-align:left}'
        'tr.shared{background:#fff3cd}.meta{color:#666;font-size:.9em}</style>'
        '</head><body>\n' + '\n'.join(body) + '\n</body></html>\n')


def run_consolidation(paths, config):
    """
    Expand the given paths (files, globs, or directories), load the JSON IOC
    reports they reference, consolidate them, and write text/JSON/HTML
    summaries. Used by the --merge mode.

    Arguments:
        paths: list of file paths, globs, or directories
        config: active configuration dictionary
    Returns:
        none
    """
    json_files = []
    for path in paths:
        if os.path.isdir(path):
            json_files.extend(sorted(glob.glob(os.path.join(path, '*.iocs.json'))))
        elif any(ch in path for ch in '*?['):
            json_files.extend(sorted(glob.glob(path)))
        else:
            json_files.append(path)
    seen = set()
    json_files = [f for f in json_files if not (f in seen or seen.add(f))]

    named_reports = []
    for json_file in json_files:
        try:
            with open(json_file, encoding='utf-8') as handle:
                report = json.load(handle)
        except (OSError, ValueError) as err:
            print('[!] Skipping {}: {}'.format(json_file, err))
            continue
        name = report.get('noriben', {}).get('source_csv') or os.path.basename(json_file)
        named_reports.append((name, report))

    if not named_reports:
        print('[!] No valid *.iocs.json reports found to consolidate.')
        return

    print('[*] Consolidating {} run(s)...'.format(len(named_reports)))
    consolidated = consolidate_reports(named_reports)
    metadata = {'version': __VERSION__,
                'generated': datetime.datetime.now().isoformat(timespec='seconds')}

    out_dir = config.get('output_folder') or '.'
    base = os.path.join(out_dir, 'Noriben_consolidated')
    text_lines = format_consolidated_section(consolidated)
    try:
        with open(base + '.txt', 'w', encoding='utf-8') as handle:
            handle.write('\r\n'.join(text_lines))
        print('[*] Saving consolidated report to: {}.txt'.format(base))
        with open(base + '.json', 'w', encoding='utf-8') as handle:
            json.dump(dict({'noriben': metadata}, **consolidated), handle, indent=2)
        print('[*] Saving consolidated JSON to: {}.json'.format(base))
        with open(base + '.html', 'w', encoding='utf-8') as handle:
            handle.write(build_consolidated_html(consolidated, metadata))
        print('[*] Saving consolidated HTML to: {}.html'.format(base))
    except OSError as err:
        print('[!] Error writing consolidated output: {}'.format(err))

    print('\n' + '\n'.join(text_lines))


def parse_csv(csv_file, report, timeline):
    """
    Given the location of CSV and TXT files, parse the CSV for notable items

    Arguments:
        csv_file: path to csv output to parse
        report: OUT string text containing the entirety of the text report
        timeline: OUT string text containing the entirety of the CSV report
    """
    log_debug('[*] Processing CSV: {}'.format(csv_file))

    process_output = []
    file_output = []
    reg_output = []
    net_output = []
    error_output = []
    remote_servers = []
    if config['yara_folder'] and has_yara:
        yara_rules = yara_import_rules(config['yara_folder'])
    else:
        yara_rules = ''

    time_parse_csv_start = time.time()

    csv_file_handle = open(csv_file, newline='', encoding='utf-8-sig')
    reader = csv.DictReader(csv_file_handle)

    for original_line in reader:
        server = ''
        field = original_line
        # log_debug('[*] Parse line. Event: {}'.format(field['Operation'])

        date_stamp = field['Time of Day'].split()[0].split('.')[0]

        try:
            if field['Operation'] == 'Process Create' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(cmd_approvelist, field):
                    cmdline = field['Detail'].split('Command line: ')[1]
                    log_debug('[*] CreateProcess: {}'.format(cmdline))

                    if config['generalize_paths']:
                        cmdline = generalize_var(cmdline)
                    child_pid = field['Detail'].split('PID: ')[1].split(',')[0]
                    outputtext = '[CreateProcess] {}:{} > "{}"\t[Child PID: {}]'.format(
                        field['Process Name'], field['PID'], cmdline.replace('"', ''), child_pid)
                    tl_text = '{},Process,CreateProcess,{},{},{},{}'.format(date_stamp, field['Process Name'], field['PID'], cmdline.replace('"', ''), child_pid)
                    process_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'CreateFile' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(file_approvelist, field):
                    path = field['Path']
                    log_debug('[*] CreateFile: {}'.format(path))
                    yara_hits = ''
                    if config['yara_folder'] and yara_rules:
                        yara_hits = yara_filescan(path, yara_rules)
                    if os.path.isdir(path):
                        if config['generalize_paths']:
                            path = generalize_var(path)
                        outputtext = '[CreateFolder] {}:{} > {}'.format(field['Process Name'], field['PID'], path)
                        tl_text = '{},File,CreateFolder,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                         field['PID'], path)
                        file_output.append(outputtext)
                        timeline.append(tl_text)
                    else:
                        av_hits = ''
                        try:
                            if config['disable-file-hash']:
                                hashval = ''
                            else:
                                hashval = hash_file(path)
                                if hashval in hash_approvelist:
                                    log_debug('[_] Skipping hash: {}'.format(hashval))
                                    continue

                                if use_virustotal and has_internet:
                                    av_hits = virustotal_query_hash(hashval, path)

                            if config['generalize_paths']:
                                path = generalize_var(path)

                            if hashval:
                                hashval_output = '[{}: {}]'.format(config['hash_type'], hashval)
                            else:
                                hashval_output = ''

                            outputtext = '[CreateFile] {}:{} > {}\t{}{}{}'.format(field['Process Name'], field['PID'], path,
                                                                                        hashval_output, yara_hits, av_hits)
                            tl_text = '{},File,CreateFile,{},{},{},{},{},{}'.format(date_stamp,
                                                                                       field['Process Name'], field['PID'], path,
                                                                                       hashval_output, yara_hits, av_hits)
                            file_output.append(outputtext)
                            timeline.append(tl_text)
                        except (IndexError, IOError):
                            if config['generalize_paths']:
                                path = generalize_var(path)
                            outputtext = '[CreateFile] {}:{} > {}\t[File no longer exists]'.format(field['Process Name'], field['PID'],
                                                                                                   path)
                            tl_text = '{},File,CreateFile,{},{},{},N/A'.format(date_stamp,
                                                                               field['Process Name'], field['PID'], path)
                            file_output.append(outputtext)
                            timeline.append(tl_text)

            elif field['Operation'] == 'SetDispositionInformationFile' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(file_approvelist, field):
                    path = field['Path']
                    log_debug('[*] DeleteFile: {}'.format(path))
                    if config['generalize_paths']:
                        path = generalize_var(path)
                    outputtext = '[DeleteFile] {}:{} > {}'.format(field['Process Name'], field['PID'], path)
                    tl_text = '{},File,DeleteFile,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                   field['PID'], path)
                    file_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'SetRenameInformationFile':
                if not approvelist_scan(file_approvelist, field):
                    from_file = field['Path']
                    to_file = field['Detail'].split('FileName: ')[1].strip('"')
                    if config['generalize_paths']:
                        from_file = generalize_var(from_file)
                        to_file = generalize_var(to_file)
                    outputtext = '[RenameFile] {}:{} > {} => {}'.format(field['Process Name'], field['PID'], from_file, to_file)
                    tl_text = '{},File,RenameFile,{},{},{},{}'.format(date_stamp, field['Process Name'],
                                                                      field['PID'], from_file, to_file)
                    file_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'RegCreateKey' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(reg_approvelist, field):
                    path = field['Path']
                    log_debug('[*] RegCreateKey: {}'.format(path))

                    outputtext = '[RegCreateKey] {}:{} > {}'.format(field['Process Name'], field['PID'], field['Path'])
                    if outputtext not in reg_output:  # Ignore multiple CreateKeys. Only log the first.
                        tl_text = '{},Registry,RegCreateKey,{},{},{}'.format(date_stamp,
                                                                             field['Process Name'], field['PID'], field['Path'])
                        reg_output.append(outputtext)
                        timeline.append(tl_text)

            elif field['Operation'] == 'RegSetValue' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(reg_approvelist, field):
                    reg_length = field['Detail'].split('Length:')[1].split(',')[0].strip(string.whitespace + '"')
                    reg_length = reg_length.replace('’', '')  # Addresses errant ticks found in some data samples
                    try:
                        if int(float(reg_length)):
                            if 'Data:' in field['Detail']:
                                data_field = '  =  {}'.format(field['Detail'].split('Data:')[1].strip(string.whitespace + '"'))
                                if len(data_field.split(' ')) == 16:
                                    data_field += ' ...'
                            elif 'Length:' in field['Detail']:
                                data_field = ''
                            else:
                                continue
                            outputtext = '[RegSetValue] {}:{} > {}{}'.format(field['Process Name'], field['PID'], field['Path'], data_field)
                            tl_text = '{},Registry,RegSetValue,{},{},{},{}'.format(date_stamp,
                                                                                   field['Process Name'], field['PID'], field['Path'],
                                                                                   data_field)
                            reg_output.append(outputtext)
                            timeline.append(tl_text)

                    except (IndexError, ValueError):
                        error_output.append(''.join(original_line))

            elif field['Operation'] == 'RegDeleteValue':  # and field['Result'] == 'SUCCESS':
                # SUCCESS is commented out to allow all attempted deletions, whether or not the value exists
                if not approvelist_scan(reg_approvelist, field):
                    outputtext = '[RegDeleteValue] {}:{} > {}'.format(field['Process Name'], field['PID'], field['Path'])
                    tl_text = '{},Registry,RegDeleteValue,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                            field['PID'], field['Path'])
                    reg_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'RegDeleteKey':  # and field['Result'] == 'SUCCESS':
                # SUCCESS is commented out to allow all attempted deletions, whether or not the value exists
                if not approvelist_scan(reg_approvelist, field):
                    outputtext = '[RegDeleteKey] {}:{} > {}'.format(field['Process Name'], field['PID'], field['Path'])
                    tl_text = '{},Registry,RegDeleteKey,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                         field['PID'], field['Path'])
                    reg_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'UDP Send' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(net_approvelist, field):
                    server = field['Path'].split('-> ')[1]
                    # TODO: work on this later, once I can verify it better.
                    # if field['Detail'] == 'Length: 20':
                    #    output_line = '[DNS Query] {}:{} > {}'.format(field['Process Name'], field['PID'], protocol_replace(server))
                    # else:
                    outputtext = '[UDP] {}:{} > {}'.format(field['Process Name'], field['PID'], protocol_replace(server))
                    if outputtext not in net_output:
                        tl_text = '{},Network,UDP Send,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                        field['PID'], protocol_replace(server))
                        net_output.append(outputtext)
                        timeline.append(tl_text)

            elif field['Operation'] == 'UDP Receive' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(net_approvelist, field):
                    server = field['Path'].split('-> ')[1]
                    outputtext = '[UDP] {} > {}:{}'.format(protocol_replace(server), field['Process Name'], field['PID'])
                    if outputtext not in net_output:
                        tl_text = '{},Network,UDP Receive,{},{}'.format(date_stamp, field['Process Name'],
                                                                        field['PID'])
                        net_output.append(outputtext)
                        timeline.append(tl_text)

            elif field['Operation'] == 'TCP Send' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(net_approvelist, field):
                    server = field['Path'].split('-> ')[1]
                    outputtext = '[TCP] {}:{} > {}'.format(field['Process Name'], field['PID'], protocol_replace(server))
                    if outputtext not in net_output:
                        tl_text = '{},Network,TCP Send,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                        field['PID'], protocol_replace(server))
                        net_output.append(outputtext)
                        timeline.append(tl_text)

            elif field['Operation'] == 'TCP Receive' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(net_approvelist, field):
                    server = field['Path'].split('-> ')[1]
                    outputtext = '[TCP] {} > {}:{}'.format(protocol_replace(server), field['Process Name'], field['PID'])
                    if outputtext not in net_output:
                        tl_text = '{},Network,TCP Receive,{},{}'.format(date_stamp, field['Process Name'],
                                                                        field['PID'])
                        net_output.append(outputtext)
                        timeline.append(tl_text)

        except IndexError:
            log_debug(original_line)
            log_debug(traceback.format_exc())
            error_output.append(original_line)

        # Enumerate unique remote hosts into their own section
        if server:
            # server.split(':')[0] is a bad method as it breaks IPv6
            server_host, server_port = network_split_host_port(server)
            if server_host not in remote_servers and not server_host == 'localhost':
                remote_servers.append(server_host)
    # } End of file input processing

    time_parse_csv_end = time.time()

    # Build structured indicators and heuristic ATT&CK tags for the summary
    # section, the optional JSON report, the diff, and the IOC exports.
    indicators = analyze_indicators(process_output, file_output, reg_output,
                                    net_output, remote_servers, config['hash_type'])
    attack_techniques = detect_attack_techniques(indicators)
    report_metadata = {
        'version': __VERSION__,
        'generated': datetime.datetime.now().isoformat(timespec='seconds'),
        'command_line': exe_cmdline,
        'hash_type': config['hash_type'],
        'source_csv': os.path.basename(csv_file)
    }
    json_report_data = build_json_report(indicators, attack_techniques, report_metadata)

    report.append('-=] Sandbox Analysis Report generated by Noriben v{}'.format(__VERSION__))
    report.append('-=] https://github.com/Rurik/Noriben')
    report.append('')
    if exe_cmdline:
        report.append('-=] Analysis of command line: {}'.format(exe_cmdline))

    if time_exec:
        report.append('-=] Execution time: {:.2f} seconds'.format(time_exec))
    if time_process:
        report.append('-=] Processing time: {:.2f} seconds'.format(time_process))

    time_analyze = time_parse_csv_end - time_parse_csv_start
    report.append('-=] Analysis time: {:.2f} seconds'.format(time_analyze))
    report.append('')

    for summary_line in format_analysis_section(indicators, attack_techniques):
        report.append(summary_line)

    # Optional run-to-run diff against a previously saved JSON IOC report
    diff_result = None
    baseline_path = config.get('diff_against')
    if baseline_path:
        try:
            with open(baseline_path, encoding='utf-8') as baseline_handle:
                baseline_report = json.load(baseline_handle)
            diff_result = diff_reports(baseline_report, json_report_data)
            for diff_line in format_diff_section(diff_result, os.path.basename(baseline_path)):
                report.append(diff_line)
        except (OSError, ValueError) as err:
            print('[!] Could not load diff baseline {}: {}'.format(baseline_path, err))
            log_debug('[!] Diff baseline load failed: {}'.format(err))

    report.append('Processes Created:')
    report.append('==================')
    log_debug('[*] Writing {} Process Events results to report'.format(len(process_output)))
    for event in process_output:
        report.append(event)

    report.append('')
    report.append('File Activity:')
    report.append('==================')
    log_debug('[*] Writing {} Filesystem Events results to report'.format(len(file_output)))
    for event in file_output:
        report.append(event)

    report.append('')
    report.append('Registry Activity:')
    report.append('==================')
    log_debug('[*] Writing {} Registry Events results to report'.format(len(reg_output)))
    for event in reg_output:
        report.append(event)

    report.append('')
    report.append('Network Traffic:')
    report.append('==================')
    log_debug('[*] Writing {} Network Events results to report'.format(len(net_output)))
    for event in net_output:
        report.append(event)

    report.append('')
    report.append('Unique Hosts:')
    report.append('==================')
    log_debug('[*] Writing {} Remote Servers results to report'.format(len(remote_servers)))
    for server in sorted(remote_servers):
        report.append(protocol_replace(server).strip())

    if error_output:
        report.append('\r\n\r\n\r\n\r\n\r\n\r\nERRORS DETECTED')
        report.append('The following items could not be parsed correctly:')
        log_debug('[*] Writing {} Output Errors results to report'.format(len(error_output)))
        for error in error_output:
            report.append(error)

    # Structured IOC exports. Each is independent and non-fatal.
    output_base = os.path.splitext(csv_file)[0]

    def _write_export(enabled, suffix, label, builder, as_json=True):
        if not enabled:
            return
        path = output_base + suffix
        try:
            payload = builder()
            if not payload:
                return
            with open(path, 'w', encoding='utf-8') as handle:
                if as_json:
                    json.dump(payload, handle, indent=2, sort_keys=False)
                else:
                    handle.write(payload)
            print('[*] Saving {} to: {}'.format(label, path))
        except OSError as err:
            log_debug('[!] Unable to write {} ({}): {}'.format(label, path, err))

    _write_export(config.get('json_report'), '.iocs.json', 'JSON IOC report',
                  lambda: json_report_data)
    _write_export(config.get('gen_yara'), '.suggested.yar', 'suggested YARA rule',
                  lambda: build_yara_rule(indicators, hash_type=config['hash_type']), as_json=False)
    _write_export(config.get('stix_export'), '.stix.json', 'STIX 2.1 bundle',
                  lambda: build_stix_bundle(indicators, report_metadata))
    _write_export(config.get('misp_export'), '.misp.json', 'MISP event',
                  lambda: build_misp_event(indicators, report_metadata))
    _write_export(config.get('gen_sigma'), '.sigma.yml', 'Sigma rules',
                  lambda: sigma_rules_to_yaml(build_sigma_rules(indicators, attack_techniques, report_metadata)),
                  as_json=False)
    _write_export(diff_result is not None, '.diff.html', 'HTML diff report',
                  lambda: build_diff_html(diff_result, os.path.basename(baseline_path), report_metadata),
                  as_json=False)

    if config['debug'] and vt_dump:
        vt_file = os.path.join(config['output_folder'], os.path.splitext(csv_file)[0] + '.vt.json')
        log_debug('[*] Writing {} VirusTotal results to {}'.format(len(vt_dump), vt_file))
        vt_out = open(vt_file, 'w', encoding='utf-8')
        json.dump(vt_dump, vt_out)
        vt_out.close()

    if config['debug'] and debug_messages:
        debug_out = open(debug_file, 'a', encoding='utf-8')
        for message in debug_messages:
            debug_out.write(message)
        debug_out.close()


# End of parse_csv()


def generate_ai_analysis(report_lines, config):
    """
    Send the generated Noriben report to a Large Language Model to produce a
    human-readable behavioral analysis of the captured activity.

    Works with any OpenAI-compatible Chat Completions endpoint. This includes
    a local Ollama instance (which exposes an OpenAI-compatible API at
    http://localhost:11434/v1) as well as the OpenAI API itself and other
    compatible gateways (LM Studio, vLLM, LiteLLM, etc.).

    Arguments:
        report_lines: list of strings comprising the text report
        config: active configuration dictionary
    Returns:
        string of the AI-generated analysis, or '' on any failure
    """
    if requests is None:
        print('[!] AI analysis requested but the "requests" module is not installed.')
        return ''

    provider = str(config.get('ai_provider', 'ollama')).lower()
    base_url = str(config.get('ai_base_url', '')).strip()
    if not base_url:
        base_url = 'https://api.openai.com/v1' if provider == 'openai' else 'http://localhost:11434/v1'
    base_url = base_url.rstrip('/')

    model = str(config.get('ai_model', '')).strip()
    if not model:
        model = 'gpt-4o-mini' if provider == 'openai' else 'llama3.1'
    api_key = str(config.get('ai_api_key', '')).strip()

    try:
        timeout = int(config.get('ai_timeout', 120))
    except (TypeError, ValueError):
        timeout = 120
    try:
        max_chars = int(config.get('ai_max_chars', 60000))
    except (TypeError, ValueError):
        max_chars = 60000

    report_text = '\n'.join(report_lines)
    truncated = False
    if max_chars and len(report_text) > max_chars:
        report_text = report_text[:max_chars]
        truncated = True

    system_prompt = (
        'You are an expert malware analyst. You are given a behavioral report '
        'produced by Noriben, which summarizes Sysinternals Process Monitor '
        '(Procmon) activity captured while running a sample in a sandbox. '
        'Analyze the activity and produce a concise Markdown report with these '
        'sections:\n'
        '1. Executive Summary (2-3 sentences)\n'
        '2. Notable Behaviors (processes, file system, registry)\n'
        '3. Persistence Mechanisms\n'
        '4. Network Indicators (domains, IPs, URLs)\n'
        '5. Indicators of Compromise (IOCs)\n'
        '6. Risk Assessment: classify as Benign, Suspicious, or Malicious, with '
        'a confidence level and a short justification.\n\n'
        'Only use information present in the report. Do not invent indicators. '
        'If the data is insufficient to make a determination, say so explicitly.'
    )
    user_prompt = 'Noriben behavioral report:\n\n' + report_text
    if truncated:
        user_prompt += '\n\n[Note: the report was truncated for length before analysis.]'

    url = base_url + '/chat/completions'
    headers = {'Content-Type': 'application/json'}
    if api_key:
        headers['Authorization'] = 'Bearer {}'.format(api_key)

    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_prompt}
        ],
        'temperature': 0.2,
        'stream': False
    }

    print('[*] Requesting AI analysis from {} (model: {}) ...'.format(url, model))
    log_debug('[*] AI request to {} using model {}'.format(url, model))
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.exceptions.RequestException as err:
        print('[!] AI analysis failed: could not reach endpoint ({})'.format(err))
        log_debug('[!] AI request exception: {}'.format(err))
        return ''

    if response.status_code != 200:
        print('[!] AI analysis failed: HTTP {} - {}'.format(response.status_code, response.text[:200]))
        log_debug('[!] AI response error {}: {}'.format(response.status_code, response.text[:500]))
        return ''

    try:
        data = response.json()
        content = data['choices'][0]['message']['content'].strip()
    except (ValueError, KeyError, IndexError, TypeError) as err:
        print('[!] AI analysis failed: unexpected response format ({})'.format(err))
        log_debug('[!] AI parse error: {} -- body: {}'.format(err, response.text[:500]))
        return ''

    return content


def append_ai_analysis(report, config, ai_file):
    """
    If AI analysis is enabled, generate it, append it to the report list, and
    save a standalone copy to ai_file. All failures are non-fatal so that the
    primary Noriben report is always produced.

    Arguments:
        report: list of report strings (modified in place)
        config: active configuration dictionary
        ai_file: path to write the standalone AI analysis to
    Returns:
        none
    """
    if not config.get('ai_enabled'):
        return

    analysis = generate_ai_analysis(report, config)
    if not analysis:
        return

    report.append('')
    report.append('')
    report.append('AI Analysis:')
    report.append('==================')
    for line in analysis.splitlines():
        report.append(line)

    try:
        with open(ai_file, 'w', encoding='utf-8') as handle:
            handle.write(analysis)
        print('[*] Saving AI analysis to: {}'.format(ai_file))
    except OSError as err:
        log_debug('[!] Unable to write AI analysis file {}: {}'.format(ai_file, err))


def main():
    """
    Main routine, parses arguments and calls other routines
    """
    global config
    global use_pmc
    global exe_cmdline
    global script_cwd
    global debug_file
    global use_virustotal

    print('\n--===[ Noriben v{}'.format(__VERSION__))

    if sys.version_info < (3, 0):
        print('[*] Support for Python 2 is no longer available. Please use Python 3.')
        terminate_self(10)

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--csv', help='Re-analyze an existing Noriben CSV file', required=False)
    parser.add_argument('-p', '--pml', help='Re-analyze an existing Noriben PML file', required=False)
    parser.add_argument('-f', '--filter', help='Specify alternate Procmon Filter PMC', required=False)
    parser.add_argument('--config', help='Specify configuration file', required=False)
    parser.add_argument('--hash', help='Specify hash approvelist file', required=False)
    parser.add_argument('--hashtype', help='Specify hash type', required=False, choices=valid_hash_types)
    parser.add_argument('--disable-file-hash', action='store_true', help='Disable hashing new files', required=False)
    parser.add_argument('--json', action='store_true',
                        help='Also write a structured JSON report with IOCs and ATT&CK tags', required=False)
    parser.add_argument('--gen-yara', action='store_true',
                        help='Generate a suggested YARA rule from behavioral indicators', required=False)
    parser.add_argument('--gen-sigma', action='store_true',
                        help='Generate Sigma detection rules (*.sigma.yml) from indicators', required=False)
    parser.add_argument('--stix', action='store_true',
                        help='Export IOCs as a STIX 2.1 bundle (*.stix.json)', required=False)
    parser.add_argument('--misp', action='store_true',
                        help='Export IOCs as a MISP event (*.misp.json)', required=False)
    parser.add_argument('--diff', help='Diff this run against a previously saved *.iocs.json baseline',
                        required=False)
    parser.add_argument('--merge', nargs='+', metavar='IOCS_JSON',
                        help='Consolidate multiple *.iocs.json reports (files, globs, or a folder) '
                        'into a single multi-run summary, then exit', required=False)
    parser.add_argument('--headless', action='store_true', help='Do not open results on VM after processing',
                        required=False)
    parser.add_argument('--human', action='store_true', help='Perform human activity', required=False)
    parser.add_argument('-t', '--timeout', help='Number of seconds to collect activity', required=False, type=int)
    parser.add_argument('--output', help='Folder to store output files', required=False)
    parser.add_argument('--yara', help='Folder containing YARA rules', required=False)
    parser.add_argument('--cmd', help='Command line to execute (in quotes)', required=False)
    parser.add_argument('--ai', action='store_true',
                        help='Generate an AI behavioral analysis of the report', required=False)
    parser.add_argument('--ai-provider', help='AI provider for report analysis',
                        choices=['ollama', 'openai'], required=False)
    parser.add_argument('--ai-model', help='Model name for AI analysis (e.g. llama3.1, gpt-4o-mini)',
                        required=False)
    parser.add_argument('--ai-url', help='Base URL for an OpenAI-compatible AI endpoint '
                        '(e.g. http://localhost:11434/v1)', required=False)
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debugging', required=False)
    parser.add_argument('--troubleshoot', action='store_true', help='Pause before exiting for troubleshooting',
                        required=False)
    parser.add_argument('--version', action='version', version='Noriben {}'.format(__VERSION__))
    args = parser.parse_args()
    report = []
    timeline = []
    script_cwd = os.path.dirname(os.path.abspath(__file__))

    # Load config file first, then use additional args to override those values if necessary
    default_config_location = os.path.join(script_cwd, 'Noriben.config')
    config = read_config(default_config_location)
    if args.config:
        if file_exists(args.config):
            config = read_config(args.config)
        else:
            print('[!] Config file {} not found. Continuing with default values.'.format(args.config))

    if args.debug:
        config['debug'] = True

    # Override AI settings from the command line if provided
    if args.ai:
        config['ai_enabled'] = True
    if args.ai_provider:
        config['ai_provider'] = args.ai_provider
    if args.ai_model:
        config['ai_model'] = args.ai_model
    if args.ai_url:
        config['ai_base_url'] = args.ai_url

    if not config['virustotal_api_key'] and os.path.exists('virustotal.api'):
        config['virustotal_api_key'] = open('virustotal.api', 'r', encoding='utf-8').readline().strip()
        use_virustotal = bool(config['virustotal_api_key'] and has_internet)
        if config['virustotal_upload'] and not use_virustotal:
            config['virustotal_upload'] = False

    if args.troubleshoot:
        config['troubleshoot'] = True

    # Check to see if string generalization is wanted
    if config['generalize_paths']:
        generalize_vars_init()

    if args.disable_file_hash:
        config['disable-file-hash'] = True

    if args.json:
        config['json_report'] = True
    if args.gen_yara:
        config['gen_yara'] = True
    if args.gen_sigma:
        config['gen_sigma'] = True
    if args.stix:
        config['stix_export'] = True
    if args.misp:
        config['misp_export'] = True
    if args.diff:
        config['diff_against'] = args.diff

    # Consolidated multi-run mode: aggregate several JSON IOC reports and exit.
    if args.merge:
        if args.output:
            config['output_folder'] = args.output
        run_consolidation(args.merge, config)
        terminate_self(0)

    if args.headless:
        config['headless'] = True

    if args.hashtype:
        config['hash_type'] = args.hashtype

    # Load hash approvelist and append to global approve list
    if args.hash and file_exists(args.hash):
        read_hash_file(args.hash)

    # Check for a valid filter file
    if args.filter:
        if file_exists(args.filter):
            pmc_file = args.filter
        else:
            pmc_file = ''
    else:
        pmc_file = 'ProcmonConfiguration.PMC'
    pmc_file_cwd = os.path.join(script_cwd, pmc_file)

    if pmc_file:
        if not file_exists(pmc_file):
            if not file_exists(pmc_file_cwd):
                use_pmc = False
                print('[!] Filter file {} not found. Continuing without filters.'.format(pmc_file))
            else:
                use_pmc = True
                pmc_file = pmc_file_cwd
                print('[*] Using filter file: {}'.format(pmc_file))
        else:
            use_pmc = True
            print('[*] Using filter file: {}'.format(pmc_file))
            log_debug('[*] Using filter file: {}'.format(pmc_file))
    else:
        use_pmc = False

    # Check to see if specified output folder exists. If not, make it.
    # This only works one path deep. In future, may make it recursive.
    if args.output:
        config['output_folder'] = args.output
        if not os.path.exists(config['output_folder']):
            try:
                os.mkdir(config['output_folder'])
            except OSError:
                print('[!] Fatal: Unable to create output directory: {}'.format(config['output_folder']))
                terminate_self(3)
    log_debug('[*] Log output directory: {}'.format(config['output_folder']))

    # Check to see if specified YARA folder exists
    if args.yara or config['yara_folder']:
        if not config['yara_folder']:
            config['yara_folder'] = args.yara
        if not config['yara_folder'][-1] == '\\':
            config['yara_folder'] += '\\'
        if not os.path.exists(config['yara_folder']):
            print('[!] YARA rule path not found: {}'.format(config['yara_folder']))
            config['yara_folder'] = ''
    log_debug('[*] YARA directory: {}'.format(config['yara_folder']))


    # Print feature list
    log_debug(
        '[+] Features: (Debug: {}\tInternet: {}\tVirusTotal: {})'.format(config['debug'], has_internet, use_virustotal))


    log_debug('[*] Configuration data read:', override=True)
    for section in config.keys():
        log_debug('[=] {} = {}'.format(section, config[section]), override=True)


    # Check if user-specified to rescan a PML
    if args.pml:
        if file_exists(args.pml):
            # Reparse an existing PML
            if not args.output:
                config['output_folder'] = os.path.dirname(args.pml)
            pml_basename = os.path.splitext(os.path.basename(args.pml))[0]
            csv_file = os.path.join(config['output_folder'], pml_basename + '.csv')
            txt_file = os.path.join(config['output_folder'], pml_basename + '.' + config['txt_extension'])
            debug_file = os.path.join(config['output_folder'], pml_basename + '.log')
            timeline_file = os.path.join(config['output_folder'], pml_basename + '_timeline.csv')

            # Converting a PML to CSV requires procmon (unlike re-parsing a CSV)
            procmonexe = check_procmon()
            if not procmonexe:
                print('[!] Unable to find Procmon ({}) in path.'.format(config['procmon']))
                terminate_self(2)

            process_pml_to_csv(procmonexe, args.pml, pmc_file, csv_file)
            if not file_exists(csv_file):
                print('[!] Error detected. Could not create CSV file: {}'.format(csv_file))
                terminate_self(5)

            parse_csv(csv_file, report, timeline)

            ai_file = os.path.join(config['output_folder'], pml_basename + '_AI_Analysis.md')
            append_ai_analysis(report, config, ai_file)

            print('[*] Saving report to: {}'.format(txt_file))
            codecs.open(txt_file, 'w', 'utf-8-sig').write('\r\n'.join(report))

            print('[*] Saving timeline to: {}'.format(timeline_file))
            # codecs.open(timeline_file, 'w', 'utf-8-sig').write('\r\n'.join(timeline))
            with open(timeline_file, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerows(timeline)

            open_file_with_assoc(txt_file)
            terminate_self(0)
        else:
            print('[!] PML file does not exist: {}\n'.format(args.pml))
            parser.print_usage()
            terminate_self(1)

    # Check if user-specified to rescan a CSV
    if args.csv:
        if file_exists(args.csv):
            # Reparse an existing CSV
            if not args.output:
                config['output_folder'] = os.path.dirname(args.csv)
            csv_basename = os.path.splitext(os.path.basename(args.csv))[0]
            txt_file = os.path.join(config['output_folder'], csv_basename + '.' + config['txt_extension'])
            debug_file = os.path.join(config['output_folder'], csv_basename + '.log')
            timeline_file = os.path.join(config['output_folder'], csv_basename + '_timeline.csv')

            parse_csv(args.csv, report, timeline)

            ai_file = os.path.join(config['output_folder'], csv_basename + '_AI_Analysis.md')
            append_ai_analysis(report, config, ai_file)

            print('[*] Saving report to: {}'.format(txt_file))
            codecs.open(txt_file, 'w', 'utf-8-sig').write('\r\n'.join(report))

            print('[*] Saving timeline to: {}'.format(timeline_file))
            codecs.open(timeline_file, 'w', 'utf-8-sig').write('\r\n'.join(timeline))

            open_file_with_assoc(txt_file)
            terminate_self(0)
        else:
            parser.print_usage()
            terminate_self(10)

    if args.timeout:
        config['timeout_seconds'] = args.timeout

    if args.cmd:
        exe_cmdline = args.cmd
    else:
        exe_cmdline = ''

    # Find a valid procmon executable.
    procmonexe = check_procmon()
    if not procmonexe:
        print('[!] Unable to find Procmon ({}) in path.'.format(config['procmon']))
        terminate_self(2)

    # Start main data collection and processing
    print('[*] Using procmon EXE: {}'.format(procmonexe))
    session_id = get_session_name()
    pml_file = os.path.join(config['output_folder'], 'Noriben_{}.pml'.format(session_id))
    csv_file = os.path.join(config['output_folder'], 'Noriben_{}.csv'.format(session_id))
    txt_file = os.path.join(config['output_folder'], 'Noriben_{}.{}'.format(session_id, config['txt_extension']))
    debug_file = os.path.join(config['output_folder'], 'Noriben_{}.log'.format(session_id))

    timeline_file = os.path.join(config['output_folder'], 'Noriben_{}_timeline.csv'.format(session_id))

    print('[*] Procmon session saved to: {}'.format(pml_file))

    if exe_cmdline:
        exe_cmdline_base_file = shlex.split(exe_cmdline, posix=False)[0]
        if not file_exists(exe_cmdline_base_file):
            print('[!] Error: Specified malware executable does not exist: {}'.format(exe_cmdline_base_file))
            terminate_self(6)

    print('[*] Launching Procmon ...')
    launch_procmon_capture(procmonexe, pml_file, pmc_file)

    if exe_cmdline:
        print('[*] Launching command line: {}'.format(exe_cmdline))
        try:
            subprocess.Popen(exe_cmdline)
        except OSError as e:  # Occurs if VMWare bug removes Owner from file
            print('[*] Execution failed. File is potentially not an executable.')
            print(e)
            print('[*] Attempting to open with associated application...')
            try:
                open_file_with_assoc(exe_cmdline)
            except OSError:
                print('\n[*] Unexpected termination of Procmon commencing... please wait')
                print('[!] Error executing file. Windows is refusing execution based upon permissions.')
                terminate_procmon(procmonexe)
                terminate_self(4)

    else:
        print('[*] Procmon is running. Run your executable now.')

    try:
        if config['human']:
            human()
    except KeyError:
        pass

    if not config['timeout_seconds'] == '0':
        print('[*] Running for {} seconds. Press Ctrl-C to stop logging early.'.format(config['timeout_seconds']))
        # Print a small progress indicator, for those REALLY long sleeps.
        try:
            timeout_seconds = int(config['timeout_seconds'])
            for i in range(timeout_seconds):
                progress = round((100 / timeout_seconds) * i)
                sys.stdout.write('\r{}% complete'.format(progress))
                sys.stdout.flush()
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    else:
        print('[*] When runtime is complete, press CTRL+C to stop logging.')
        try:
            while True:
                time.sleep(100)
        except KeyboardInterrupt:
            pass

    print('\n[*] Termination of Procmon commencing... please wait')
    terminate_procmon(procmonexe)

    print('[*] Procmon terminated')
    if not file_exists(pml_file):
        print('[!] Error creating PML file!')
        terminate_self(8)

    # PML created, now convert it to a CSV for parsing
    process_pml_to_csv(procmonexe, pml_file, pmc_file, csv_file)
    if not file_exists(csv_file):
        print('[!] Error detected. Could not create CSV file: {}'.format(csv_file))
        terminate_self(7)

    # Process CSV file, results in 'report' and 'timeline' output lists
    parse_csv(csv_file, report, timeline)

    ai_file = os.path.join(config['output_folder'], 'Noriben_{}_AI_Analysis.md'.format(session_id))
    append_ai_analysis(report, config, ai_file)

    print('[*] Saving report to: {}'.format(txt_file))
    codecs.open(txt_file, 'w', 'utf-8').write('\r\n'.join(report))

    print('[*] Saving timeline to: {}'.format(timeline_file))
    codecs.open(timeline_file, 'w', 'utf-8').write('\r\n'.join(timeline))

    open_file_with_assoc(txt_file)
    terminate_self(0)
    # End of main()


if __name__ == '__main__':
    main()
