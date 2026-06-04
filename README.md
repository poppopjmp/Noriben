## <img src="https://raw.githubusercontent.com/Rurik/Noriben/master/images/noriben_logo.png" height=100> Noriben Malware Analysis Sandbox
![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2015.svg) ![Black Hat Arsenal](https://raw.githubusercontent.com/toolswatch/badges/master/arsenal/usa/2023.svg)



<pre>
Contact Information:
@bbaskin on Twitter
brian _at_ thebaskins _dot_ com
</pre>


Noriben is a Python-based script that works in conjunction with Sysinternals Procmon to automatically collect, analyze, and report on runtime indicators of malware. In a nutshell, it allows you to run an applications, hit a keypress, and get a simple text report of the sample's activities.


Noriben allows you to not only run malware similar to a sandbox, but to also log system-wide events while you manually run malware in ways particular to making it run. For example, it can listen as you run an application that requires varying command line options, or user interaction. Or, to watch the system as you step through the application in a debugger.

While Noriben was designed for analysis of malware, it has also been widely used to audit normal software applications. In 2013 it was used by the Tor Project to provide a [public audit](https://research.torproject.org/techreports/tbb-forensic-analysis-2013-06-28.pdf) of the Tor Browser Bundle

Below is a video of debugging a VM-checking malware in a way to still get sandbox results (mis-clicks due to a mouse pointer that was 5 pixels off :))

[![Noriben running against malware checking for VM ](https://img.youtube.com/vi/kmCzAmqMeTY/0.jpg)](https://www.youtube.com/watch?v=kmCzAmqMeTY)


Noriben only requires Sysinternals procmon.exe (or procmon64.exe) to operate. It requires no pre-filtering (though it would greatly help) as it contains numerous white list items to reduce unwanted noise from system activity.


For a more detailed explanation, see <a href="http://www.slideshare.net/bbaskin/bh15-arsenal-noriben">my slide deck</a> from Black Hat 2015 Arsenal. And a more detailed blog post:
http://ghettoforensics.blogspot.com/2013/04/noriben-your-personal-portable-malware.html


I've also included a much desired frontend operator, NoribenSandbox.py. This script allows you to automate the execution of Noriben within a guest VM and retrieve the reports. It currently runs on OSX (but will be ported) and is responsible for: spinning up a predefined VM and snapshot, copying the malware to the VM, starting Noriben and the malware, waiting a predetermined period of time, copying the results to the host as a ZIP, and taking a screen capture of the VM. You can even use --update to automatically copy the newest Noriben from your host, so that you don't have to continually make new snapshots when you make a change to the script.

Want to see that in action?

[![Noriben Automation Script in Action](https://img.youtube.com/vi/GSSCM0kUqo8/0.jpg)](https://www.youtube.com/watch?v=GSSCM0kUqo8)



# Cool Features

If you have a folder of YARA signature files, you can specify it with the --yara option. Every new file create will be scanned against these signatures with the results displayed in the output results.

If you have a VirusTotal API, place it into a file named "virustotal.api" (or embed directly in the script) to auto-submit MD5 file hashes to VT to get the number of viral results.  

You can add lists of MD5s to auto-ignore (such as all of your system files). Use md5deep and throw them into a text file, use --hash <file> to read them. This will ultimately go under changes, though.

You can automate the script for sandbox-usage. Using -t <seconds> to automate execution time, and --cmd "path\exe" to specify a malware file, you can automatically run malware, copy the results off, and then revert to run a new sample.

The --generalize feature will automatically substitute absolute paths with Windows environment paths for better IOC development. For example, C:\Users\malware_user\AppData\Roaming\malware.exe will be automatically resolved to %AppData%\malware.exe.

# Automated Triage: IOCs, MITRE ATT&CK & JSON

Every report now opens with a **Behavioral Summary & Indicators of Compromise**
section so an analyst can see the important findings without scrolling through
the full event log:

* activity counts (processes, files created/deleted, registry writes, hosts)
* dropped-file hashes
* network endpoints
* **heuristic MITRE ATT&CK technique tags** with the evidence that triggered
  them — persistence (Run keys, services, scheduled tasks, Winlogon, IFEO),
  LOLBIN execution (rundll32, regsvr32, mshta, certutil, bitsadmin), encoded
  PowerShell, recovery inhibition (vssadmin/bcdedit), defense evasion, and more

Add `--json` to also write a structured, machine-readable `*.iocs.json` next to
the report. It contains the parsed processes, file/registry/network activity,
extracted IOCs, and the ATT&CK tags — ready to feed into your own tooling, a
threat-intel platform, or a run-to-run diff:

<pre>
python Noriben.py --json                       # live capture + JSON IOC report
python Noriben.py --csv Noriben_12_Jan.csv --json   # re-triage an existing CSV
</pre>

Both can be enabled persistently via `json_report` in `Noriben.config`. When AI
analysis is also enabled, this IOC summary is part of what the model sees, so
its assessment is better grounded in the actual indicators.

The summary also extracts **named pipes** and **mutexes** (common infection
markers) from the captured activity.

## Sharing & comparing results

Noriben can turn a run into artifacts you can act on:

<pre>
--gen-yara   Write a suggested YARA rule (*.suggested.yar) built from the
             behavioral indicators (dropped file names, mutexes, named pipes,
             network hosts, autostart value names). A starting point to
             review, not a vetted rule.
--gen-sigma  Write Sigma detection rules (*.sigma.yml) for dropped executables,
             registry persistence, network endpoints, named pipes, and
             suspicious command lines - each tagged with MITRE ATT&CK
--stix       Export the IOCs as a STIX 2.1 bundle (*.stix.json)
--misp       Export the IOCs as a MISP event (*.misp.json)
--diff FILE  Compare this run against a previously saved *.iocs.json baseline.
             Prints what was added/removed (processes, files, hashes, registry
             keys, hosts, pipes, mutexes, ATT&CK techniques) and also writes a
             self-contained HTML diff report (*.diff.html)
</pre>

Example — triage a sample, then diff a second variant against it:

<pre>
python Noriben.py --csv sample_a.csv --json --gen-yara --stix --misp
python Noriben.py --csv sample_b.csv --diff sample_a.iocs.json
</pre>

`--gen-yara`, `--gen-sigma`, `--stix`, and `--misp` also have matching
`gen_yara`, `gen_sigma`, `stix_export`, and `misp_export` keys in
`Noriben.config`.

### Consolidating multiple runs

To profile a malware family, run several samples with `--json`, then merge the
resulting `*.iocs.json` reports into a single view that shows which IOCs and
ATT&CK techniques are **shared across runs** versus unique to one sample:

<pre>
python Noriben.py --merge results/            # a folder of *.iocs.json
python Noriben.py --merge a.iocs.json b.iocs.json c.iocs.json
python Noriben.py --merge "results/*.iocs.json" --output results
</pre>

This writes `Noriben_consolidated.txt`, `.json`, and `.html` (a sortable-looking
table with shared indicators highlighted).

# AI-Assisted Report Analysis

Noriben can hand the generated report to a Large Language Model to produce an
automated behavioral analysis — an executive summary, notable behaviors,
persistence mechanisms, network/host IOCs, and a Benign/Suspicious/Malicious
risk assessment. The analysis is appended to the text report and also saved as
a standalone `*_AI_Analysis.md` file.

It works with **any OpenAI-compatible Chat Completions endpoint**, so you can
keep everything local with [Ollama](https://ollama.com/) or point it at a hosted
provider:

<pre>
# Local, private analysis with Ollama (no data leaves your machine)
ollama serve
ollama pull llama3.1
python Noriben.py --ai --ai-provider ollama --ai-model llama3.1

# Re-analyze an existing capture with a local model
python Noriben.py --csv Noriben_12_Jan_25.csv --ai

# Use the OpenAI API (or any compatible gateway: LM Studio, vLLM, LiteLLM)
python Noriben.py --ai --ai-provider openai --ai-model gpt-4o-mini \
    --ai-url https://api.openai.com/v1
</pre>

All AI options can also be set persistently in `Noriben.config` under the
`[Noriben]` section (`ai_enabled`, `ai_provider`, `ai_base_url`, `ai_model`,
`ai_api_key`, `ai_timeout`, `ai_max_chars`). The OpenAI provider needs an API
key (`ai_api_key`, or pass it via the endpoint); local Ollama needs none. If the
endpoint is unreachable the normal report is still produced — AI failures are
never fatal.


## Requirements & Installation

Noriben requires **Python 3.8+** and the Sysinternals `procmon.exe` (run on the
Windows analysis VM).

Install the Python dependencies with:

<pre>
pip install -r requirements.txt
</pre>

All third-party modules are optional and the script degrades gracefully if one
is missing:

* `requests` — VirusTotal hash lookups / file submission
* `yara-python` — `--yara` rule scanning of newly created files
* `python-magic` + `pyautogui` — only needed for the host automation front end,
  `NoribenSandbox.py` (`pip install -r requirements.txt` installs these too; on
  Linux/macOS `python-magic` also needs the native `libmagic` library)

Alternatively, install Noriben as a package (provides a `noriben` console
command):

<pre>
pip install .
</pre>

Usage:
<pre>
--===[ Noriben v2.0.1
--===[ @bbaskin
usage: Noriben.py [-h] [-c CSV] [-p PML] [-f FILTER] [--hash HASH]
                  [--hashtype {MD5,SHA1,SHA256}] [--headless] [-t TIMEOUT]
                  [--output OUTPUT] [--yara YARA] [--generalize] [--cmd CMD]
                  [-d]

optional arguments:
  -h, --help            show this help message and exit
  -c CSV, --csv CSV     Re-analyze an existing Noriben CSV file
  -p PML, --pml PML     Re-analyze an existing Noriben PML file
  -f FILTER, --filter FILTER
                        Specify alternate Procmon Filter PMC
  --hash HASH           Specify hash whitelist file
  --hashtype {MD5,SHA1,SHA256}
                        Specify hash type
  --headless            Do not open results on VM after processing
  -t TIMEOUT, --timeout TIMEOUT
                        Number of seconds to collect activity
  --output OUTPUT       Folder to store output files
  --yara YARA           Folder containing YARA rules
  --generalize          Generalize file paths to their environment variables.
                        Default: True
  --cmd CMD             Command line to execute (in quotes)
  -d, --debug           Enable debugging
</pre>

## Notable contributors

Brian Baskin
<Your name here>
<Documentation writers welcome!>

<a href="https://twitter.com/noticemecowpie">Cowpy for the logo design</a>

## Copyright and license

Copyright 2015 Brian Baskin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this work except in compliance with the License.
You may obtain a copy of the License in the LICENSE file, or at:

  [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
