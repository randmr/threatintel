# threatintel in Splunk

To run this script in Splunk, several changes have been made from the original.

* The script expects the input file to be located in the lookups folder of the same app where the script is installed
  * This allows the input file to be referenced as a lookup in case additional info about where the threat data came from is desired
* Logging has been changed
  * Informational messages are printed so they will be added to the main Splunk Index
  * Error messages are sent to stderr so they will be added to the _internal index.  This makes it easier to alert on errors
* A wrapper script has been used that can be called from the python included with Splunk.  The netaddr module is unavailable in Splunk python, so the main script must be run by an external python

## Installation

1. Place the threatlist.py and threatlist-wrapper.py scripts in the appropriate apps bin directory
2. Place the threatlist.in.csv file in the lookups folder of the same app
3. Create a scripted input to call the threatlist-wrapper.py script on an appropriate interval
     * When creating the input, the index specified is where informational messages will go.  Informational messages will go to the defined index, error messages will go to the _internal index and lookup data will not be indexed
4. After running the script one time and confirming that there are no errors, create a lookup to use the threatlist.csv lookup file

## Using the script in Splunk

To populate the lookup file on a regular basis, create a scripted input in `inputs.conf` to call the wrapper script:
```
[script://$SPLUNK_HOME/etc/apps/yourApp/bin/threatlist-wrapper.py]
disabled = false
interval = 15 4 * * *
sourcetype = generic_single_line
```

To use the lookup files, create the following lookups in `transforms.conf`:
```
[threatlist]
filename = threatlist.csv
match_type = CIDR(ip_range)
default_match = NONE
min_matches = 1

[threatlist_sources]
filename = threatlist.in.csv
```

This is an example search that utilizes both lookups:
```
source="http:testing" (index="testing")
 | lookup threatlist ip_range as IP OUTPUTNEW ip_range, threat_name, threat_severity
 | where threat_name!="*"
 | lookup threatlist_sources Name as threat_name
 | table IP, threat_name, threat_severity, URL, ip_range
 ```
