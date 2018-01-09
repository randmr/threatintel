# threatintel in Splunk

To run this script in Splunk, several changes have been made from the original.

* The script expects the input file to be located in the lookups folder of the same app where the script is installed
  * This allows the input file to be referenced as a lookup in case additional info about where the threat data came from is desired
* Logging has been changed
  * Informational messages are printed so they will be added to the main Splunk Index
  * Error messages are sent to stderr so they will be added to the _internal index.  This makes it easier to alert on errors
* A wrapper script has been used that can be called from the python included with Splunk.  The netaddr module is unavailable in Splunk python, so the main script must be run by an external python

## Installation

1. Extract the application to the $SPLUNK_HOME/etc/apps directory
2. Restart splunk
3. Enable the input via web or by creating a local inputs.conf file 

## Installation in distributed Splunk designs

This app only needs to be installed on search heads.  It does not need to be installed on indexers as the lookup files are automatically distributed to the indexers.

## Using the script in Splunk

This is an example search that utilizes both lookups:
```
index=main source=firewall
 | lookup threatlist ip_range as IP OUTPUTNEW ip_range, threat_name, threat_severity
 | where threat_name!="NONE"
 | lookup threatlist_sources Name as threat_name
 | table IP, threat_name, threat_severity, URL, ip_range
```
