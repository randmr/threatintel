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
2. Place the threatlist.in.csv file in the same apps lookups folder
3. Create a scripted input to call the threatlist-wrapper.py script on an appropriate interval
  * When creating the input, the index specified is where informational messages will go.  The lookup data will not be indexed, and error messages will go to the _internal index
4. After running the script one time and confirming that there are no errors, create a lookup to use the threatlist.csv lookup file
