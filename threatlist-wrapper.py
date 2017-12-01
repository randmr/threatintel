import os
import subprocess

_NEW_PYTHON_PATH = '/usr/bin/python'
_SPLUNK_PYTHON_PATH = os.environ['PYTHONPATH']

os.environ['PYTHONPATH'] = _NEW_PYTHON_PATH
my_process = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'threatlist.py')

p = subprocess.Popen([os.environ['PYTHONPATH'], my_process, _SPLUNK_PYTHON_PATH],
stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output,err = p.communicate()
print "output: " + output
print "err: " + err
