# wifi-scanner-server
Server side of WiFi scan survey.

Started from a Flask tutorial.

Uses nl80211 to get scan survey results. Store in Python3. Serve up various endpoints for scan data.

Do *not* write anything to disk, etc. Long term goal is to run on Raspberry Pi and such.  No need to save to disk when could wear out the flash or fill up the disk.
