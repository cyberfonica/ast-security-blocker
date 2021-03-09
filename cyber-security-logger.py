"""

Requires some debian packages first

    sudo apt-get install python3-pip python3-dev default-libmysqlclient-dev build-essential

Then requires some PIP packages

    pip3 install pygtail
    pip3 install mysqlclient

"""
from pygtail import Pygtail
import re
import MySQLdb
import logging

# Configure logging
log = logging.getLogger('cyber-security-blocker')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log.setLevel(logging.WARNING)
ch = logging.StreamHandler()
ch.setLevel(logging.CRITICAL)
ch.setFormatter(formatter)
log.addHandler(ch)
fh = logging.FileHandler("/var/log/asterisk/cyber-security")
fh.setLevel(logging.WARNING)
fh.setFormatter(formatter)
log.addHandler(fh)

db = MySQLdb.connect("localhost", "root", "xtreme1969", "voip10")
cursor = db.cursor()

pattern = re.compile(r'SecurityEvent="ChallengeSent".*AccountID="sip:(.*)@.*RemoteAddress="IPV4/UDP/(.*)/\d+"')

for line in Pygtail("/var/log/asterisk/security"):
    match = pattern.search(line)
    if match:
        account_id = match.group(1)
        ip_address = match.group(2)

        cursor.execute("SELECT * FROM `voip10`.`lines` WHERE line_id = %s", (account_id,))
        row = cursor.fetchone()
        if row:
            # Do nothing, as someone has tried to log in that is a user
            log.debug("Challenge sent to real user {} from IP {}. Not dispatching security alert".format(
                account_id, ip_address))
        else:
            log.error("Security alert. User {} tried to connect from IP {}".format(account_id, ip_address))
