#!/usr/bin/python

## attachment_watcher.py : pyinotify for email reporting
# Ben Lieberman
# Version 1.0.0

import pyinotify, subprocess, sys, os, logging
import paramiko, hashlib
from datetime import datetime, tzinfo, timedelta

## CONSTANTS ##
NOTIFY_ROOT = "/var/tmp/exim/mime/reports"
LOG_SERVER = "YOUR_LOG_SERVER.YOUR_DOMAIN"
PORT = 22
LOG_DIR = "YOUR_LOG_DIR"
SCPUSER = "YOUR_SCP_USER"
LOGGING_DIR = "/var/log/pywatch/"
rsa_private_key = r"YOUR_SSH_PRIVATE_KEY"

logging.basicConfig(filename=LOGGING_DIR + 'pyinotify_strelay.log',level=logging.INFO,format='%(asctime)s.%(msecs)d %(levelname)s %(module)s - %(funcName)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
################################################

## TIMEZONE REQUIRED FOR UTC TO ETC CONVERSIONS ##
class Zone(tzinfo):
  def __init__(self,offset,isdst,name):
    self.offset = offset
    self.isdst = isdst
    self.name = name
  def utcoffset(self, dt):
    return timedelta(hours=self.offset) + self.dst(dt)
  def dst(self, dt):
    return timedelta(hours=1) if self.isdst else timedelta(0)
  def tzname(self,dt):
    return self.name

## HELPER FUNCTIONS ##
def hasExtension(filename):
  extensions = ['.xls', '.xlsx', '.csv', '.zip', '.tsv'] # extensions to look for
  for e in extensions:
    if filename.endswith(e):
      return True
    else:
      continue

def agent_auth(transport, username):
  try:
    ki = paramiko.RSAKey.from_private_key_file(rsa_private_key)
  except Exception, e:
    logging.critical('Failed loading private key %s', rsa_private_key)

  agent = paramiko.Agent()
  agent_keys = agent.get_keys() + (ki,)
  if len(agent_keys) == 0:
    return

  for key in agent_keys:
    logging.info('Trying ssh-agent key')
    try:
      transport.auth_publickey(username, key)
      logging.info('... success!')
      return
    except paramiko.SSHException, e:
      logging.critical('... failed! Error: %s', e)

## REQUIRED FOR TZ CONVERSTIONS ##
EST = Zone(-5, True, 'EST')
##################################

def transferFile(filepath, reportName):
  # we need to load the date variables at function call if running for more than 24 hour period
  second = datetime.now(EST).strftime("%S")
  minute = datetime.now(EST).strftime("%M")
  hour = datetime.now(EST).strftime("%H")
  day = datetime.now(EST).strftime("%d")
  month = datetime.now(EST).strftime("%m")
  year = datetime.now(EST).strftime("%Y")

  # now, connect and use paramiko Transport to negotiate SSH2 across the connection
  try:
    logging.info('Establishing SSH connection to: %s...', LOG_SERVER)
    t = paramiko.Transport((LOG_SERVER, PORT))
    t.start_client()

    agent_auth(t, SCPUSER)

    if not t.is_authenticated():
      logging.critical('RSA key auth failed!...')
    else:
      sftp = t.open_session()
    sftp = paramiko.SFTPClient.from_transport(t)

    # Ensure directory is created before entry starts
    dir_remote = LOG_DIR + "/" + year + "-" + month + "-" + day
    try:
      sftp.mkdir(dir_remote)
      logging.info('Ensured %s exists.', dir_remote)
    except IOError, e:
      logging.info('Assuming %s exists.', dir_remote)

    is_up_to_date = False
    local_file = filepath
    remote_file = dir_remote + "/" + reportName

    # does the remote file already exist? let's do a checksum
    try:
      if sftp.stat(remote_file):
        local_file_data = open(local_file, "rb").read()
        remote_file_data = sftp.open(remote_file).read()
        md1 = hashlib.md5(local_file_data).hexdigest()
        md2 = hashlib.md5(remote_file_data).hexdigest()
        if md1 == md2:
          is_up_to_date = True
          logging.info("UNCHANGED: %s", reportName)
        else:
          logging.info("MODIFIED: %s", reportName)
    except:
      logging.info("NEW: %s", reportName)

    if not is_up_to_date:
      logging.info('Copying to %s', remote_file)
      sftp.put(local_file, remote_file)
      logging.info('Completed copy of file to %s', LOG_SERVER)
      logging.info('Removing local file %s', local_file)
      os.remove(local_file)

    t.close()

  except Exception, e:
    logging.critical('Unknown state. File trasnfer likely failed, please investigate.')
    logging.critical('Exception caught: %s: %s', e.__class__, e)
    try:
      t.close()
    except:
      pass

################################################

# handle events class
class EventHandler(pyinotify.ProcessEvent):
  # when a file is created...
  def process_IN_CREATE(self, event):
    # we need to load the date variables at function call if running for more than 24 hour period
    minute = datetime.now(EST).strftime("%M")
    hour = datetime.now(EST).strftime("%H")
    day = datetime.now(EST).strftime("%d")
    month = datetime.now(EST).strftime("%m")

    if hasExtension(event.name):
      logging.info('Filename is valid: %s', event.pathname)
      logging.info('Initiating copy of file to %s', LOG_SERVER)
      transferFile(event.pathname, os.path.basename(event.path) + "-" + month + day + hour + minute + os.path.splitext(event.pathname)[1])
    else:
      logging.error('Created file has an invlaid file name: %s', event.pathname)
  
  # when a file is deleted...
  def process_IN_DELETE(self, event):
    logging.info('File deletion detected: %s', event.pathname)

################################################

def main():
  logging.info('Starting pyinotify...')

  logging.info('Initilizing watch manager')
  wm = pyinotify.WatchManager()  # init watch Manager
  
  mask = pyinotify.IN_DELETE | pyinotify.IN_CREATE  # watched events
  
  logging.info('Initilizing event handler')
  handler = EventHandler() # init event hanadler

  logging.info('Initilizing notifier')
  notifier = pyinotify.Notifier(wm, handler) # init notifier

  # get all reporting subdirectories per relay address
  rootSubDirs = os.walk(NOTIFY_ROOT).next()[1]
  for d in rootSubDirs:
    fp = NOTIFY_ROOT + "/" + d
    wdd = wm.add_watch(fp, mask, rec=True)
    logging.info('Added watcher on %s' % d)

  logging.info('Initilization completed...')
  notifier.loop()

if __name__ == '__main__':
  main()
