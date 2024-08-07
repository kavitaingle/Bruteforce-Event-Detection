# Bruteforce-Event-Detection
#Developed a system to detect brute force attacks by analyzing Windows Security Event Logs using Python. Implemented a script to identify and flag suspicious login activities, enhancing security monitoring capabilities.
import win32evtlog

server = "localhost"
logtype = "security"
flags = win32evtlog.EVENTLOG_FORWARDS_READ win32evtlog.EVENTLOG_SEQUENTIAL_READ

def QueryEventLog(eventID, filename=None):
   logs = []
   if not filename:
      h = win32evtlog.OpenEvenTLog(server, logtype)
   else:
      h = win32evtlog.OpenBackupEvenTLog(server, filename)
   while True:
      events = win32evtlog.ReadEventLog(h, flags, 0)
      if events:
         for event in events:
            if event.EventID == eventID:
               logs.append(event)
               
      else:
          break
   return logs

def DetectBruteForce(filename=None):
    failures = {}
    events = QueryEventLog(4625, filename)
    for event in events:
       if int(event.StringInserts[10])in [3,8,19]:
          account = event.StringInserts[5]
          if account in failures:
              failures[account] +=1
          else:
              failures[account] =1
    return failures

 filename = "events.evtx"
 failures = DetectBruteForce(filename)
 for account in failures:
     print("%s: %sfailed logins"%(account,failures[account]))
     
    
