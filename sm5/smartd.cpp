/*
 * Home page of code is: http://smartmontools.sourceforge.net
 *
 * Copyright (C) 2002-3 Bruce Allen <smartmontools-support@lists.sourceforge.net>
 * Copyright (C) 2000 Michael Cornwell <cornwell@acm.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * You should have received a copy of the GNU General Public License
 * (for example COPYING); if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * This code was originally developed as a Senior Thesis by Michael Cornwell
 * at the Concurrent Systems Laboratory (now part of the Storage Systems
 * Research Center), Jack Baskin School of Engineering, University of
 * California, Santa Cruz. http://ssrc.soe.ucsc.edu/
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/hdreg.h>
#include <syslog.h>
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include "atacmds.h"
#include "ataprint.h"
#include "extern.h"
#include "knowndrives.h"
#include "scsicmds.h"
#include "smartd.h"
#include "utility.h"

extern const char *atacmds_c_cvsid, *ataprint_c_cvsid, *knowndrives_c_cvsid, *scsicmds_c_cvsid, *utility_c_cvsid;
const char *smartd_c_cvsid="$Id: smartd.cpp,v 1.143 2003/04/17 03:12:19 dpgilbert Exp $" 
ATACMDS_H_CVSID ATAPRINT_H_CVSID EXTERN_H_CVSID KNOWNDRIVES_H_CVSID SCSICMDS_H_CVSID SMARTD_H_CVSID UTILITY_H_CVSID; 

// Forward declaration
const char *getvalidarglist(char opt);

// global variable used for control of printing, passing arguments, etc.
smartmonctrl *con=NULL;

// Two other globals -- number of ATA and SCSI devices being monitored
int numatadevices=0;
int numscsidevices=0;

// How long to sleep between checks.  Handy as global variable for
// debugging
int checktime=CHECKTIME;

// name of PID file (== NULL if no pid_file is used)
char* pid_file=NULL;

// If set, we should exit after checking all disks once
int checkonce=0;

// Needed to interrupt sleep when catching SIGUSR1.  Unix Gurus: I
// know that this can be done better.  Please tell me how -- use email
// address for Bruce Allen at the top of this file.  Search for
// "sleeptime" to see what I am doing.
volatile int sleeptime=CHECKTIME;

// Interrupt sleep if we get a SIGUSR1.  Unix Gurus: I know that this
// can be done better.  Please tell me how -- use email address for
// Bruce Allen at the top of this file. Search for "sleeptime" to see
// what I am doing.
void sleephandler(int sig){
  int oldsleeptime=sleeptime;
  sleeptime=0;
  printout(LOG_CRIT,"Signal USR1 - checking devices now rather than in %d seconds.\n",oldsleeptime<0?0:oldsleeptime);
  return;
}

// Global Variables for command line options. These should go into a
// structure at some point.
unsigned char debugmode               = FALSE;

// This function prints either to stdout or to the syslog as needed

// [From GLIBC Manual: Since the prototype doesn't specify types for
// optional arguments, in a call to a variadic function the default
// argument promotions are performed on the optional argument
// values. This means the objects of type char or short int (whether
// signed or not) are promoted to either int or unsigned int, as
// appropriate.]
void printout(int priority,char *fmt, ...){
  va_list ap;
  // initialize variable argument list 
  va_start(ap,fmt);
  if (debugmode) 
    vprintf(fmt,ap);
  else {
    openlog("smartd",LOG_PID,LOG_DAEMON);
    vsyslog(priority,fmt,ap);
    closelog();
  }
  va_end(ap);
  return;
}

// If either address or executable path is non-null then send and log
// a warning email, or execute executable
void printandmail(cfgfile *cfg, int which, int priority, char *fmt, ...){
  char command[2048], message[256], hostname[256], additional[256];
  char original[256], further[256], domainname[256], subject[256],dates[64];
  int status;
  time_t epoch;
  va_list ap;
  const int day=24*3600;
  int days=0;
  char *whichfail[]={
    "emailtest", // 0
    "health",    // 1
    "usage",     // 2
    "selftest",  // 3
    "errorcount" // 4
    "FAILEDhealthcheck",         //5
    "FAILEDreadsmartdata",       //6
    "FAILEDreadsmarterrorlog",   //7
    "FAILEDreadsmartsefltestlog",//8
    "FAILEDopendevice"           //9
  };
  
  char *address=cfg->address;
  char *executable=cfg->emailcmdline;
  mailinfo *mail=cfg->maildata+which;
  
  // See if user wants us to send mail
  if (!address && !executable)
    return;

  // checks for sanity
  if (cfg->emailfreq<1 || cfg->emailfreq>3) {
    printout(LOG_INFO,"internal error in printandmail(): cfg->emailfreq=%d\n",cfg->emailfreq);
    return;
  }
  if (which<0 || which>9) {
    printout(LOG_INFO,"internal error in printandmail(): which=%d\n",which);
    return;
  }
  
  // Return if a single warning mail has been sent.
  if ((cfg->emailfreq==1) && mail->logged)
    return;
  
  // To decide if to send mail, we need to know what time it is.
  epoch=time(NULL);

  // Return if less than one day has gone by
  if (cfg->emailfreq==2 && mail->logged && epoch<(mail->lastsent+day))
    return;

  // Return if less than 2^(logged-1) days have gone by
  if (cfg->emailfreq==3 && mail->logged){
    days=0x01<<(mail->logged-1);
    days*=day;
    if  (epoch<(mail->lastsent+days))
      return;
  }

  // record the time of this mail message, and the first mail message
  if (!mail->logged)
    mail->firstsent=epoch;
  mail->lastsent=epoch;
  
  // get system host & domain names (not null terminated if length=MAX) 
  if (gethostname(hostname, 256))
    sprintf(hostname,"Unknown host");
  else
    hostname[255]='\0';
  if (getdomainname(domainname, 256))
    sprintf(hostname,"Unknown domain");
  else
    domainname[255]='\0';
  
  // print warning string into message
  va_start(ap, fmt);
  vsnprintf(message, 256, fmt, ap);
  va_end(ap);

  // appropriate message about further information
  additional[0]=original[0]=further[0]='\0';
  if (which) {
    sprintf(further,"You can also use the smartctl utility for further investigation.\n");

    switch (cfg->emailfreq){
    case 1:
      sprintf(additional,"No additional email messages about this problem will be sent.\n");
      break;
    case 2:
      sprintf(additional,"Another email message will be sent in 24 hours if the problem persists.\n");
      break;
    case 3:
      sprintf(additional,"Another email message will be sent in %d days if the problem persists\n",
              (0x01)<<mail->logged);
      break;
    }
    if (cfg->emailfreq>1 && mail->logged){
      dateandtimezoneepoch(dates, mail->firstsent);
      sprintf(original,"The original email about this issue was sent at %s\n", dates);
    }
  }
  
  snprintf(subject, 256,"SMART error (%s) detected on host: %s", whichfail[which], hostname);

  // If the user has set cfg->emailcmdline, use that as mailer, else "mail".
  if (!executable)
    executable="mail";
    
  // Export information in environment variables that will be useful
  // for user scripts
  setenv("SMARTD_MAILER", executable, 1);
  setenv("SMARTD_DEVICE", cfg->name, 1);
  setenv("SMARTD_DEVICETYPE", cfg->tryata?"ata":"scsi", 1);
  setenv("SMARTD_MESSAGE", message, 1);
  setenv("SMARTD_SUBJECT", subject, 1);
  dateandtimezoneepoch(dates, mail->firstsent);
  setenv("SMARTD_TFIRST", dates, 1);
  snprintf(dates, 64,"%d", (int)mail->firstsent);
  setenv("SMARTD_TFIRSTEPOCH", dates, 1);
  setenv("SMARTD_FAILTYPE", whichfail[which], 1);
  if (address)
    setenv("SMARTD_ADDRESS", address, 1);

  // now construct a command to send this as EMAIL
  if (address)
    snprintf(command, 2048, 
             "$SMARTD_MAILER -s '%s' %s > /dev/null 2> /dev/null << \"ENDMAIL\"\n"
             "This email was generated by the smartd daemon running on host:\n"
             "%s\n"
             "in the domain:\n"
             "%s\n\n"
             "The following warning/error was logged by the smartd daemon:\n"
             "%s\n\n"
             "For details see the SYSLOG (default: /var/log/messages) for host:\n"
             "%s\n\n"
             "%s%s%s"
             "ENDMAIL\n",
           subject, address, hostname, domainname, message, hostname, further, original, additional);
  else
    snprintf(command, 2048, "%s", executable);
  
  // tell SYSLOG what we are about to do...
  printout(LOG_INFO,"%s %s to %s ...\n",
           which?"Sending warning via ":"Executing test of", executable, address?address:"<nomailer>");

  // issue the command to send mail or to run the user's executable
  status=system(command);
  
  // now tell SYSLOG what happened.
  if (status==-1){
    printout(LOG_CRIT,"%s %s to %s failed (unable to fork new process)\n", 
             which?"Warning via":"Test of", executable, address?address:"<nomailer>");
  }
  else {
    int status8;
    // check and report exit status of command
#ifdef WEXITSTATUS
    status8=WEXITSTATUS(status);
#else
    status8=(status>>8) & 0xff;
#endif 
    if (status8)  
      printout(LOG_CRIT,"%s %s to %s failed (32-bit/8-bit exit status: %d/%d)\n", 
               which?"Warning via":"Test of", executable, address?address:"<nomailer>", status, status8);
    else
      printout(LOG_INFO,"%s %s to %s successful\n",
               which?"Warning via":"Test of", executable, address?address:"<nomailer>");
  } 
  // increment mail sent counter
  mail->logged++;
  
  return;
}

// Printing function for watching ataprint commands, or losing them
void pout(char *fmt, ...){
  va_list ap;
  // initialize variable argument list 
  va_start(ap,fmt);
  // in debug mode we will print the output from the ataprint.o functions!
  if (debugmode)
    vprintf(fmt,ap);
  else if (con->reportataioctl || con->reportscsiioctl) {
    openlog("smartd", LOG_PID, LOG_DAEMON);
    vsyslog(LOG_INFO, fmt, ap);
    closelog();
  }
  va_end(ap);
  return;
}

// tell user that we ignore HUP signals
void huphandler(int sig){
  printout(LOG_CRIT,"HUP ignored: smartd does NOT re-read /etc/smartd.conf.\n");
  return;
}

// signal handler that tells users about signals that were caught
void sighandler(int sig){
    printout(LOG_CRIT,"smartd received signal %d: %s\n",
             sig, strsignal(sig));
    exit(1);
}

// remove the PID file
void remove_pid_file(){
  if (pid_file) {
    if ( -1==unlink(pid_file) )
      printout(LOG_INFO,"Can't unlink PID file %s (%s).\n", 
	       pid_file, strerror(errno));
    free(pid_file);
  }
  return;
}

// signal handler that prints goodbye message and removes pidfile
void goodbye(){
  printout(LOG_CRIT,"smartd is exiting\n");
  remove_pid_file();
  return;
}

// Forks new process, closes all file descriptors, redirects stdin,
// stdout, stderr
void daemon_init(){
  pid_t pid;
  int i;  

  // flush all buffered streams.  Else we might get two copies of open
  // streams since both parent and child get copies of the buffers.
  fflush(NULL);
  
  if ((pid=fork()) < 0) {
    // unable to fork!
    printout(LOG_CRIT,"smartd unable to fork daemon process!\n");
    exit(1);
  }
  else if (pid)
    // we are the parent process -- exit cleanly
    exit(0);
  
  // from here on, we are the child process.
  setsid();

  // Fork one more time to avoid any possibility of having terminals
  if ((pid=fork()) < 0) {
    // unable to fork!
    printout(LOG_CRIT,"smartd unable to fork daemon process!\n");
    exit(1);
  }
  else if (pid)
    // we are the parent process -- exit cleanly
    exit(0);

  // Now we are the child's child...

  // close any open file descriptors
  for (i=getdtablesize();i>=0;--i)
    close(i);
  
  // redirect any IO attempts to /dev/null for stdin
  i=open("/dev/null",O_RDWR);
  // stdout
  dup(i);
  // stderr
  dup(i);
  umask(0);
  chdir("/");
  
  return;
}

// create a PID file containing the current process id
void write_pid_file() {
  if (pid_file) {
    int error = 0;
    pid_t pid = getpid();
    mode_t old_umask;
    FILE* fd; 
    
    old_umask = umask(0077);
    fd = fopen(pid_file, "w");
    umask(old_umask);
    if (fd == NULL) {
      error = 1;
    } else if (fprintf(fd, "%d\n", pid) <= 0) {
      error = 1;
    } else if (fclose(fd) != 0) {
      error = 1;
    }
    if (error) {
      printout(LOG_CRIT, "unable to write PID file %s - exiting.\n", pid_file);
      exit(1);
    }
    printout(LOG_INFO, "file %s written containing PID %d\n", pid_file, pid);
  }
  return;
}

// Prints header identifying version of code and home
void printhead(){
  printout(LOG_INFO,"smartd version %d.%d-%d Copyright (C) 2002-3 Bruce Allen\n",
           (int)RELEASE_MAJOR, (int)RELEASE_MINOR, (int)SMARTMONTOOLS_VERSION);
  printout(LOG_INFO,"Home page is %s\n\n",PROJECTHOME);
  return;
}


// prints help info for configuration file Directives
void Directives() {
  printout(LOG_INFO,"Configuration file (/etc/smartd.conf) Directives (after device name):\n");
  printout(LOG_INFO,"  -d TYPE Set the device type to one of: ata, scsi\n");
  printout(LOG_INFO,"  -T TYPE set the tolerance to one of: normal, permissive\n");
  printout(LOG_INFO,"  -o VAL  Enable/disable automatic offline tests (on/off)\n");
  printout(LOG_INFO,"  -S VAL  Enable/disable attribute autosave (on/off)\n");
  printout(LOG_INFO,"  -H      Monitor SMART Health Status, report if failed\n");
  printout(LOG_INFO,"  -l TYPE Monitor SMART log.  Type is one of: error, selftest\n");
  printout(LOG_INFO,"  -f      Monitor 'Usage' Attributes, report failures\n");
  printout(LOG_INFO,"  -m ADD  Send email warning to address ADD\n");
  printout(LOG_INFO,"  -M TYPE Modify email warning behavior (see man page)\n");
  printout(LOG_INFO,"  -p      Report changes in 'Prefailure' Attributes\n");
  printout(LOG_INFO,"  -u      Report changes in 'Usage' Attributes\n");
  printout(LOG_INFO,"  -t      Equivalent to -p and -u Directives\n");
  printout(LOG_INFO,"  -r ID   Also report Raw values of Attribute ID with -p, -u or -t\n");
  printout(LOG_INFO,"  -R ID   Track changes in Attribute ID Raw value with -p, -u or -t\n");
  printout(LOG_INFO,"  -i ID   Ignore Attribute ID for -f Directive\n");
  printout(LOG_INFO,"  -I ID   Ignore Attribute ID for -p, -u or -t Directive\n");
  printout(LOG_INFO,"  -v N,ST Modifies labeling of Attribute N (see man page)  \n");
  printout(LOG_INFO,"  -P TYPE Drive-specific presets: use, ignore, show, showall\n");
  printout(LOG_INFO,"  -a      Default: equivalent to -H -f -t -l error -l selftest\n");
  printout(LOG_INFO,"  -F      Fix byte order in some SMART data (some Samsung disks)\n");
  printout(LOG_INFO,"   #      Comment: text after a hash sign is ignored\n");
  printout(LOG_INFO,"   \\      Line continuation character\n");
  printout(LOG_INFO,"Attribute ID is a decimal integer 1 <= ID <= 255\n");
  printout(LOG_INFO,"SCSI devices: only -d, -m, and -M Directives allowed.\n");
  printout(LOG_INFO,"Example: /dev/hda -a\n");
return;
}

/* prints help information for command syntax */
void Usage (void){
  printout(LOG_INFO,"Usage: smartd [options]\n\n");
#ifdef HAVE_GETOPT_LONG
  printout(LOG_INFO,"Command Line Options:\n");
  printout(LOG_INFO,"  -d, --debug\n  Start smartd in debug mode\n\n");
  printout(LOG_INFO,"  -D, --showdirectives\n");
  printout(LOG_INFO,"  Print the configuration file Directives and exit\n\n");
  printout(LOG_INFO,"  -r, --report=TYPE\n");
  printout(LOG_INFO,"  Report transactions for one of: %s\n\n", getvalidarglist('r'));
  printout(LOG_INFO,"  -i N, --interval=N\n");
  printout(LOG_INFO,"  Set interval between disk checks to N seconds, where N >= 10\n\n");
  printout(LOG_INFO,"  -c, --checkonce\n  Check all devices once, then exit\n\n");
  printout(LOG_INFO,"  -p NAME, --pidfile=NAME\n  Write PID file NAME\n\n");
  printout(LOG_INFO,"  -V, --version, --license, --copyright\n");
  printout(LOG_INFO,"  Print License, Copyright, and version information\n\n");
  printout(LOG_INFO,"  -h, -?, --help, --usage\n  Display this help and exit\n\n");
#else
  printout(LOG_INFO,"Command Line Options:\n");
  printout(LOG_INFO,"  -d      Start smartd in debug mode\n");
  printout(LOG_INFO,"  -D      Print the configuration file Directives and exit\n");
  printout(LOG_INFO,"  -r TYPE Report transactions for one of: %s\n", getvalidarglist('r'));
  printout(LOG_INFO,"  -p NAME\n  Write PID file NAME\n\n");
  printout(LOG_INFO,"  -i N    Set interval between disk checks to N seconds, where N >= 10\n");
  printout(LOG_INFO,"  -V      Print License, Copyright, and version information\n");
  printout(LOG_INFO,"  -c      Check all devices once, then exit\n");
  printout(LOG_INFO,"  -h      Display this help and exit\n");
  printout(LOG_INFO,"  -?      Same as -h\n");
#endif
}

// returns negative if problem, else fd>=0
int opendevice(char *device){
  int fd = open(device, O_RDWR);
  
  // open device - read-write access is needed to use the scsi generic
  // (sg) device for some commands (e.g. '-s on'). Attempt to open
  // read-write and if that fails with an error suggesting writing is
  // not permitted, fall back to a read-only open. [When opened
  // O_RDONLY invoking '-s on' will attempt the scsi command MODE
  // SELECT. Sg disallows it since that scsi command potentially
  // modifies mode page data.]  
  if (fd<0 && ((EACCES == errno) || (EROFS == errno)))
    fd = open(device, O_RDONLY);  
  
  if (fd<0) {
    printout(LOG_INFO,"Device: %s, %s, open() failed\n",device, strerror(errno));
    return -1;
  }

  // device opened sucessfully
  return fd;
}

int closedevice(int fd, char *name){
  if (close(fd)){
    printout(LOG_INFO,"Device: %s, %s, close(%d) failed\n", name, strerror(errno), fd);
    return 1;
  }
  // device sucessfully closed
  return 0;
}

// returns <0 on failure
int ataerrorcount(int fd, char *name){
  struct ata_smart_errorlog log;
  
  if (-1==ataReadErrorLog(fd,&log)){
    printout(LOG_INFO,"Device: %s, Read SMART Error Log Failed\n",name);
    return -1;
  }
  
  // return current number of ATA errors
  return log.error_log_pointer?log.ata_error_count:0;
}

// returns <0 if problem
int selftesterrorcount(int fd, char *name){
  struct ata_smart_selftestlog log;

  if (-1==ataReadSelfTestLog(fd,&log)){
    printout(LOG_INFO,"Device: %s, Read SMART Self Test Log Failed\n",name);
    return -1;
  }
  
  // return current number of self-test errors
  return ataPrintSmartSelfTestlog(&log,0);
}



// scan to see what ata devices there are, and if they support SMART
int atadevicescan2(atadevices_t *devices, cfgfile *cfg){
  int fd;
  struct hd_driveid drive;
  char *device=cfg->name;
  
  // should we try to register this as an ATA device?
  if (!(cfg->tryata))
    return 1;
  
  // open the device
  if ((fd=opendevice(device))<0)
    // device open failed
    return 1;
  printout(LOG_INFO,"Device: %s, opened\n", device);
  
  // Get drive identity structure
  if (ataReadHDIdentity (fd,&drive)){
    // Unable to read Identity structure
    printout(LOG_INFO,"Device: %s, unable to read Device Identity Structure\n",device);
    close(fd);
    return 2; 
  }
  
  // If requested, show which presets would be used for this drive and exit.
  if (cfg->showpresets) {
    debugmode = TRUE;
    pout("Presets for %s are:\n", device);
    showpresets(&drive);
    exit(0);
  }

  // Use preset vendor attribute options unless user has requested otherwise.
  if (!cfg->ignorepresets)
    applypresets(&drive, cfg->attributedefs, con);

  // Now check whether applypresets() has set con->reversesamsung.  This is
  // messy, but we shouldn't have to do it often.
  cfg->reversesamsung = con->reversesamsung;

  if (!cfg->permissive && !ataSmartSupport(&drive)){
    // SMART not supported
    printout(LOG_INFO,"Device: %s, appears to lack SMART, use '-T permissive' Directive to try anyway.\n",device);
    close(fd);
    return 2; 
  }
  
  if (ataEnableSmart(fd)){
    // Enable SMART command has failed
    printout(LOG_INFO,"Device: %s, could not enable SMART capability\n",device);
    close(fd);
    return 2; 
  }
  
  // disable device attribute autosave...
  if (cfg->autosave==1){
    if (ataDisableAutoSave(fd))
      printout(LOG_INFO,"Device: %s, could not disable SMART Attribute Autosave.\n",device);
    else
      printout(LOG_INFO,"Device: %s, disabled SMART Attribute Autosave.\n",device);
  }

  // or enable device attribute autosave
  if (cfg->autosave==2){
    if (ataEnableAutoSave(fd))
      printout(LOG_INFO,"Device: %s, could not enable SMART Attribute Autosave.\n",device);
    else
      printout(LOG_INFO,"Device: %s, enabled SMART Attribute Autosave.\n",device);
  }

  // capability check: SMART status
  if (cfg->smartcheck && ataSmartStatus2(fd)==-1){
    printout(LOG_INFO,"Device: %s, not capable of SMART Health Status check\n",device);
    cfg->smartcheck=0;
  }
  
  // capability check: Read smart values and thresholds
  if (cfg->usagefailed || cfg->prefail || cfg->usage || cfg->autoofflinetest) {
    devices->smartval=(struct ata_smart_values *)calloc(1,sizeof(struct ata_smart_values));
    devices->smartthres=(struct ata_smart_thresholds *)calloc(1,sizeof(struct ata_smart_thresholds));
    
    if (!devices->smartval || !devices->smartthres){
      printout(LOG_CRIT,"Not enough memory to obtain SMART data\n");
      exit(1);
    }
    
    if (ataReadSmartValues(fd,devices->smartval) ||
        ataReadSmartThresholds (fd,devices->smartthres)){
      printout(LOG_INFO,"Device: %s, Read SMART Values and/or Thresholds Failed\n",device);
      free(devices->smartval);
      free(devices->smartthres);

      // make it easy to recognize that we've deallocated
      devices->smartval=NULL;
      devices->smartthres=NULL;
      cfg->usagefailed=cfg->prefail=cfg->usage=0;
    }
  }

  // disable automatic on-line testing
  if (cfg->autoofflinetest==1){
    if (devices->smartval && isSupportAutomaticTimer(devices->smartval) && !ataDisableAutoOffline(fd))
      printout(LOG_INFO,"Device: %s, disabled SMART Automatic Offline Testing .\n",device);
    else
      printout(LOG_INFO,"Device: %s, could not disable SMART Automatic Offline Testing.\n",device);
  }

  // enable automatic on-line testing
  if (cfg->autoofflinetest==2){
    if (devices->smartval && isSupportAutomaticTimer(devices->smartval) && !ataDisableAutoOffline(fd))
      printout(LOG_INFO,"Device: %s, enabled SMART Automatic Offline Testing.\n",device);
    else
      printout(LOG_INFO,"Device: %s, could not enable SMART Automatic Offline Testing.\n",device);
  }

  // capability check: self-test-log
  if (cfg->selftest){
    int val;

    // fix bug in Samsung firmware
    con->reversesamsung=cfg->reversesamsung;
    
    // get number of Self-test errors logged
    val=selftesterrorcount(fd, device);
    if (val>=0)
      cfg->selflogcount=val;
    else
      cfg->selftest=0;
  }
  
  // capability check: ATA error log
  if (cfg->errorlog){
    int val;

    // fix bug in Samsung firmware
    con->reversesamsung=cfg->reversesamsung;
    
    // get number of ATA errors logged
    val=ataerrorcount(fd, device);
    if (val>=0)
      cfg->ataerrorcount=val;
    else
      cfg->errorlog=0;
  }
  
  // If not tests available or selected, return
  if (!(cfg->errorlog || cfg->selftest || cfg->smartcheck || 
        cfg->usagefailed || cfg->prefail || cfg->usage)) {
    close(fd);
    return 3;
  }
  
  // Do we still have entries available?
  if (numatadevices>=MAXATADEVICES){
    printout(LOG_CRIT,"smartd has found more than MAXATADEVICES=%d ATA devices.\n"
             "Recompile code from " PROJECTHOME " with larger MAXATADEVICES\n",(int)numatadevices);
    exit(1);
  }
  
  // register device
  printout(LOG_INFO,"Device: %s, is SMART capable. Adding to \"monitor\" list.\n",device);
  
  // we were called from a routine that has global storage for the name.  Keep pointer.
  devices->devicename=device;
  devices->cfg=cfg;
  
  // record number of device, type of device, increment device count
  cfg->tryscsi=0;
  cfg->tryata=1;
  cfg->atadevicenum=numatadevices;
  cfg->scsidevicenum=-1;
  numatadevices++;

  // close file descriptor
  closedevice(fd, device);
  return 0;
}


static int scsidevicescan(scsidevices_t *devices, cfgfile *cfg)
{
    int k, fd, err; 
    char *device = cfg->name;
    struct scsi_iec_mode_page iec;
    UINT8  tBuf[64];

    // should we try to register this as a SCSI device?
    if (! cfg->tryscsi)
        return 1;
    // open the device
    if ((fd = opendevice(device)) < 0) {
        printout(LOG_WARNING, "Device: %s, skip\n", device);
        return 0; // device open failed
    }
    printout(LOG_INFO,"Device: %s, opened\n", device);
  
    // check that it's ready for commands. IE stores its stuff on the media.
    if ((err = scsiTestUnitReady(fd))) {
        if (1 == err) {
            printout(LOG_WARNING, "Device: %s, NOT READY (media absent, spun "
                     "down); skip\n", device);
            close(fd);
            return 0;
        } else {
           printout(LOG_ERR, "Device: %s, failed Test Unit Ready [err=%d]\n", 
                    device, err);
           close(fd);
           return 2;
        }
    }
  
    if ((err = scsiFetchIECmpage(fd, &iec))) {
        printout(LOG_WARNING, "Device: %s, Fetch of IEC (SMART) mode page "
                 "failed, err=%d, skip device\n", device, err);
        return 0;
    }
    if (! scsi_IsExceptionControlEnabled(&iec)) {
        printout(LOG_WARNING, "Device: %s, IE (SMART) not enabled, "
                 "skip device\n", device);
        close(fd);
        return 0;
    }

    // Device exists, and does SMART.  Add to list
    if (numscsidevices >= MAXSCSIDEVICES) {
        printout(LOG_ERR, "smartd has found more than MAXSCSIDEVICES=%d "
                 "SCSI devices.\n" "Recompile code from " PROJECTHOME 
                 " with larger MAXSCSIDEVICES\n", (int)numscsidevices);
        return 0;
    }

    // now we can proceed to register the device
    printout(LOG_INFO, "Device: %s, is SMART capable. Adding "
             "to \"monitor\" list.\n",device);
 
    // since device points to global memory, just keep that address
    devices->devicename = device;
    devices->cfg = cfg;

    // Flag that certain log pages are supported (information may be
    // available from other sources).
    if (0 == scsiLogSense(fd, SUPPORTED_LOG_PAGES, tBuf, sizeof(tBuf))) {
        for (k = 4; k < tBuf[3] + LOGPAGEHDRSIZE; ++k) {
            switch (tBuf[k]) { 
                case TEMPERATURE_PAGE:
                    devices->TempPageSupported = 1;
                    break;
                case IE_LOG_PAGE:
                    devices->SmartPageSupported = 1;
                    break;
                default:
                    break;
            }
        }   
    }

    // record number of device, type of device, increment device count
    cfg->tryata = 0;
    cfg->tryscsi = 1;
    cfg->scsidevicenum = numscsidevices;
    cfg->atadevicenum = -1;
    ++numscsidevices;

    // close file descriptor
    closedevice(fd, device);
    return 0;
}

// We compare old and new values of the n'th attribute.  Note that n
// is NOT the attribute ID number.. If (Normalized & Raw) equal,
// then return 0, else nonzero.
int  ataCompareSmartValues(changedattribute_t *delta,
                            struct ata_smart_values *new,
                            struct ata_smart_values *old,
                            struct ata_smart_thresholds *thresholds,
                            int n, char *name){
  struct ata_smart_attribute *now,*was;
  struct ata_smart_threshold_entry *thre;
  unsigned char oldval,newval;
  int sameraw;

  // check that attribute number in range, and no null pointers
  if (n<0 || n>=NUMBER_ATA_SMART_ATTRIBUTES || !new || !old || !thresholds)
    return 0;
  
  // pointers to disk's values and vendor's thresholds
  now=new->vendor_attributes+n;
  was=old->vendor_attributes+n;
  thre=thresholds->thres_entries+n;

  // consider only valid attributes
  if (!now->id || !was->id || !thre->id)
    return 0;
  
  
  // issue warning if they don't have the same ID in all structures:
  if ( (now->id != was->id) || (now->id != thre->id) ){
    printout(LOG_INFO,"Device: %s, same Attribute has different ID numbers: %d = %d = %d\n",
             name, (int)now->id, (int)was->id, (int)thre->id);
    return 0;
  }

  // new and old values of Normalized Attributes
  newval=now->current;
  oldval=was->current;

  // See if the RAW values are unchanged (ie, the same)
  if (memcmp(now->raw, was->raw, 6))
    sameraw=0;
  else
    sameraw=1;
  
  // if any values out of the allowed range, or if the values haven't
  // changed, return 0
  if (!newval || !oldval || newval>0xfe || oldval>0xfe || (oldval==newval && sameraw))
    return 0;
  
  // values have changed.  Construct output and return
  delta->newval=newval;
  delta->oldval=oldval;
  delta->id=now->id;
  delta->prefail=now->status.flag.prefailure;
  delta->sameraw=sameraw;

  return 1;
}

// This looks to see if the corresponding bit of the 32 bytes is set.
// This wastes a few bytes of storage but eliminates all searching and
// sorting functions! Entry is ZERO <==> the attribute ON. Calling
// with set=0 tells you if the attribute is being tracked or not.
// Calling with set=1 turns the attribute OFF.
int isattoff(unsigned char attr,unsigned char *data, int set){
  // locate correct attribute
  int loc=attr>>3;
  int bit=attr & 0x07;
  unsigned char mask=0x01<<bit;

  // attribute zero is always OFF
  if (!attr)
    return 1;

  if (!set)
    return (data[loc] & mask);
  
  data[loc]|=mask;
  // return value when setting makes no sense!
  return 0;
}


int ataCheckDevice(atadevices_t *drive){
  int fd,i;
  char *name=drive->devicename;
  cfgfile *cfg=drive->cfg;
  
  // If user has asked, test the email warning system
  if (cfg->emailtest){
    printandmail(cfg, 0, LOG_CRIT, "TEST EMAIL from smartd for device: %s", drive->devicename);
  }

  // if we can't open device, fail gracefully rather than hard --
  // perhaps the next time around we'll be able to open it
  if ((fd=opendevice(name))<0){
    printandmail(cfg, 9, LOG_CRIT, "Device: %s, unable to open device", name);
    return 1;
  }

  // check smart status
  if (cfg->smartcheck){
    int status=ataSmartStatus2(fd);
    if (status==-1){
      printout(LOG_INFO,"Device: %s, not capable of SMART self-check\n",name);
      printandmail(cfg, 5, LOG_CRIT, "Device: %s, not capable of SMART self-check", name);
    }
    else if (status==1){
      printout(LOG_CRIT, "Device: %s, FAILED SMART self-check. BACK UP DATA NOW!\n", name);
      printandmail(cfg, 1, LOG_CRIT, "Device: %s, FAILED SMART self-check. BACK UP DATA NOW!", name);
    }
  }
  
  // Check everything that depends upon SMART Data (eg, Attribute values)
  if (cfg->usagefailed || cfg->prefail || cfg->usage){
    struct ata_smart_values     curval;
    struct ata_smart_thresholds *thresh=drive->smartthres;
    
    // Read current attribute values. *drive contains old values and thresholds
    if (ataReadSmartValues(fd,&curval)){
      printout(LOG_CRIT, "Device: %s, failed to read SMART Attribute Data\n", name);
      printandmail(cfg, 6, LOG_CRIT, "Device: %s, failed to read SMART Attribute Data", name);
    }
    else {  
      // look for failed usage attributes, or track usage or prefail attributes
      for (i=0; i<NUMBER_ATA_SMART_ATTRIBUTES; i++){
        int att;
        changedattribute_t delta;


        // This block looks for usage attributes that have failed.
        // Prefail attributes that have failed are returned with a
        // positive sign. No failure returns 0. Usage attributes<0.
        if (cfg->usagefailed && ((att=ataCheckAttribute(&curval, thresh, i))<0)){
          
          // are we ignoring failures of this attribute?
          att *= -1;
          if (!isattoff(att, cfg->monitorattflags, 0)){
            char attname[64], *loc=attname;
            
            // get attribute name & skip white space
            ataPrintSmartAttribName(loc, att, cfg->attributedefs[att]);
            while (*loc && *loc==' ') loc++;
            
            // warning message
            printout(LOG_CRIT, "Device: %s, Failed SMART usage Attribute: %s.\n", name, loc);
            printandmail(cfg, 2, LOG_CRIT, "Device: %s, Failed SMART usage Attribute: %s.", name, loc);
          }
        }
        
        // This block tracks usage or prefailure attributes to see if
        // they are changing.  It also looks for changes in RAW values
        // if this has been requested by user.
        if ((cfg->usage || cfg->prefail) && ataCompareSmartValues(&delta, &curval, drive->smartval, thresh, i, name)){
          unsigned char id=delta.id;

          // if the only change is the raw value, and we're not
          // tracking raw value, then continue loop over attributes
          if (!delta.sameraw && delta.newval==delta.oldval && !isattoff(id, cfg->monitorattflags+96, 0))
            continue;

          // are we tracking this attribute?
          if (!isattoff(id, cfg->monitorattflags+32, 0)){
            char newrawstring[64], oldrawstring[64], attname[64], *loc=attname;

            // get attribute name, skip spaces
            ataPrintSmartAttribName(loc, id, cfg->attributedefs[id]);
            while (*loc && *loc==' ') loc++;
            
            // has the user asked for us to print raw values?
            if (isattoff(id, cfg->monitorattflags+64, 0)) {
              // get raw values (as a string) and add to printout
              char rawstring[64];
              ataPrintSmartAttribRawValue(rawstring, curval.vendor_attributes+i, cfg->attributedefs);
              sprintf(newrawstring, " [Raw %s]", rawstring);
              ataPrintSmartAttribRawValue(rawstring, drive->smartval->vendor_attributes+i, cfg->attributedefs);
              sprintf(oldrawstring, " [Raw %s]", rawstring);
            }
            else
              newrawstring[0]=oldrawstring[0]='\0';

            // prefailure attribute
            if (cfg->prefail && delta.prefail)
              printout(LOG_INFO, "Device: %s, SMART Prefailure Attribute: %s changed from %d%s to %d%s\n",
                       name, loc, delta.oldval, oldrawstring, delta.newval, newrawstring);

            // usage attribute
            if (cfg->usage && !delta.prefail)
              printout(LOG_INFO, "Device: %s, SMART Usage Attribute: %s changed from %d%s to %d%s\n",
                       name, loc, delta.oldval, oldrawstring, delta.newval, newrawstring);
          }
        } // endof block tracking usage or prefailure
      } // end of loop over attributes
     
      // Save the new values into *drive for the next time around
      *drive->smartval=curval;
    } 
  }
  
  // check if number of selftest errors has increased (note: may also DECREASE)
  if (cfg->selftest){
    int new;
    unsigned char old=cfg->selflogcount;
    
    // fix bug in Samsung firmware
    con->reversesamsung=cfg->reversesamsung;

    // new self test error count
    new=selftesterrorcount(fd, name);
    
    // did command fail?
    if (new<0)
      printandmail(cfg, 8, LOG_CRIT, "Device: %s, Read SMART Self Test Log Failed", name);
    
    // hsa self-test error count increased?
    if (new>old){
      printout(LOG_CRIT, "Device: %s, Self-Test Log error count increased from %d to %d\n",
               name, (int)old, new);
      printandmail(cfg, 3, LOG_CRIT, "Device: %s, Self-Test Log error count increased from %d to %d",
                   name, (int)old, new);
    }

    // Needed since self-test error count may  DECREASE
    if (new>=0)
      cfg->selflogcount=new;
  }

  
  // check if number of ATA errors has increased
  if (cfg->errorlog){

    int new,old=cfg->ataerrorcount;

    // fix bug in Samsung firmware
    con->reversesamsung=cfg->reversesamsung;

    // new number of errors
    new=ataerrorcount(fd, name);

    // did command fail?
    if (new<0)
      printandmail(cfg, 7, LOG_CRIT, "Device: %s, Read SMART Error Log Failed", name);
  
    // has error count increased?
    if (new>old){
      printout(LOG_CRIT, "Device: %s, ATA error count increased from %d to %d\n",
               name, old, new);
      printandmail(cfg, 4, LOG_CRIT, "Device: %s, ATA error count increased from %d to %d",
                   name, old, new);
    }
    
    // this last line is probably not needed, count always increases
    if (new>=0)
      cfg->ataerrorcount=new;
  }
  
  // Don't leave device open -- the OS/user may want to access it
  // before the next smartd cycle!
  closedevice(fd, name);
  return 0;
}


int scsiCheckDevice(scsidevices_t *drive)
{
    UINT8 asc, ascq;
    UINT8 currenttemp;
    int fd;
    cfgfile *cfg=drive->cfg;
    char *name=drive->devicename;
    const char *cp;

    // If the user has asked for it, test the email warning system
    if (cfg->emailtest)
        printandmail(cfg, 0, LOG_CRIT, 
                     "TEST EMAIL from smartd for device: %s", name);

    // if we can't open device, fail gracefully rather than hard --
    // perhaps the next time around we'll be able to open it
    if ((fd=opendevice(name))<0) {
        printandmail(cfg, 9, LOG_CRIT, "Device: %s, unable to open device",
                      name);
        return 1;
    }
    currenttemp = 0;
    asc = 0;
    ascq = 0;
    if (scsiCheckIE(fd, drive->SmartPageSupported, drive->TempPageSupported,
                    &asc, &ascq, &currenttemp)) {
        printout(LOG_INFO, "Device: %s, failed to read SMART values\n", name);
        printandmail(cfg, 6, LOG_CRIT, 
                     "Device: %s, failed to read SMART values", name);
    }
    if (asc > 0) {
        cp = scsiGetIEString(asc, ascq);
        if (cp) {
            printout(LOG_CRIT, "Device: %s, SMART Failure: %s\n", name, cp);
            printandmail(cfg, 1, LOG_CRIT, "Device: %s, SMART Failure: %s",
                         name, cp); 
        }
    } else if (debugmode)
        printout(LOG_INFO,"Device: %s, Acceptable asc,ascq: %d,%d\n", 
                 name, (int)asc, (int)ascq);  
  
    // Seems to completely ignore what capabilities were found on the
    // device when scanned
    if (currenttemp) {
        if (255 == currenttemp) /* this means temperature unavailable */
            currenttemp = 0;    /* less likely to worry people */
        if ((currenttemp != drive->Temperature) && (drive->Temperature))
            printout(LOG_INFO, "Device: %s, Temperature changed %d degrees "
                     "to %d degrees since last reading\n", name, 
                     (int)(currenttemp - drive->Temperature), 
                     (int)currenttemp);
        drive->Temperature = currenttemp;
    }
    closedevice(fd, name);
    return 0;
}

void CheckDevices(atadevices_t *atadevices, scsidevices_t *scsidevices){
  static int firstpass=1;
  int i;

  // Infinite loop, which checks devices
  printout(LOG_INFO,"Started monitoring %d ATA and %d SCSI devices\n",numatadevices,numscsidevices);
  while (1){
    for (i=0; i<numatadevices; i++) 
      ataCheckDevice(atadevices+i);
    
    for (i=0; i<numscsidevices; i++)
      scsiCheckDevice(scsidevices+i);

    // This option is primarily for distribution developers who want
    // an automated procedure for seeing if smartd works correctly.
    // Use the -c/--checkonce option and verify zero exit status.
    if (checkonce) {
      printout(LOG_INFO,"Started with '-c' option. All devices sucessfully checked once.\n");
      exit(0);
    }

    // Initialization setup
    if (firstpass){
      
      // If in background as a daemon, fork and close file descriptors
      if (!debugmode)
	daemon_init();
      
      // install goobye message and remove pidfile handler
      atexit(goodbye);
      
      // write PID file only after installing exit handler
      if (!debugmode)
	write_pid_file();
      
      // install signal handlers
      if (signal(SIGINT, sighandler)==SIG_IGN)
	signal(SIGINT, SIG_IGN);
      if (signal(SIGTERM, sighandler)==SIG_IGN)
	signal(SIGTERM, SIG_IGN);
      if (signal(SIGQUIT, sighandler)==SIG_IGN)
	signal(SIGQUIT, SIG_IGN);
      if (signal(SIGHUP, huphandler)==SIG_IGN)
	signal(SIGHUP, SIG_IGN);
      if (signal(SIGUSR1, sleephandler)==SIG_IGN)
	signal(SIGUSR1, SIG_IGN);
            
      // done with initialization setup
      firstpass=0;
    }

    // Unix Gurus: I know that this can be done better.  Please tell
    // me how -- use email address for Bruce Allen at the top of this
    // file. Search for "sleeptime" to see what I am doing.  I think
    // that when done "right" I should not have to call sleep once per
    // second, but just set an alarm for checktime in the future, and
    // then have an additional alarm sent if the user does SIGUSR1,
    // which arrives first to cause another device check.  Please help
    // me out.
    
    // Sleep until next check. Note that since sleeptime can be set to
    // zero by an EXTERNAL signal SIGUSR1, it's possible for sleeptime
    // to be negative.  Don't use while (sleeptime)!
    sleeptime=checktime;
    while (sleeptime-->0)
      sleep(1); 
  }
}

// Print out a list of valid arguments for the Directive d
void printoutvaliddirectiveargs(int priority, char d) {
  char *s;

  switch (d) {
  case 'd':
    printout(priority, "ata, scsi");
    break;
  case 'T':
    printout(priority, "normal, permissive");
    break;
  case 'o':
  case 'S':
    printout(priority, "on, off");
    break;
  case 'l':
    printout(priority, "error, selftest");
    break;
  case 'M':
    printout(priority, "\"once\", \"daily\", \"diminishing\", \"test\", \"exec\"");
    break;
  case 'v':
    if (!(s = create_vendor_attribute_arg_list())) {
      printout(LOG_CRIT,"Insufficient memory to construct argument list\n");
      break;
    }
    printout(priority, "\n%s\n", s);
    free(s);
    break;
  case 'P':
    printout(priority, "use, ignore, show, showall");
    break;
  }
}

char copyleftstring[]=
"smartd comes with ABSOLUTELY NO WARRANTY. This\n"
"is free software, and you are welcome to redistribute it\n"
"under the terms of the GNU General Public License Version 2.\n"
"See http://www.gnu.org for further details.\n\n";

cfgfile config[MAXENTRIES];

// exits with an error message, or returns integer value of token
int inttoken(char *arg, char *name, char *token, int lineno, char *configfile, int min, int max){
  char *endptr;
  int val;
  
  // make sure argument is there
  if (!arg) {
    printout(LOG_CRIT,"File %s line %d (drive %s): Directive: %s takes integer argument from %d to %d.\n",
             configfile, lineno, name, token, min, max);
    Directives();
    exit(1);
  }
  
  // get argument value (base 10), check that it's integer, and in-range
  val=strtol(arg,&endptr,10);
  if (*endptr!='\0' || val<min || val>max )  {
    printout(LOG_CRIT,"File %s line %d (drive %s): Directive: %s has argument: %s; needs integer from %d to %d.\n",
             configfile, lineno, name, token, arg, min, max);
    Directives();
    exit(1);
  }

  // all is well; return value
  return val;
}

// This function returns non-zero if it has correctly parsed a token,
// else zero if it has failed to parse a token.  Or it exits with a
// Directive message if there is a token-parsing problem.
int parsetoken(char *token,cfgfile *cfg){
  char sym;
  char *name=cfg->name;
  int lineno=cfg->lineno;
  char *delim = " \n\t";
  int badarg = 0;
  int missingarg = 0;
  char *arg = NULL;

  // is the rest of the line a comment
  if (*token=='#')
    return 1;
  
  // is the token not recognized?
  if (*token!='-' || strlen(token)!=2) {
    printout(LOG_CRIT,"File %s line %d (drive %s): unknown Directive: %s\n",
             CONFIGFILE, lineno, name, token);
    Directives();
    exit(1);
  }
  
  // let's parse the token and swallow its argument
  switch (sym=token[1]) {
    int val;

  case 'T':
    // Set tolerance level for SMART command failures
    if ((arg = strtok(NULL, delim)) == NULL) {
      missingarg = 1;
    } else if (!strcmp(arg, "normal")) {
      // Normal mode: exit on failure of a mandatory S.M.A.R.T. command, but
      // not on failure of an optional S.M.A.R.T. command.
      // This is the default so we don't need to actually do anything here.
      ;
    } else if (!strcmp(arg, "permissive")) {
      // Permissive mode; ignore errors from Mandatory SMART commands
      cfg->permissive = 1;
    } else {
      badarg = 1;
    }
    break;
  case 'd':
    // specify the device type
    if ((arg = strtok(NULL, delim)) == NULL) {
      missingarg = 1;
    } else if (!strcmp(arg, "ata")) {
      cfg->tryata  = 1;
      cfg->tryscsi = 0;
    } else if (!strcmp(arg, "scsi")) {
      cfg->tryscsi = 1;
      cfg->tryata  = 0;
    } else {
      badarg = 1;
    }
    break;
  case 'F':
    // fix bug in Samsung Firmware
    cfg->reversesamsung=1;
    break;
  case 'H':
    // check SMART status
    cfg->smartcheck=1;
    break;
  case 'f':
    // check for failure of usage attributes
    cfg->usagefailed=1;
    break;
  case 't':
    // track changes in all vendor attributes
    cfg->prefail=1;
    cfg->usage=1;
    break;
  case 'p':
    // track changes in prefail vendor attributes
    cfg->prefail=1;
    break;
  case 'u':
    //  track changes in usage vendor attributes
    cfg->usage=1;
    break;
  case 'l':
    // track changes in SMART logs
    if ((arg = strtok(NULL, delim)) == NULL) {
      missingarg = 1;
    } else if (!strcmp(arg, "selftest")) {
      // track changes in self-test log
      cfg->selftest=1;
    } else if (!strcmp(arg, "error")) {
      // track changes in ATA error log
      cfg->errorlog=1;
    } else {
      badarg = 1;
    }
    break;
  case 'a':
    // monitor everything
    cfg->smartcheck=1;
    cfg->prefail=1;
    cfg->usagefailed=1;
    cfg->usage=1;
    cfg->selftest=1;
    cfg->errorlog=1;
    break;
  case 'o':
    if ((arg = strtok(NULL, delim)) == NULL) {
      missingarg = 1;
    } else if (!strcmp(arg, "on")) {
      cfg->autoofflinetest = 2;
    } else if (!strcmp(arg, "off")) {
      cfg->autoofflinetest = 1;
    } else {
      badarg = 1;
    }
    break;
  case 'S':
    if ((arg = strtok(NULL, delim)) == NULL) {
      missingarg = 1;
    } else if (!strcmp(arg, "on")) {
      cfg->autosave = 2;
    } else if (!strcmp(arg, "off")) {
      cfg->autosave = 1;
    } else {
      badarg = 1;
    }
    break;
  case 'M':
    // email warning option
    if ((arg = strtok(NULL, delim)) == NULL) {
      missingarg = 1;
    } else if (!strcmp(arg, "once")) {
      cfg->emailfreq = 1;
    } else if (!strcmp(arg, "daily")) {
      cfg->emailfreq = 2;
    } else if (!strcmp(arg, "diminishing")) {
      cfg->emailfreq = 3;
    } else if (!strcmp(arg, "test")) {
      cfg->emailtest = 1;
    } else if (!strcmp(arg, "exec")) {
      // Get the next argument (the command line)
      if ((arg = strtok(NULL, delim)) == NULL) {
        printout(LOG_CRIT, "File %s line %d (drive %s): Directive %s 'exec' argument must be followed by executable path.\n",
                 CONFIGFILE, lineno, name, token);
        Directives();
        exit(1);
      }
      // Free the last cmd line given if any
      if (cfg->emailcmdline) {
        printout(LOG_INFO, "File %s line %d (drive %s): found multiple -M exec Directives on line - ignoring all but the last\n", CONFIGFILE, lineno, name);
        free(cfg->emailcmdline);
      }
      // Attempt to copy the argument
      if (!(cfg->emailcmdline = strdup(arg))) {
        printout(LOG_CRIT, "File %s line %d (drive %s): no free memory for command line argument to exec: %s\n",
          CONFIGFILE, lineno, name, arg);
          Directives();
          exit(1);
      }
    } else {
      badarg = 1;
    }
    break;
  case 'i':
    // ignore failure of usage attribute
    val=inttoken(arg=strtok(NULL,delim), name, token, lineno, CONFIGFILE, 1, 255);
    isattoff(val,cfg->monitorattflags,1);
    break;
  case 'I':
    // ignore attribute for tracking purposes
    val=inttoken(arg=strtok(NULL,delim), name, token, lineno, CONFIGFILE, 1, 255);
    isattoff(val,cfg->monitorattflags+32,1);
    break;
  case 'r':
    // print raw value when tracking
    val=inttoken(arg=strtok(NULL,delim), name, token, lineno, CONFIGFILE, 1, 255);
    isattoff(val,cfg->monitorattflags+64,1);
    break;
  case 'R':
    // track changes in raw value (forces printing of raw value)
    val=inttoken(arg=strtok(NULL,delim), name, token, lineno, CONFIGFILE, 1, 255);
    isattoff(val,cfg->monitorattflags+64,1);
    isattoff(val,cfg->monitorattflags+96,1);
    break;
  case 'm':
    // send email to address that follows
    if ((arg = strtok(NULL,delim)) == NULL) {
      printout(LOG_CRIT,"File %s line %d (drive %s): Directive: %s needs email address(es)\n",
               CONFIGFILE, lineno, name, token);
      Directives();
      exit(1);
    }
    if (!(cfg->address=strdup(arg))){
      printout(LOG_CRIT,"File %s line %d (drive %s): Directive: %s: no free memory for email address(es) %s\n",
               CONFIGFILE, lineno, name, token, arg);
      Directives();
      exit(1);
    }
    break;
  case 'v':
    // non-default vendor-specific attribute meaning
    if ((arg=strtok(NULL,delim)) == NULL) {
      missingarg = 1;
    } else if (parse_attribute_def(arg, cfg->attributedefs)){   
      badarg = 1;
    }
    break;
  case 'P':
    // Define use of drive-specific presets.
    if ((arg = strtok(NULL, delim)) == NULL) {
      missingarg = 1;
    } else if (!strcmp(arg, "use")) {
      cfg->ignorepresets = FALSE;
    } else if (!strcmp(arg, "ignore")) {
      cfg->ignorepresets = TRUE;
    } else if (!strcmp(arg, "show")) {
      cfg->showpresets = TRUE;
    } else if (!strcmp(arg, "showall")) {
      debugmode = TRUE;
      showallpresets();
      exit(0);
    } else {
      badarg = 1;
    }
    break;
  default:
    // Directive not recognized
    printout(LOG_CRIT,"File %s line %d (drive %s): unknown Directive: %s\n",
             CONFIGFILE, lineno, name, token);
    Directives();
    exit(1);
  }
  if (missingarg) {
    printout(LOG_CRIT, "File %s line %d (drive %s): Missing argument to Directive: %s\n", CONFIGFILE, lineno, name, token);
  }
  if (badarg) {
    printout(LOG_CRIT, "File %s line %d (drive %s): Invalid argument: %s\n", CONFIGFILE, lineno, name, arg);
  }
  if (missingarg || badarg) {
      printout(LOG_CRIT, "Valid arguments to %s Directive are: ", token);
      printoutvaliddirectiveargs(LOG_CRIT, sym);
      printout(LOG_CRIT, "\n");
      Directives();
      exit(1);
  }
  return 1;
}

int parseconfigline(int entry, int lineno,char *line){
  char *token,*copy;
  char *name;
  char *delim = " \n\t";
  int len;
  cfgfile *cfg;
  static int numtokens=0;
  int devscan=0;

  if (!(copy=strdup(line))){
    printout(LOG_INFO,"No memory to parse file: %s line %d, %s\n", CONFIGFILE, lineno, strerror(errno));
    exit(1);
  }
  
  // get first token -- device name
  if (!(name=strtok(copy,delim)) || *name=='#') {
    free(copy);
    return 0;
  }

  // Have we detected the DEVICESCAN directive?
  if (!strcmp(SCANDIRECTIVE,name)){
    devscan=1;
    if (numtokens) {
      printout(LOG_INFO,"Scan Directive %s must be the first entry in %s\n",name,CONFIGFILE);
      exit(1);
    }
    else
      printout(LOG_INFO,"Scan Directive %s found in %s. Will scan for devices.\n",name,CONFIGFILE);
  }
  numtokens++;

  // Is there space for another entry?
  if (entry>=MAXENTRIES){
    printout(LOG_CRIT,"Error: configuration file %s can have no more than MAXENTRIES=%d entries\n",
             CONFIGFILE,MAXENTRIES);
    exit(1);
  }

  // We've got a legit entry, clear structure
  cfg=config+entry;
  memset(cfg,0,sizeof(*config));

  // Save info to process memory for after forking 32 bytes contains 1
  // bit per possible attribute ID.  See isattoff()
  cfg->name=strdup(name);
  if (!devscan){
    cfg->monitorattflags=(unsigned char *)calloc(NMONITOR*32,1);
    cfg->attributedefs=(unsigned char *)calloc(256,1);
  }

  // check that all memory allocations were sucessful
  if (!cfg->name || (!devscan && (!cfg->monitorattflags || !cfg->attributedefs))) {
    printout(LOG_INFO,"No memory to store file: %s line %d, %s\n", CONFIGFILE, lineno, strerror(errno));
    exit(1);
  }

  // Store line number, and by default check for both device types.
  cfg->lineno=lineno;
  cfg->tryscsi=1;
  cfg->tryata=1;
  
  // Try and recognize if a IDE or SCSI device.  These can be
  // overwritten by configuration file directives.
  len=strlen(name);
  if (len>5 && !strncmp("/dev/h",name, 6))
    cfg->tryscsi=0;
  
  if (len>5 && !strncmp("/dev/s",name, 6))
    cfg->tryata=0;
  
  // parse tokens one at a time from the file.  This line actually
  // parses ALL the tokens.
  while ((token=strtok(NULL,delim)) && parsetoken(token,cfg)){
#if 0
    printout(LOG_INFO,"Parsed token %s\n",token);
#endif
  }

  // If no ATA monitoring directives are set, then set all of them.
  if (cfg->tryata && !(cfg->smartcheck || cfg->usagefailed || cfg->prefail || 
                       cfg->usage || cfg->selftest || cfg->errorlog)){
    
    printout(LOG_INFO,"Drive: %s, implied '-a' Directive on line %d of file %s\n",
             cfg->name, cfg->lineno, CONFIGFILE);
    
    cfg->smartcheck=1;
    cfg->usagefailed=1;
    cfg->prefail=1;
    cfg->usage=1;
    cfg->selftest=1;
    cfg->errorlog=1;
  }
  
  // additional sanity check. Has user set -M options without -m?
  if (!cfg->address && (cfg->emailcmdline || cfg->emailfreq || cfg->emailtest)){
    printout(LOG_CRIT,"Drive: %s, -M Directive(s) on line %d of file %s need -m ADDRESS Directive\n",
             cfg->name, cfg->lineno, CONFIGFILE);
    Directives();
    exit(1);
  }
  
  // has the user has set <nomailer>?
  if (cfg->address && !strcmp(cfg->address,"<nomailer>")){
    // check that -M exec is also set
    if (!cfg->emailcmdline){
      printout(LOG_CRIT,"Drive: %s, -m <nomailer> Directive on line %d of file %s needs -M exec Directive\n",
               cfg->name, cfg->lineno, CONFIGFILE);
      Directives();
      exit(1);
    }
    // now free memory.  From here on the sign of <nomailer> is
    // address==NULL and cfg->emailcmdline!=NULL
    free(cfg->address);
    cfg->address=NULL;
  }

  // set cfg->emailfreq to 1 (once) if user hasn't set it
  if (!cfg->emailfreq)
    cfg->emailfreq = 1;

  entry++;
  free(copy);

  // Return:
  if (devscan)
    return -1;
  else
    return 1;
}

// returns number of entries in config file, or 0 if no config file
// exists.  A config file with zero entries will cause an error
// message and an exit.  Returns -1 if it found a SCANDEVICE directive
// in the config file.
int parseconfigfile(){
  FILE *fp;
  int entry=0,lineno=1,cont=0,contlineno=0;
  char line[MAXLINELEN+2];
  char fullline[MAXCONTLINE+1];

  // Open config file, if it exists
  fp=fopen(CONFIGFILE,"r");
  if (fp==NULL && errno!=ENOENT){
    // file exists but we can't read it
    printout(LOG_CRIT,"%s: Unable to open configuration file %s\n",
             strerror(errno),CONFIGFILE);
    exit(1);
  }
  
  // No config file
  if (fp==NULL)
    return 0;
  
  // configuration file exists
  printout(LOG_INFO,"Using configuration file %s\n",CONFIGFILE);

  // parse config file line by line
  while (1) {
    int len=0,scandevice;
    char *lastslash;
    char *comment;
    char *code;

    // make debugging simpler
    memset(line,0,sizeof(line));

    // get a line
    code=fgets(line,MAXLINELEN+2,fp);
    
    // are we at the end of the file?
    if (!code){
      if (cont) {
        scandevice=parseconfigline(entry,lineno,fullline);
        // See if we found a SCANDEVICE directive
        if (scandevice<0)
          return -1;
        // the final line is part of a continuation line
        cont=0;
        entry+=scandevice;
      }
      break;
    }

    // input file line number
    contlineno++;
    
    // See if line is too long
    len=strlen(line);
    if (len>MAXLINELEN){
      char *warn;
      if (line[len-1]=='\n')
        warn="(including newline!) ";
      else
        warn="";
      printout(LOG_CRIT,"Error: line %d of file %s %sis more than %d characters.\n",
               (int)contlineno,CONFIGFILE,warn,(int)MAXLINELEN);
      exit(1); 
    }

    // Ignore anything after comment symbol
    if ((comment=index(line,'#'))){
      *comment='\0';
      len=strlen(line);
    }

    // is the total line (made of all continuation lines) too long?
    if (cont+len>MAXCONTLINE){
      printout(LOG_CRIT,"Error: continued line %d (actual line %d) of file %s is more than %d characters.\n",
               lineno, (int)contlineno, CONFIGFILE, (int)MAXCONTLINE);
      exit(1);
    }
    
    // copy string so far into fullline, and increment length
    strcpy(fullline+cont,line);
    cont+=len;

    // is this a continuation line.  If so, replace \ by space and look at next line
    if ( (lastslash=rindex(line,'\\')) && !strtok(lastslash+1," \n\t")){
      *(fullline+(cont-len)+(lastslash-line))=' ';
      continue;
    }

    // Not a continuation line. Parse it
    scandevice=parseconfigline(entry,lineno,fullline);

    // did we find a scandevice directive?
    if (scandevice<0)
      return -1;

    entry+=scandevice;
    lineno++;
    cont=0;
  }
  fclose(fp);
  if (entry)
    return entry;
  
  printout(LOG_CRIT,"Configuration file %s contains no devices (like /dev/hda)\n",CONFIGFILE);
  exit(1);
}

// Prints copyright, license and version information
void PrintCopyleft(void){
  char out[CVSMAXLEN];
  debugmode=1;
  printhead();
  printout(LOG_INFO,copyleftstring);
  printout(LOG_INFO,"CVS version IDs of files used to build this code are:\n");
  printone(out,atacmds_c_cvsid);
  printout(LOG_INFO,"%s",out);
  printone(out,ataprint_c_cvsid);
  printout(LOG_INFO,"%s",out);
  printone(out,knowndrives_c_cvsid);
  printout(LOG_INFO,"%s",out);
  printone(out,scsicmds_c_cvsid);
  printout(LOG_INFO,"%s",out);
  printone(out,smartd_c_cvsid);
  printout(LOG_INFO,"%s",out);
  printone(out,utility_c_cvsid);
  printout(LOG_INFO,"%s",out);

}

/* Returns a pointer to a static string containing a formatted list of the valid
   arguments to the option opt or NULL on failure. */
const char *getvalidarglist(char opt) {
  switch (opt) {
  case 'r':
    return "ioctl, ataioctl, scsiioctl";
  case 'p':
    return "<FILE_NAME>";
  case 'i':
    return "<INTEGER_SECONDS>";
  default:
    return NULL;
  }
}

/* Prints the message "=======> VALID ARGUMENTS ARE: <LIST>  <=======\n", where
   <LIST> is the list of valid arguments for option opt. */
void printvalidarglistmessage(char opt) {
  const char *s;

  printout(LOG_CRIT, "=======> VALID ARGUMENTS ARE: ");
  if (!(s = getvalidarglist(opt)))
    pout("Error whilst constructing argument list for option %c", opt);
  else
    printout(LOG_CRIT, (char *)s);
  printout(LOG_CRIT, " <=======\n");
}

// Parses input line, prints usage message and
// version/license/copyright messages
void ParseOpts(int argc, char **argv){
  extern char *optarg;
  extern int  optopt, optind, opterr;
  int optchar;
  int badarg;
  char *tailptr;
  long lchecktime;
  // Please update getvalidarglist() if you edit shortopts
  const char *shortopts = "cdDi:p:r:Vh?";
#ifdef HAVE_GETOPT_LONG
  char *arg;
  // Please update getvalidarglist() if you edit longopts
  struct option longopts[] = {
    { "checkonce",      no_argument,       0, 'c' },
    { "debug",          no_argument,       0, 'd' },
    { "showdirectives", no_argument,       0, 'D' },
    { "interval",       required_argument, 0, 'i' },
    { "pidfile",	required_argument, 0, 'p' },
    { "report",         required_argument, 0, 'r' },
    { "version",        no_argument,       0, 'V' },
    { "license",        no_argument,       0, 'V' },
    { "copyright",      no_argument,       0, 'V' },
    { "help",           no_argument,       0, 'h' },
    { "usage",          no_argument,       0, 'h' },
    { 0,                0,                 0, 0   }
  };
#endif

  opterr=optopt=0;
  badarg=FALSE;

  // Parse input options:
#ifdef HAVE_GETOPT_LONG
  while (-1 != (optchar = getopt_long(argc, argv, shortopts, longopts, NULL))){
#else
  while (-1 != (optchar = getopt(argc, argv, shortopts))){
#endif
    switch(optchar) {
    case 'c':
      checkonce = TRUE;
      debugmode = TRUE;
      break;
    case 'd':
      debugmode = TRUE;
      break;
    case 'D':
      debugmode = TRUE;
      Directives();
      exit(0);
      break;
    case 'i':
      // Period (time interval) for checking
      // strtol will set errno in the event of overflow, so we'll check it.
      errno = 0;
      lchecktime = strtol(optarg, &tailptr, 10);
      if (*tailptr != '\0' || lchecktime < 10 || lchecktime > INT_MAX || errno) {
        debugmode=1;
        printhead();
        printout(LOG_CRIT, "======> INVALID INTERVAL: %s <=======\n", optarg);
        printout(LOG_CRIT, "======> INTERVAL MUST BE INTEGER BETWEEN %d AND %d <=======\n", 10, INT_MAX);
        printout(LOG_CRIT, "\nUse smartd -h to get a usage summary\n\n");
        exit(-1);
      }
      checktime = (int)lchecktime;
      break;
    case 'r':
      if (!strcmp(optarg,"ioctl")) {
        con->reportataioctl++;
        con->reportscsiioctl++;
      } else if (!strcmp(optarg,"ataioctl")) {
        con->reportataioctl++;
      } else if (!strcmp(optarg,"scsiioctl")) {
        con->reportscsiioctl++;
      } else {
        badarg = TRUE;
      }
      break;
    case 'p':
      if( -1 == asprintf(&pid_file, "%s", optarg)) {
	printout(LOG_CRIT, "Can't allocate memory for pid file name %s - exiting.\n", optarg);
	pid_file = NULL;
	exit(-1);
      }
      break;
    case 'V':
      PrintCopyleft();
      exit(0);
      break;
    case '?':
    case 'h':
    default:
      debugmode=1;
      printhead();
#ifdef HAVE_GETOPT_LONG
      // Point arg to the argument in which this option was found.
      arg = argv[optind-1];
      // Check whether the option is a long option that doesn't map to -h.
      if (arg[1] == '-' && optchar != 'h') {
        // Iff optopt holds a valid option then argument must be missing.
        if (optopt && (strchr(shortopts, optopt) != NULL)) {
          printout(LOG_CRIT, "=======> ARGUMENT REQUIRED FOR OPTION: %s <=======\n",arg+2);
          printvalidarglistmessage(optopt);
        } else {
          printout(LOG_CRIT, "=======> UNRECOGNIZED OPTION: %s <=======\n\n",arg+2);
        }
        printout(LOG_CRIT, "\nUse smartd --help to get a usage summary\n\n");
        exit(-1);
      }
#endif
      if (optopt) {
        // Iff optopt holds a valid option then argument must be missing.
        if (strchr(shortopts, optopt) != NULL){
          printout(LOG_CRIT, "=======> ARGUMENT REQUIRED FOR OPTION: %c <=======\n",optopt);
          printvalidarglistmessage(optopt);
        } else {
          printout(LOG_CRIT, "=======> UNRECOGNIZED OPTION: %c <=======\n\n",optopt);
        }
        printout(LOG_CRIT, "\nUse smartd -h to get a usage summary\n\n");
        exit(-1);
      }
      Usage();
      exit(0);
    }

    // Check to see if option had an unrecognized or incorrect argument.
    if (badarg) {
      debugmode=1;
      printhead();
      // It would be nice to print the actual option name given by the user
      // here, but we just print the short form.  Please fix this if you know
      // a clean way to do it.
      printout(LOG_CRIT, "=======> INVALID ARGUMENT TO -%c: %s <======= \n", optchar, optarg);
      printvalidarglistmessage(optchar);
      printout(LOG_CRIT, "\nUse smartd -h to get a usage summary\n\n");
      exit(-1);
    }
  }

  // no pidfile in debug mode
  if (debugmode && pid_file) {
    printout(LOG_INFO, "warning: pid file %s not written in debug mode\n", pid_file);
    free(pid_file);
    pid_file = NULL;
  }
  
  // print header
  printhead();
  
  return;
}
  
// Function we call if no configuration file was found or if the
// DEVICESCAN Directive was found.  It makes entries for /dev/hd[a-l]
// and /dev/sd[a-z].
int makeconfigentries(int num, char *name, int isata, int start, int scandirective){
  int i;
  
  // check that we still have space for entries
  if (MAXENTRIES<(start+num)){
    printout(LOG_CRIT,"Error: simulated config file can have no more than %d entries\n",(int)MAXENTRIES);
    exit(1);
  }
  
  // loop over the number of entries that we should create
  for(i=0; i<num; i++){
    cfgfile *cfg=config+start+i;
    
    // If user has given the scan directive, copy config files entries
    if (scandirective){
      memcpy(cfg, config, sizeof(*cfg));
    }
    else {
      // no config file was used: all structure entries need to be set
      memset(cfg,0,sizeof(*cfg));
      
      // enable all possible tests
      cfg->smartcheck=1;
      cfg->prefail=1;
      cfg->usagefailed=1;
      cfg->usage=1;
      cfg->selftest=1;
      cfg->errorlog=1;
      
      // lineno==0 is our clue that the device was not found in a
      // config file!
      cfg->lineno=0;    
    }
    
    // select if it's a SCSI or ATA device
    cfg->tryata=isata;
    cfg->tryscsi=!isata;
    
    // put in the device name
    cfg->name=strdup(name);
    cfg->monitorattflags=(unsigned char *)calloc(NMONITOR*32,1);
    cfg->attributedefs=(unsigned char *)calloc(256,1);
    if (!cfg->name || !cfg->monitorattflags || !cfg->attributedefs) {
      printout(LOG_INFO,"No memory for %d'th device after %s, %s\n", i, name, strerror(errno));
      exit(1);
    }
    
    // increment final character of the name
    cfg->name[strlen(name)-1]+=i;
  }
  return i;
}

void cantregister(char *name, char *type, int line, int scandirective){
  if (line)
    printout(scandirective?LOG_INFO:LOG_CRIT,
             "Unable to register %s device %s at line %d of file %s\n",
             type, name, line, CONFIGFILE);
  else
    printout(LOG_INFO,"Unable to register %s device %s\n",
             type, name);
  return;
}
 
 
/* Main Program */
int main (int argc, char **argv){
  atadevices_t atadevices[MAXATADEVICES], *atadevicesptr=atadevices;
  scsidevices_t scsidevices[MAXSCSIDEVICES], *scsidevicesptr=scsidevices;
  int i, entries, scandirective=0, scanning=0;
  smartmonctrl control;
  
  // initialize global communications variables
  con=&control;
  memset(con,0,sizeof(control));
  
  // Parse input and print header and usage info if needed
  ParseOpts(argc,argv);
  
  // Do we mute printing from ataprint commands?
  con->quietmode=0;
  con->veryquietmode=debugmode?0:1;
  con->checksumfail=0;

  // look in configuration file CONFIGFILE (normally /etc/smartd.conf)
  entries=parseconfigfile();
  
  // if SCANDEVICE used or there was no /etc/smartd.conf config file,
  // then create needed entries for scanning
  if (entries<=0){
    int doscsi, doata;

    scanning=1;

    // Was SCANDEVICE Directive given?
    scandirective=entries;
    if (scandirective){
      printout(LOG_INFO,"smartd: Scanning for devices.\n");
      // free up storage used for SCANDIRECTIVE string
      free(config->name);
      config->name=NULL;
    }
    else {
      // No config file given, so scan for both ATA and SCSI devices
      printout(LOG_INFO,"smartd: file %s not found. Searching for ATA & SCSI devices.\n",CONFIGFILE);
      config->tryata=1;
      config->tryscsi=1;
    }

    // initialize total number of entries to seach for
    entries=0;
    doata=config->tryata;
    doscsi=config->tryscsi;

    // make list of ATA devices to search for
    if (doata)
      entries+=makeconfigentries(MAXATADEVICES,  "/dev/hda", 1, entries, scandirective);
    // make list of SCSI devices to search for
    if (doscsi)
      entries+=makeconfigentries(MAXSCSIDEVICES, "/dev/sda", 0, entries, scandirective);
  }

  // Register entries
  for (i=0;i<entries;i++){
    int notregistered=1;
    
    // register ATA devices
    if (config[i].tryata){
      if (atadevicescan2(atadevicesptr+numatadevices, config+i))
	cantregister(config[i].name, "ATA", config[i].lineno, scandirective);
      else
	notregistered=0;
    }
    
    // then register SCSI devices
    if (config[i].tryscsi){
      if (scsidevicescan(scsidevicesptr+numscsidevices, config+i))
	cantregister(config[i].name, "SCSI", config[i].lineno, scandirective);
      else
	notregistered=0;
    }
    
    // if device explictly listed and we can't register it, then exit
    if (notregistered && !scanning){
      printout(LOG_CRIT, "Unable to register device %s.  Exiting.\n", config[i].name);
      exit(1);
    }
  } // done registering entries

  // If there are no devices to monitor, then exit
  if (!numatadevices && !numscsidevices){
    printout(LOG_INFO,"Unable to monitor any SMART enabled ATA or SCSI devices.\n");
    exit(1);
  }

  // Now start an infinite loop that checks all devices
  CheckDevices(atadevicesptr, scsidevicesptr); 
  return 0;
}

