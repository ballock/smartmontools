/*
 * Home page of code is: http://smartmontools.sourceforge.net
 *
 * Copyright (C) 2002-11 Bruce Allen <smartmontools-support@lists.sourceforge.net>
 * Copyright (C) 2000    Michael Cornwell <cornwell@acm.org>
 * Copyright (C) 2008    Oliver Bock <brevilo@users.sourceforge.net>
 * Copyright (C) 2008-14 Christian Franke <smartmontools-support@lists.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * You should have received a copy of the GNU General Public License
 * (for example COPYING); If not, see <http://www.gnu.org/licenses/>.
 *
 * This code was originally developed as a Senior Thesis by Michael Cornwell
 * at the Concurrent Systems Laboratory (now part of the Storage Systems
 * Research Center), Jack Baskin School of Engineering, University of
 * California, Santa Cruz. http://ssrc.soe.ucsc.edu/
 *
 */
#ifndef SMARTD_H
#define SMARTD_H

#include "config.h"
#include "int64.h"

// unconditionally included files
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>   // umask
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <getopt.h>

#include <stdexcept>
//#include <string>
#include <vector>
#include <algorithm> // std::replace()

// conditionally included files
#ifndef _WIN32
#include <sys/wait.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef _WIN32
#ifdef _MSC_VER
#pragma warning(disable:4761) // "conversion supplied"
typedef unsigned short mode_t;
typedef int pid_t;
#endif
#include <io.h> // umask()
#include <process.h> // getpid()
#endif // _WIN32

#ifdef __CYGWIN__
#include <io.h> // setmode()
#endif // __CYGWIN__

#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif // LIBCAP_NG

// locally included files
#include "atacmds.h"
#include "dev_interface.h"
#include "knowndrives.h"
#include "scsicmds.h"
#include "utility.h"

// This is for solaris, where signal() resets the handler to SIG_DFL
// after the first signal is caught.
#ifdef HAVE_SIGSET
#define SIGNALFN sigset
#else
#define SIGNALFN signal
#endif

#ifdef _WIN32
// fork()/signal()/initd simulation for native Windows
#include "daemon_win32.h" // daemon_main/detach/signal()
#undef SIGNALFN
#define SIGNALFN  daemon_signal
#define strsignal daemon_strsignal
#define sleep     daemon_sleep
// SIGQUIT does not exist, CONTROL-Break signals SIGBREAK.
#define SIGQUIT SIGBREAK
#define SIGQUIT_KEYNAME "CONTROL-Break"
#else  // _WIN32
#define SIGQUIT_KEYNAME "CONTROL-\\"
#endif // _WIN32

#if defined (__SVR4) && defined (__sun)
extern "C" int getdomainname(char *, int); // no declaration in header files!
#endif

// smartd exit codes
#define EXIT_BADCMD    1   // command line did not parse
#define EXIT_BADCONF   2   // syntax error in config file
#define EXIT_STARTUP   3   // problem forking daemon
#define EXIT_PID       4   // problem creating pid file
#define EXIT_NOCONF    5   // config file does not exist
#define EXIT_READCONF  6   // config file exists but cannot be read

#define EXIT_NOMEM     8   // out of memory
#define EXIT_BADCODE   10  // internal error - should NEVER happen

#define EXIT_BADDEV    16  // we can't monitor this device
#define EXIT_NODEV     17  // no devices to monitor

#define EXIT_SIGNAL    254 // abort on signal


unsigned char debugmode;

// command-line: how long to sleep between checks
#define CHECKTIME 1800
int checktime;

// command-line: name of PID file (empty for no pid file)
std::string pid_file;

// command-line: path prefix of persistent state file, empty if no persistence.
std::string state_path_prefix
#ifdef SMARTMONTOOLS_SAVESTATES
          = SMARTMONTOOLS_SAVESTATES
#endif
                                    ;

// command-line: path prefix of attribute log file, empty if no logs.
static std::string attrlog_path_prefix
#ifdef SMARTMONTOOLS_ATTRIBUTELOG
          = SMARTMONTOOLS_ATTRIBUTELOG
#endif
                                    ;

// configuration file name
static const char * configfile;
// configuration file "name" if read from stdin
static const char * const configfile_stdin = "<stdin>";
// path of alternate configuration file
static std::string configfile_alt;

// warning script file
static std::string warning_script;

// command-line: when should we exit?
static int quit=0;

// command-line; this is the default syslog(3) log facility to use.
static int facility=LOG_DAEMON;

#ifndef _WIN32
// command-line: fork into background?
static bool do_fork=true;
#endif

#ifdef HAVE_LIBCAP_NG
// command-line: enable capabilities?
static bool enable_capabilities = false;
#endif

// TODO: This smartctl only variable is also used in os_win32.cpp
extern unsigned char failuretest_permissive;

// set to one if we catch a USR1 (check devices now)
static volatile int caughtsigUSR1=0;

#ifdef _WIN32
// set to one if we catch a USR2 (toggle debug mode)
static volatile int caughtsigUSR2=0;
#endif

// set to one if we catch a HUP (reload config file). In debug mode,
// set to two, if we catch INT (also reload config file).
static volatile int caughtsigHUP=0;

// set to signal value if we catch INT, QUIT, or TERM
static volatile int caughtsigEXIT=0;

// This function prints either to stdout or to the syslog as needed.
static void PrintOut(int priority, const char *fmt, ...)
                     __attribute_format_printf(2, 3);

// Attribute monitoring flags.
// See monitor_attr_flags below.
enum {
  MONITOR_IGN_FAILUSE = 0x01,
  MONITOR_IGNORE      = 0x02,
  MONITOR_RAW_PRINT   = 0x04,
  MONITOR_RAW         = 0x08,
  MONITOR_AS_CRIT     = 0x10,
  MONITOR_RAW_AS_CRIT = 0x20,
};

// Array of flags for each attribute.
class attribute_flags
{
public:
  attribute_flags();
  bool is_set(int id, unsigned char flag) const;
  void set(int id, unsigned char flags);

private:
  unsigned char m_flags[256];
};


/// Configuration data for a device. Read from smartd.conf.
/// Supports copy & assignment and is compatible with STL containers.
struct dev_config
{
  int lineno;                             // Line number of entry in file
  std::string name;                       // Device name (with optional extra info)
  std::string dev_name;                   // Device name (plain, for SMARTD_DEVICE variable)
  std::string dev_type;                   // Device type argument from -d directive, empty if none
  std::string dev_idinfo;                 // Device identify info for warning emails
  std::string state_file;                 // Path of the persistent state file, empty if none
  std::string attrlog_file;               // Path of the persistent attrlog file, empty if none
  bool ignore;                            // Ignore this entry
  bool smartcheck;                        // Check SMART status
  bool usagefailed;                       // Check for failed Usage Attributes
  bool prefail;                           // Track changes in Prefail Attributes
  bool usage;                             // Track changes in Usage Attributes
  bool selftest;                          // Monitor number of selftest errors
  bool errorlog;                          // Monitor number of ATA errors
  bool xerrorlog;                         // Monitor number of ATA errors (Extended Comprehensive error log)
  bool offlinests;                        // Monitor changes in offline data collection status
  bool offlinests_ns;                     // Disable auto standby if in progress
  bool selfteststs;                       // Monitor changes in self-test execution status
  bool selfteststs_ns;                    // Disable auto standby if in progress
  bool permissive;                        // Ignore failed SMART commands
  char autosave;                          // 1=disable, 2=enable Autosave Attributes
  char autoofflinetest;                   // 1=disable, 2=enable Auto Offline Test
  firmwarebug_defs firmwarebugs;          // -F directives from drivedb or smartd.conf
  bool ignorepresets;                     // Ignore database of -v options
  bool showpresets;                       // Show database entry for this device
  bool removable;                         // Device may disappear (not be present)
  char powermode;                         // skip check, if disk in idle or standby mode
  bool powerquiet;                        // skip powermode 'skipping checks' message
  int powerskipmax;                       // how many times can be check skipped
  unsigned char tempdiff;                 // Track Temperature changes >= this limit
  unsigned char tempinfo, tempcrit;       // Track Temperatures >= these limits as LOG_INFO, LOG_CRIT+mail
  regular_expression test_regex;          // Regex for scheduled testing

  // Configuration of email warning messages
  std::string emailcmdline;               // script to execute, empty if no messages
  std::string emailaddress;               // email address, or empty
  unsigned char emailfreq;                // Emails once (1) daily (2) diminishing (3)
  bool emailtest;                         // Send test email?

  // ATA ONLY
  int dev_rpm; // rotation rate, 0 = unknown, 1 = SSD, >1 = HDD
  int set_aam; // disable(-1), enable(1..255->0..254) Automatic Acoustic Management
  int set_apm; // disable(-1), enable(2..255->1..254) Advanced Power Management
  int set_lookahead; // disable(-1), enable(1) read look-ahead
  int set_standby; // set(1..255->0..254) standby timer
  bool set_security_freeze; // Freeze ATA security
  int set_wcache; // disable(-1), enable(1) write cache

  bool sct_erc_set;                       // set SCT ERC to:
  unsigned short sct_erc_readtime;        // ERC read time (deciseconds)
  unsigned short sct_erc_writetime;       // ERC write time (deciseconds)

  unsigned char curr_pending_id;          // ID of current pending sector count, 0 if none
  unsigned char offl_pending_id;          // ID of offline uncorrectable sector count, 0 if none
  bool curr_pending_incr, offl_pending_incr; // True if current/offline pending values increase
  bool curr_pending_set,  offl_pending_set;  // True if '-C', '-U' set in smartd.conf

  attribute_flags monitor_attr_flags;     // MONITOR_* flags for each attribute

  ata_vendor_attr_defs attribute_defs;    // -v options

  dev_config();
};



// Number of allowed mail message types
static const int SMARTD_NMAIL = 13;
// Type for '-M test' mails (state not persistent)
static const int MAILTYPE_TEST = 0;
// TODO: Add const or enum for all mail types.

struct mailinfo {
  int logged;// number of times an email has been sent
  time_t firstsent;// time first email was sent, as defined by time(2)
  time_t lastsent; // time last email was sent, as defined by time(2)

  mailinfo()
    : logged(0), firstsent(0), lastsent(0) { }
};

/// Persistent state data for a device.
struct persistent_dev_state
{
  unsigned char tempmin, tempmax;         // Min/Max Temperatures

  unsigned char selflogcount;             // total number of self-test errors
  unsigned short selfloghour;             // lifetime hours of last self-test error

  time_t scheduled_test_next_check;       // Time of next check for scheduled self-tests

  uint64_t selective_test_last_start;     // Start LBA of last scheduled selective self-test
  uint64_t selective_test_last_end;       // End LBA of last scheduled selective self-test

  mailinfo maillog[SMARTD_NMAIL];         // log info on when mail sent

  // ATA ONLY
  int ataerrorcount;                      // Total number of ATA errors

  // Persistent part of ata_smart_values:
  struct ata_attribute {
    unsigned char id;
    unsigned char val;
    unsigned char worst; // Byte needed for 'raw64' attribute only.
    uint64_t raw;
    unsigned char resvd;

    ata_attribute() : id(0), val(0), worst(0), raw(0), resvd(0) { }
  };
  ata_attribute ata_attributes[NUMBER_ATA_SMART_ATTRIBUTES];
  
  // SCSI ONLY

  struct scsi_error_counter {
    struct scsiErrorCounter errCounter;
    unsigned char found;
    scsi_error_counter() : found(0) { }
  };
  scsi_error_counter scsi_error_counters[3];

  struct scsi_nonmedium_error {
    struct scsiNonMediumError nme;
    unsigned char found;
    scsi_nonmedium_error() : found(0) { }
  };
  scsi_nonmedium_error scsi_nonmedium_error;

  persistent_dev_state();
};

/// Non-persistent state data for a device.
struct temp_dev_state
{
  bool must_write;                        // true if persistent part should be written

  bool not_cap_offline;                   // true == not capable of offline testing
  bool not_cap_conveyance;
  bool not_cap_short;
  bool not_cap_long;
  bool not_cap_selective;

  unsigned char temperature;              // last recorded Temperature (in Celsius)
  time_t tempmin_delay;                   // time where Min Temperature tracking will start

  bool powermodefail;                     // true if power mode check failed
  int powerskipcnt;                       // Number of checks skipped due to idle or standby mode

  // SCSI ONLY
  unsigned char SmartPageSupported;       // has log sense IE page (0x2f)
  unsigned char TempPageSupported;        // has log sense temperature page (0xd)
  unsigned char ReadECounterPageSupported;
  unsigned char WriteECounterPageSupported;
  unsigned char VerifyECounterPageSupported;
  unsigned char NonMediumErrorPageSupported;
  unsigned char SuppressReport;           // minimize nuisance reports
  unsigned char modese_len;               // mode sense/select cmd len: 0 (don't
                                          // know yet) 6 or 10
  // ATA ONLY
  uint64_t num_sectors;                   // Number of sectors
  ata_smart_values smartval;              // SMART data
  ata_smart_thresholds_pvt smartthres;    // SMART thresholds
  bool offline_started;                   // true if offline data collection was started
  bool selftest_started;                  // true if self-test was started

  temp_dev_state();
};


/// Runtime state data for a device.
struct dev_state
: public persistent_dev_state,
  public temp_dev_state
{
  void update_persistent_state();
  void update_temp_state();
};

/// Container for configuration info for each device.
typedef std::vector<dev_config> dev_config_vector;

/// Container for state info for each device.
typedef std::vector<dev_state> dev_state_vector;

// Parse a line from a state file.
static bool parse_dev_state_line(const char * line, persistent_dev_state & state);

// Read a state file.
static bool read_dev_state(const char * path, persistent_dev_state & state);

static void write_dev_state_line(FILE * f, const char * name, uint64_t val);

static void write_dev_state_line(FILE * f, const char * name1, int id, const char * name2, uint64_t val);

// Write a state file
static bool write_dev_state(const char * path, const persistent_dev_state & state);

// Write to the attrlog file
static bool write_dev_attrlog(const char * path, const dev_state & state);

// Write all state files. If write_always is false, don't write
// unless must_write is set.
static void write_all_dev_states(const dev_config_vector & configs,
                                 dev_state_vector & states,
                                 bool write_always = true);

// Write to all attrlog files
static void write_all_dev_attrlogs(const dev_config_vector & configs,
                                   dev_state_vector & states);

// remove the PID file
static void RemovePidFile();

extern "C" { // signal handlers require C-linkage

//  Note if we catch a SIGUSR1
static void USR1handler(int sig);

#ifdef _WIN32
//  Note if we catch a SIGUSR2
static void USR2handler(int sig);
#endif

// Note if we catch a HUP (or INT in debug mode)
static void HUPhandler(int sig);

// signal handler for TERM, QUIT, and INT (if not in debug mode)
static void sighandler(int sig);

} // extern "C"

// Cleanup, print Goodbye message and remove pidfile
static int Goodbye(int status);

// a replacement for setenv() which is not available on all platforms.
// Note that the string passed to putenv must not be freed or made
// invalid, since a pointer to it is kept by putenv(). This means that
// it must either be a static buffer or allocated off the heap. The
// string can be freed if the environment variable is redefined via
// another call to putenv(). There is no portable way to unset a variable
// with putenv(). So we manage the buffer in a static object.
// Using setenv() if available is not considered because some
// implementations may produce memory leaks.

class env_buffer
{
public:
  env_buffer()
    : m_buf((char *)0) { }

  void set(const char * name, const char * value);

private:
  char * m_buf;

  env_buffer(const env_buffer &);
  void operator=(const env_buffer &);
};

#define EBUFLEN 1024

static void MailWarning(const dev_config & cfg, dev_state & state, int which, const char *fmt, ...)
                        __attribute_format_printf(4, 5);

static void reset_warning_mail(const dev_config & cfg, dev_state & state, int which, const char *fmt, ...)
                               __attribute_format_printf(4, 5);

#ifndef _WIN32

// Output multiple lines via separate syslog(3) calls.
static void vsyslog_lines(int priority, const char * fmt, va_list ap);

#else  // _WIN32
// os_win32/syslog_win32.cpp supports multiple lines.
#define vsyslog_lines vsyslog
#endif // _WIN32

// Printing function for watching ataprint commands, or losing them
// [From GLIBC Manual: Since the prototype doesn't specify types for
// optional arguments, in a call to a variadic function the default
// argument promotions are performed on the optional argument
// values. This means the objects of type char or short int (whether
// signed or not) are promoted to either int or unsigned int, as
// appropriate.]
void pout(const char *fmt, ...);

// This function prints either to stdout or to the syslog as needed.
static void PrintOut(int priority, const char *fmt, ...);

// Used to warn users about invalid checksums. Called from atacmds.cpp.
void checksumwarning(const char * string);

#ifndef _WIN32

// Wait for the pid file to show up, this makes sure a calling program knows
// that the daemon is really up and running and has a pid to kill it
static bool WaitForPidFile();

#endif // _WIN32

// Forks new process, closes ALL file descriptors, redirects stdin,
// stdout, and stderr.  Not quite daemon().  See
// http://www.linuxjournal.com/article/2335
// for a good description of why we do things this way.
static void DaemonInit();

// create a PID file containing the current process id
static void WritePidFile();

// Prints header identifying version of code and home
static void PrintHead();

// prints help info for configuration file Directives
static void Directives();

/* Returns a pointer to a static string containing a formatted list of the valid
   arguments to the option opt or NULL on failure. */
static const char *GetValidArgList(char opt);

/* prints help information for command syntax */
static void Usage();

static int CloseDevice(smart_device * device, const char * name);

// return true if a char is not allowed in a state file name
static bool not_allowed_in_filename(char c);

// Read error count from Summary or Extended Comprehensive SMART error log
// Return -1 on error
static int read_ata_error_count(ata_device * device, const char * name,
                                firmwarebug_defs firmwarebugs, bool extended);

// returns <0 if problem.  Otherwise, bottom 8 bits are the self test
// error count, and top bits are the power-on hours of the last error.
static int SelfTestErrorCount(ata_device * device, const char * name,
                              firmwarebug_defs firmwarebugs);

#define SELFTEST_ERRORCOUNT(x) (x & 0xff)
#define SELFTEST_ERRORHOURS(x) ((x >> 8) & 0xffff)

// Check offline data collection status
static inline bool is_offl_coll_in_progress(unsigned char status);

// Check self-test execution status
static inline bool is_self_test_in_progress(unsigned char status);

// Log offline data collection status
static void log_offline_data_coll_status(const char * name, unsigned char status);

// Log self-test execution status
static void log_self_test_exec_status(const char * name, unsigned char status);

// Check pending sector count id (-C, -U directives).
static bool check_pending_id(const dev_config & cfg, const dev_state & state,
                             unsigned char id, const char * msg);

// Called by ATA/SCSIDeviceScan() after successful device check
static void finish_device_scan(dev_config & cfg, dev_state & state);

// Common function to format result message for ATA setting
static void format_set_result_msg(std::string & msg, const char * name, bool ok,
                                  int set_option = 0, bool has_value = false);

// TODO: Add '-F swapid' directive
const bool fix_swapped_id = false;

// scan to see what ata devices there are, and if they support SMART
static int ATADeviceScan(dev_config & cfg, dev_state & state, ata_device * atadev);

// on success, return 0. On failure, return >0.  Never return <0,
// please.
static int SCSIDeviceScan(dev_config & cfg, dev_state & state, scsi_device * scsidev);

// If the self-test log has got more self-test errors (or more recent
// self-test errors) recorded, then notify user.
static void CheckSelfTestLogs(const dev_config & cfg, dev_state & state, int newi);

// Test types, ordered by priority.
static const char test_type_chars[] = "LncrSCO";
static const unsigned num_test_types = sizeof(test_type_chars)-1;

// returns test type if time to do test of type testtype,
// 0 if not time to do test.
static char next_scheduled_test(const dev_config & cfg, dev_state & state, bool scsi, time_t usetime = 0);

// Print a list of future tests.
static void PrintTestSchedule(const dev_config_vector & configs, dev_state_vector & states, const smart_device_list & devices);

// Return zero on success, nonzero on failure. Perform offline (background)
// short or long (extended) self test on given scsi device.
static int DoSCSISelfTest(const dev_config & cfg, dev_state & state, scsi_device * device, char testtype);

// Do an offline immediate or self-test.  Return zero on success,
// nonzero on failure.
static int DoATASelfTest(const dev_config & cfg, dev_state & state, ata_device * device, char testtype);

// Check pending sector count attribute values (-C, -U directives).
static void check_pending(const dev_config & cfg, dev_state & state,
                          unsigned char id, bool increase_only,
                          const ata_smart_values & smartval,
                          int mailtype, const char * msg);

// Format Temperature value
static const char * fmt_temp(unsigned char x, char (& buf)[20]);

// Check Temperature limits
static void CheckTemperature(const dev_config & cfg, dev_state & state, unsigned char currtemp, unsigned char triptemp);

void check_attribute(const dev_config & cfg, dev_state & state,
                     const ata_smart_attribute & attr,
                     const ata_smart_attribute & prev,
                     int attridx,
                     const ata_smart_threshold_entry * thresholds);

static int ATACheckDevice(const dev_config & cfg, dev_state & state, ata_device * atadev,
                          bool firstpass, bool allow_selftests);

static int SCSICheckDevice(const dev_config & cfg, dev_state & state, scsi_device * scsidev, bool allow_selftests);

// 0=not used, 1=not disabled, 2=disable rejected by OS, 3=disabled
static int standby_disable_state = 0;

static void init_disable_standby_check(dev_config_vector & configs);

static void do_disable_standby_check(const dev_config_vector & configs, const dev_state_vector & states);
// Checks the SMART status of all ATA and SCSI devices
static void CheckDevicesOnce(const dev_config_vector & configs, dev_state_vector & states,
                             smart_device_list & devices, bool firstpass, bool allow_selftests);

// Set if Initialize() was called
static bool is_initialized = false;

// Does initialization right after fork to daemon mode
static void Initialize(time_t *wakeuptime);

#ifdef _WIN32
// Toggle debug mode implemented for native windows only
// (there is no easy way to reopen tty on *nix)
static void ToggleDebugMode();
#endif

static time_t dosleep(time_t wakeuptime, bool & sigwakeup);
// Print out a list of valid arguments for the Directive d
static void printoutvaliddirectiveargs(int priority, char d);

// exits with an error message, or returns integer value of token
static int GetInteger(const char *arg, const char *name, const char *token, int lineno, const char *cfgfile,
               int min, int max, char * suffix = 0);

// Get 1-3 small integer(s) for '-W' directive
static int Get3Integers(const char *arg, const char *name, const char *token, int lineno, const char *cfgfile,
                 unsigned char *val1, unsigned char *val2, unsigned char *val3);

#ifdef _WIN32

// Concatenate strtok() results if quoted with "..."
static const char * strtok_dequote(const char * delimiters);

#endif // _WIN32


// This function returns 1 if it has correctly parsed one token (and
// any arguments), else zero if no tokens remain.  It returns -1 if an
// error was encountered.
static int ParseToken(char * token, dev_config & cfg);

// Scan directive for configuration file
#define SCANDIRECTIVE "DEVICESCAN"

// This is the routine that adds things to the conf_entries list.
//
// Return values are:
//  1: parsed a normal line
//  0: found DEFAULT setting or comment or blank line
// -1: found SCANDIRECTIVE line
// -2: found an error
//
// Note: this routine modifies *line from the caller!
static int ParseConfigLine(dev_config_vector & conf_entries, dev_config & default_conf, int lineno, /*const*/ char * line);

// Parses a configuration file.  Return values are:
//  N=>0: found N entries
// -1:    syntax error in config file
// -2:    config file does not exist
// -3:    config file exists but cannot be read
//
// In the case where the return value is 0, there are three
// possiblities:
// Empty configuration file ==> conf_entries.empty()
// No configuration file    ==> conf_entries[0].lineno == 0
// SCANDIRECTIVE found      ==> conf_entries.back().lineno != 0 (size >= 1)
static int ParseConfigFile(dev_config_vector & conf_entries);

/* Prints the message "=======> VALID ARGUMENTS ARE: <LIST>  <=======\n", where
   <LIST> is the list of valid arguments for option opt. */
static void PrintValidArgs(char opt);

#ifndef _WIN32
// Report error and exit if specified path is not absolute.
static void check_abs_path(char option, const std::string & path);
#endif // !_WIN32

// Parses input line, prints usage message and
// version/license/copyright messages
static void ParseOpts(int argc, char **argv);

// Function we call if no configuration file was found or if the
// SCANDIRECTIVE Directive was found.  It makes entries for device
// names returned by scan_smart_devices() in os_OSNAME.cpp
static int MakeConfigEntries(const dev_config & base_cfg,
  dev_config_vector & conf_entries, smart_device_list & scanned_devs, const char * type);
 
static void CanNotRegister(const char *name, const char *type, int line, bool scandirective);

// Returns negative value (see ParseConfigFile()) if config file
// had errors, else number of entries which may be zero or positive. 
static int ReadOrMakeConfigEntries(dev_config_vector & conf_entries, smart_device_list & scanned_devs);

// Return true if TYPE contains a RAID drive number
static bool is_raid_type(const char * type);

// Return true if DEV is already in DEVICES[0..NUMDEVS) or IGNORED[*]
static bool is_duplicate_device(const smart_device * dev,
                                const smart_device_list & devices, unsigned numdevs,
                                const dev_config_vector & ignored);
// This function tries devices from conf_entries.  Each one that can be
// registered is moved onto the [ata|scsi]devices lists and removed
// from the conf_entries list.
static void RegisterDevices(const dev_config_vector & conf_entries, smart_device_list & scanned_devs,
                            dev_config_vector & configs, dev_state_vector & states, smart_device_list & devices);

// Main program without exception handling
static int main_worker(int argc, char **argv);

#ifdef _WIN32
// Windows: internal main function started direct or by service control manager
static int smartd_main(int argc, char **argv);
#endif

#endif /* SMARTD_H */
