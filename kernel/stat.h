#define T_DIR    1 // Directory
#define T_FILE   2 // File
#define T_DEVICE 3 // Device

struct stat {
  int dev;     // File system's disk device
  uint ino;    // Inode number
  short type;  // Type of file
  short nlink; // Number of links to file
  uint uid;
  uint gid;
  uint mode;
  uint64 size; // Size of file in bytes
};

#define MAY_EXEC  1
#define MAY_WRITE 2
#define MAY_READ  4
#define MAX_ID    65535
