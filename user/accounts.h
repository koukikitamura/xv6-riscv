#define ACCOUNT_NAME 16

// Public records in /passwd.
struct account {
  char name[ACCOUNT_NAME];
  uint uid;
  uint gid;
  char home[16];
};

// Public records in /group.
struct group {
  char name[ACCOUNT_NAME];
  uint gid;
};

// Root-only records in /shadow.
struct credential {
  uint uid;
  uint rounds;
  uchar salt[16];
  uchar hash[32];
};

int account_name(const char *, struct account *);
int account_uid(uint, struct account *);
int group_name(const char *, struct group *);
int group_gid(uint, struct group *);
