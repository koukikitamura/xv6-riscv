#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "user/user.h"
#include "user/accounts.h"
#include "user/password.h"

// Consume the entire line even on overflow; never authenticate a prefix.
static int
read_line(char *buf, int size)
{
  int length = 0;
  int invalid = 0;
  char c;

  while (read(0, &c, 1) == 1) {
    if (c == '\n') {
      buf[length] = 0;
      if (invalid)
        return -1;
      return 0;
    }

    if (c == 0 || length == size - 1) {
      invalid = 1;
    } else {
      buf[length] = c;
      length++;
    }
  }

  buf[length] = 0;
  return -1;
}

// Close /shadow before returning, including when no matching UID exists.
static int
read_credential(uint uid, struct credential *credential)
{
  int fd;
  int found = 0;

  fd = open("/shadow", O_RDONLY);
  if (fd < 0)
    return -1;

  while (read(fd, credential, sizeof(*credential)) == sizeof(*credential)) {
    if (credential->uid == uid) {
      found = 1;
      break;
    }
  }

  close(fd);
  if (!found)
    return -1;
  return 0;
}

static int
authenticate(const struct account *account, const char *password)
{
  struct credential credential;
  uchar computed_hash[HASH_LEN];
  uint difference = 0;

  if (read_credential(account->uid, &credential) < 0) {
    secret_clear(&credential, sizeof(credential));
    return 0;
  }

  if (credential.rounds != PASSWORD_ROUNDS) {
    secret_clear(&credential, sizeof(credential));
    return 0;
  }

  password_hash(password, credential.salt, credential.rounds, computed_hash);

  // Compare every byte, without stopping at the first mismatch.
  for (int i = 0; i < HASH_LEN; i++)
    difference |= computed_hash[i] ^ credential.hash[i];

  secret_clear(computed_hash, sizeof(computed_hash));
  secret_clear(&credential, sizeof(credential));
  return difference == 0;
}

int
main(void)
{
  char name[ACCOUNT_NAME];
  char password[PASSWORD_MAX + 1];
  struct account account;
  char *argv[] = {"sh", 0};

  if (getuid() != 0) {
    fprintf(2, "login: must be started by root\n");
    exit(1);
  }

  for (;;) {
    consoleset(0, 1);
    printf("login: ");
    int name_valid = read_line(name, sizeof(name)) == 0;

    consoleset(0, 0);
    printf("Password: ");
    int password_valid = read_line(password, sizeof(password)) == 0;

    consoleset(0, 1);
    printf("\n");

    int authenticated = 0;
    if (name_valid && password_valid) {
      if (account_name(name, &account) == 0)
        authenticated = authenticate(&account, password);
    }
    secret_clear(password, sizeof(password));

    if (!authenticated) {
      printf("Login incorrect\n");
      pause(10);
      continue;
    }

    // Authentication has finished; the shell receives only the user's identity.
    consoleset(account.uid, 1);
    if (setidentity(account.uid, account.gid) < 0) {
      fprintf(2, "login: cannot enter account\n");
      exit(1);
    }

    if (chdir(account.home) < 0) {
      fprintf(2, "login: cannot enter account\n");
      exit(1);
    }

    exec("/sh", argv);
    fprintf(2, "login: cannot execute /sh\n");
    exit(1);
  }
}
