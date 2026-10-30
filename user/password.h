// One password format: PBKDF2-HMAC-SHA-256, 16-byte salt, 32-byte result.
#define SALT_LEN        16
#define HASH_LEN        32
#define PASSWORD_MAX    63
#define PASSWORD_ROUNDS 100000

void sha256(const unsigned char *, unsigned int, unsigned char *);
void hmac256(const unsigned char *, unsigned int, const unsigned char *,
             unsigned int, unsigned char *);
void password_hash(const char *, const unsigned char *, unsigned int,
                   unsigned char *);
void secret_clear(void *, unsigned int);
