// SHA-256 and HMAC follow RFC 6234; PBKDF2 follows RFC 8018 section 5.2.
// This implementation derives only one 32-byte block for the login format.
#include "password.h"

typedef unsigned int word;
typedef unsigned char byte;
struct sha256_context {
  word h[8];
  unsigned long long bytes;
  byte block[64];
  word used;
};

static const word k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void
secret_clear(void *p, unsigned int n)
{
  volatile byte *b = p;

  while (n--)
    *b++ = 0;
}

static word
ror(word x, int n)
{
  return (x >> n) | (x << (32 - n));
}

static void
sha256_transform(struct sha256_context *s)
{
  word w[64];
  word a, b, c, d, e, f, g, h;
  word t1, t2;

  // Decode the input block as 16 big-endian words.
  for (int i = 0; i < 16; i++) {
    byte *p = s->block + 4 * i;
    w[i] = ((word)p[0] << 24) | ((word)p[1] << 16) | ((word)p[2] << 8) | p[3];
  }

  // Expand the input into the 64-word message schedule.
  for (int i = 16; i < 64; i++) {
    word x = w[i - 15];
    word y = w[i - 2];
    word sigma0 = ror(x, 7) ^ ror(x, 18) ^ (x >> 3);
    word sigma1 = ror(y, 17) ^ ror(y, 19) ^ (y >> 10);

    w[i] = w[i - 16] + sigma0 + w[i - 7] + sigma1;
  }

  // a through h are the working words used in the SHA-256 specification.
  a = s->h[0];
  b = s->h[1];
  c = s->h[2];
  d = s->h[3];
  e = s->h[4];
  f = s->h[5];
  g = s->h[6];
  h = s->h[7];

  for (int i = 0; i < 64; i++) {
    word sum0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
    word sum1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
    word choose = (e & f) ^ (~e & g);
    word majority = (a & b) ^ (a & c) ^ (b & c);

    t1 = h + sum1 + choose + k[i] + w[i];
    t2 = sum0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  // Accumulate this block into the running hash.
  s->h[0] += a;
  s->h[1] += b;
  s->h[2] += c;
  s->h[3] += d;
  s->h[4] += e;
  s->h[5] += f;
  s->h[6] += g;
  s->h[7] += h;

  secret_clear(w, sizeof(w));
}

static void
sha256_init(struct sha256_context *s)
{
  static const word initial[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                  0xa54ff53a, 0x510e527f, 0x9b05688c,
                                  0x1f83d9ab, 0x5be0cd19};

  for (int i = 0; i < 8; i++)
    s->h[i] = initial[i];

  s->bytes = 0;
  s->used = 0;
}

static void
sha256_update(struct sha256_context *s, const byte *p, word n)
{
  s->bytes += n;

  while (n--) {
    s->block[s->used] = *p;
    s->used++;
    p++;

    if (s->used == 64) {
      sha256_transform(s);
      s->used = 0;
    }
  }
}

static void
sha256_finish(struct sha256_context *s, byte out[32])
{
  unsigned long long bits = s->bytes * 8;
  byte one = 0x80;
  byte zero = 0;
  byte tail[8];

  // Pad to 56 bytes, leaving eight bytes for the original bit length.
  sha256_update(s, &one, 1);
  while (s->used != 56)
    sha256_update(s, &zero, 1);

  for (int i = 0; i < 8; i++)
    tail[7 - i] = bits >> (8 * i);
  sha256_update(s, tail, 8);

  // Serialize the state as a big-endian digest.
  for (int i = 0; i < 32; i++)
    out[i] = s->h[i / 4] >> (24 - 8 * (i % 4));

  secret_clear(s, sizeof(*s));
}

void
sha256(const byte *p, word n, byte *out)
{
  struct sha256_context s;

  sha256_init(&s);
  sha256_update(&s, p, n);
  sha256_finish(&s, out);
}

void
hmac256(const byte *key, word keylen, const byte *p, word n, byte *out)
{
  byte pad[64] = {0};
  byte digest[32];
  struct sha256_context s;

  // Keys longer than one block are hashed before padding.
  if (keylen > 64) {
    sha256(key, keylen, pad);
  } else {
    for (word i = 0; i < keylen; i++)
      pad[i] = key[i];
  }

  // Inner hash: H((key XOR ipad) || message).
  for (int i = 0; i < 64; i++)
    pad[i] ^= 0x36;

  sha256_init(&s);
  sha256_update(&s, pad, 64);
  sha256_update(&s, p, n);
  sha256_finish(&s, digest);

  // Convert ipad to opad, then compute H((key XOR opad) || inner hash).
  for (int i = 0; i < 64; i++)
    pad[i] ^= 0x36 ^ 0x5c;

  sha256_init(&s);
  sha256_update(&s, pad, 64);
  sha256_update(&s, digest, 32);
  sha256_finish(&s, out);

  secret_clear(pad, sizeof(pad));
  secret_clear(digest, sizeof(digest));
}

void
password_hash(const char *password, const byte *salt, word rounds, byte *out)
{
  byte block_input[SALT_LEN + 4];
  byte previous_hash[HASH_LEN];
  word password_length = 0;

  while (password[password_length])
    password_length++;

  // U1 = HMAC(password, salt || block index). Only block 1 is needed.
  for (int i = 0; i < SALT_LEN; i++)
    block_input[i] = salt[i];

  block_input[SALT_LEN] = 0;
  block_input[SALT_LEN + 1] = 0;
  block_input[SALT_LEN + 2] = 0;
  block_input[SALT_LEN + 3] = 1;

  hmac256((const byte *)password, password_length, block_input,
          sizeof(block_input), previous_hash);

  for (int i = 0; i < HASH_LEN; i++)
    out[i] = previous_hash[i];

  // Uj = HMAC(password, Uj-1). The result is U1 XOR U2 XOR ... XOR Urounds.
  for (word round = 1; round < rounds; round++) {
    hmac256((const byte *)password, password_length, previous_hash,
            sizeof(previous_hash), previous_hash);

    for (int i = 0; i < HASH_LEN; i++)
      out[i] ^= previous_hash[i];
  }

  secret_clear(previous_hash, sizeof(previous_hash));
  secret_clear(block_input, sizeof(block_input));
}
