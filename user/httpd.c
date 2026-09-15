//
// httpd: a tiny web server that serves files from the xv6 file system.
//
//   $ httpd &
//
// then, on the host, open http://localhost:8080/ (the Makefile forwards
// host port 8080 to port 80 here). "/" is served as /index.html; any
// other path is looked up as a file, e.g. http://localhost:8080/README
//
// each connection is handled by its own process, HTTP/1.0 style: the
// response says "Connection: close" and the connection is closed after it.
//

#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

#define PORT 80

char reqbuf[2048];
char filebuf[512];

// write all of buf, retrying on short writes.
static int
writeall(int fd, char *buf, int n)
{
  int off = 0;
  while (off < n) {
    int r = write(fd, buf + off, n - off);
    if (r <= 0)
      return -1;
    off += r;
  }
  return 0;
}

// write a string.
static int
writestr(int fd, char *s)
{
  return writeall(fd, s, strlen(s));
}

// write a non-negative decimal number.
static int
writenum(int fd, int v)
{
  char buf[16];
  int i = sizeof(buf);
  buf[--i] = 0;
  do {
    buf[--i] = '0' + v % 10;
    v /= 10;
  } while (v > 0);
  return writestr(fd, buf + i);
}

// read the request until the blank line that ends the headers.
// returns the length, or -1.
static int
readrequest(int c, char *buf, int max)
{
  int n = 0;
  while (n < max - 1) {
    int r = read(c, buf + n, max - 1 - n);
    if (r <= 0)
      return -1;
    n += r;
    buf[n] = 0;
    if (n >= 4 && strcmp(buf + n - 4, "\r\n\r\n") == 0)
      return n;
    // tolerate clients that end lines with just "\n".
    if (n >= 2 && strcmp(buf + n - 2, "\n\n") == 0)
      return n;
  }
  return -1;
}

static char *
contenttype(char *path)
{
  int n = strlen(path);
  if (n >= 5 && strcmp(path + n - 5, ".html") == 0)
    return "text/html";
  return "text/plain";
}

// send a status line, headers and body.
static void
respond(int c, char *status, char *type, int fd, int length)
{
  writestr(c, "HTTP/1.0 ");
  writestr(c, status);
  writestr(c, "\r\nContent-Type: ");
  writestr(c, type);
  writestr(c, "\r\nContent-Length: ");
  writenum(c, length);
  writestr(c, "\r\nConnection: close\r\n\r\n");

  int n;
  while ((n = read(fd, filebuf, sizeof(filebuf))) > 0) {
    if (writeall(c, filebuf, n) < 0)
      break;
  }
}

static void
senderror(int c, char *status, char *body)
{
  writestr(c, "HTTP/1.0 ");
  writestr(c, status);
  writestr(c, "\r\nContent-Type: text/plain\r\nContent-Length: ");
  writenum(c, strlen(body));
  writestr(c, "\r\nConnection: close\r\n\r\n");
  writestr(c, body);
}

// handle one connection: parse "GET /path HTTP/1.x" and send the file.
static void
serve(int c)
{
  if (readrequest(c, reqbuf, sizeof(reqbuf)) < 0)
    return;

  // request line: METHOD SP PATH SP VERSION
  if (strlen(reqbuf) < 4 || memcmp(reqbuf, "GET ", 4) != 0) {
    senderror(c, "405 Method Not Allowed", "only GET is supported\n");
    return;
  }
  char *path = reqbuf + 4;
  char *end = strchr(path, ' ');
  if (end == 0) {
    senderror(c, "400 Bad Request", "bad request line\n");
    return;
  }
  *end = 0;
  if (strcmp(path, "/") == 0)
    path = "/index.html";
  printf("httpd: GET %s\n", path);

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    senderror(c, "404 Not Found", "no such file\n");
    return;
  }
  struct stat st;
  if (fstat(fd, &st) < 0 || st.type != T_FILE) {
    close(fd);
    senderror(c, "404 Not Found", "not a file\n");
    return;
  }
  respond(c, "200 OK", contenttype(path), fd, st.size);
  close(fd);
}

int
main(int argc, char *argv[])
{
  int lfd = listen(PORT);
  if (lfd < 0) {
    fprintf(2, "httpd: listen on port %d failed\n", PORT);
    exit(1);
  }
  printf("httpd: listening on port %d\n", PORT);

  for (;;) {
    int c = accept(lfd);
    if (c < 0) {
      fprintf(2, "httpd: accept failed\n");
      exit(1);
    }

    // serve each connection in its own process, so a connection that
    // never sends a request (browsers open spare ones) cannot hold up
    // the others. fork twice: the child exits at once and is reaped
    // here, the grandchild does the work and is reaped by init.
    int pid = fork();
    if (pid == 0) {
      if (fork() == 0) {
        close(lfd);
        serve(c);
        exit(0); // exit closes c, which closes the connection
      }
      exit(0);
    }
    if (pid > 0)
      wait(0);
    else
      serve(c); // fork failed: serve it here
    close(c);
  }
}
