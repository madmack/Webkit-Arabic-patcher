#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stddef.h>
#include "C/LzmaLib.h"		//to reduce resources size - linked against lzma v9.20 from http://sourceforge.net/projects/sevenzip/files/LZMA%20SDK/lzma920.tar.bz2/download

#define PATCHER_STATUS_OK 0
#define PATCHER_STATUS_ERROR 1
#define PRINT_LOG printf("\n%03d: ",__LINE__);printf
#define MAX(a,b) (a>b)?a:b
#define MIN(a,b) (a<b)?a:b

typedef struct patterns_internal_
{
  int code;
  int numchar;
  char *original;
  char *replacement;
} patterns_internal;

typedef struct patterns_
{
  int numpattern;
  patterns_internal **pattern;
} patterns;


FILE *libwebcore = NULL;
FILE *newlibwebcore = NULL;
FILE *newlibicuuc_arabic = NULL;
unsigned long filesize = 0;
unsigned long dynamic = 0;
unsigned long dynamicnum = 0;
unsigned long sections = 0;
unsigned int secnum = 0;
unsigned int secrec = 0;
unsigned int strtabidx = 0;
unsigned long progs = 0;
unsigned int progssec = 0;
unsigned int progsnum = 0;
unsigned long hdr = 0;
unsigned long secstr = 0;
unsigned long hash = 0;
unsigned long dynsym = 0;
unsigned long dynstr = 0;
unsigned long dynstrsize = 0;
unsigned long numsym = 0;
unsigned long hashbkt = 0;
unsigned long hashchn = 0;
unsigned long hashbkts = 0;
unsigned long hashchns = 0;
unsigned long prelinked_base = 0;
unsigned long JNI_OnLoad = 0;
unsigned long libicuuc_44_available = 0;

unsigned char *nlwc = NULL;

unsigned char nlwc_compressed[] =
  "\x5d\x00\x00\x00\x04\x00\x3f\x91\x45\x84\x68\x3b"
  "\xde\xde\xa6\x11\xc2\x94\xd4\x24\x19\x89\x58\x30"
  "\xb1\x41\x20\xaa\xa1\xf4\xb3\x6a\xc9\xed\xf5\x7b"
  "\x01\xc7\x1c\x9d\x37\x1f\xe0\x82\xb8\xf1\xdb\x42"
  "\x8b\x14\x36\x1f\xb6\x60\x9b\xc4\x5d\x3c\xe6\x96"
  "\x38\x02\x1b\xd9\xd2\xf3\x55\x03\xa5\xb5\x67\x73"
  "\xdf\x5d\x8d\xeb\x61\x60\xff\x3f\x9e\x57\x9a\x31"
  "\xca\xed\x26\x57\x36\x8f\xa6\xcd\x37\xe2\xd3\xb6"
  "\x0c\xe2\x46\x03\xfd\x65\x1d\x5c\xd9\xf5\x56\xa8"
  "\x96\x7d\x1f\xf0\xfa\x94\x63\x01\x48\xce\x1b\x46"
  "\xa2\xe2\x2b\x74\xae\x2a\x62\xdf\x7c\x78\x6b\xfe"
  "\x81\xbe\xe3\xb7\x7a\x30\xea\x30\xc4\x66\x98\xcc"
  "\xff\xea\xf0\xa8\x3b\xac\xce\xa2\xaf\xba\x3f\xe6"
  "\x75\x22\x43\x89\xc4\x8c\xec\xc9\xfd\x52\xb3\x84"
  "\xaf\x64\xd8\x37\xad\x5a\x00\xd1\xb5\xaf\x6a\x1c"
  "\xc9\xfb\x4a\x58\xf7\xc3\xbb\xbc\xb2\xe1\x4d\xff"
  "\xa9\x80\x31\x92\xcb\x37\x71\xf9\x47\x71\xa5\xa0"
  "\xc7\xfc\x6e\x52\x8d\x1b\x4c\x44\x83\x5f\xb2\x2d"
  "\x76\x86\x7e\xbc\xdd\xc6\x6c\x07\x9f\x21\x14\x96"
  "\xa0\xcc\xb1\xe7\x1e\xd3\x08\x60\x5b\xe7\xf1\xa8"
  "\xf4\xef\x7d\xd1\x07\x19\xd1\x34\x6f\x88\x71\x8b"
  "\x89\x1d\x94\x55\x4f\x53\xda\x7a\x36\xd8\x66\xbb"
  "\xca\x9e\x9f\xb3\xa2\xc0\x3b\x71\xc9\x36\xf9\x5a"
  "\x1d\x3a\x35\x51\x51\x80\xb0\x4d\xbb\x89\x18\xc9"
  "\x17\x3d\x10\x0f\x3a\xd3\xdb\xc9\x17\xad\xe6\x87"
  "\xc1\x3d\x52\x1e\x44\x93\x6f\x94\xc9\x87\x5f\xa7"
  "\x8b\x72\x03\xf8\x7c\x1c\x65\xc5\x62\x9b\xb7\x11"
  "\xe5\x55\x96\xe9\xb2\x21\xa6\x8c\x5d\xbf\x83\xfb"
  "\x74\xcb\xa2\xe8\xbd\xcc\x9f\x9e\xc7\x8f\x06\xe3"
  "\x21\xa5\x8f\x68\x3a\x00\xe0\xae\x30\x7a\x02\xd0"
  "\x43\x24\x1c\x49\xfe\x79\x71\xde\xa9\xb3\x29\x05"
  "\x9d\x1b\x1d\xb9\xdc\x6e\x2b\x10\x19\x86\x2c\x5d"
  "\xbe\x4e\xfb\x09\xa0\xe1\xda\x01\x78\x19\x67\x75"
  "\xdc\x21\x66\x2d\x79\xd1\xcd\x08\x01\xa2\x29\xf7"
  "\x8e\xbc\xe6\x0b\xc0\x7f\xaa\x8e\x9d\xfe\x01\xd0"
  "\x77\x78\x12\xd4\x34\xfa\x6e\xa7\x22\x8c\x1b\x7e"
  "\xb7\x60\x5d\xc8\x3e\x71\x3f\xd2\xab\xa8\x7a\x16"
  "\x1e\x22\x0a\x89\xd7\x38\x13\xed\xd6\xe4\x8f\x57"
  "\xb3\x79\xd0\x4f\xe3\xf3\xc2\xeb\xa4\xf4\x65\xd5"
  "\x7b\xf3\xa3\x94\xb0\x0c\xcf\x06\xa9\xc0\x28\x88"
  "\xe9\x2b\x28\x44\x3d\xfb\x5a\xad\x11\x94\x26\x16"
  "\x9a\x8e\x5f\xb8\x17\x87\x95\x4c\xde\xfa\xf3\x12"
  "\x6e\x06\xcc\x92\x0a\xa6\x9c\x08\x30\x6c\x08\xe6"
  "\xd4\xf1\x95\x3f\xfc\x65\x75\xdd\x1f\xbf\xbb\x2d"
  "\xb5\xd2\x9a\xd2\x49\x22\x96\xb9\x09\x1a\x71\x24"
  "\x6f\x29\x08\x02\x9d\xbb\x77\x97\xf1\x18\xbc\x8c"
  "\xa4\x09\x14\xfe\xb1\xe9\x23\x30\x57\x97\x26\xf3"
  "\xa1\xb8\xb1\xe4\xf3\x51\x3e\x60\xe8\x62\x09\x74"
  "\xc6\xa6\x74\xb4\xca\x5e\x42\x77\xb3\x69\x8b\x28"
  "\xbb\x10\xd6\xd0\x3f\x4a\x30\x40\x48\x97\x8f\xb7"
  "\x9f\x22\x7f\x84\xb4\x7e\xd7\x3b\xef\x5c\x92\x1e"
  "\xaf\x6d\xbc\xae\x98\xec\xd5\xc7\x2e\xc3\x61\xb0"
  "\x24\x80\x95\x31\xd2\x3e\x79\x87\x9d\xc3\x5d\xca"
  "\xa3\x72\x38\x0f\xea\xb1\x95\x32\xef\x56\x73\x61"
  "\xbb\x36\xb2\x3b\xc2\xa8\x6f\x8c\xc9\x3f\x9f\xab"
  "\xa8\x7a\xc6\x87\x15\x95\x2d\x45\xa7\x2e\x7f\xb7"
  "\x78\x20\x11\xc6\xed\x16\x2d\x38\x76\x81\x3d\xae"
  "\x48\x81\xf3\xcd\xb0\x5a\x6b\x0d\x6b\x6a\x50\xb5"
  "\x22\x0d\x54\xf2\x98\xe2\xe8\xc8\xa5\x92\xaa\x8e"
  "\x33\x6e\x58\x72\x56\xa4\x79\x14\x0a\x4e\x9b\x0a"
  "\xeb\xfd\x0c\x5e\xe1\xbf\x22\xa8\xec\xc4\x8d\x2b"
  "\x8c\x3a\xb2\x69\x68\xa5\xbf\x32\x3a\x26\xcc\x43"
  "\xaa\x20\x9a\x44\xab\xc1\x35\xba\x42\x9f\x6b\x38"
  "\xfa\x69\xd3\x17\x08\x5a\x66\x6d\x22\xa6\xa9\x6e"
  "\x1a\x5c\xae\x20\xc4\xce\x08\x03\x6b\x95\x18\x77"
  "\x6d\x58\x6a\x91\xc8\x48\xdb\x1a\x18\x3f\x88\xe2"
  "\xdb\x48\xb6\x59\xa0\xbf\xfb\x4f\x7e\xe5\x33\x07"
  "\xfe\xb2\xcb\xcf\x63\x4c\x4d\xbb\xac\x25\x04\x18"
  "\x99\x6c\x58\x6a\x2e\x15\x41\x30\x42\x03\x26\x3a"
  "\x42\x95\xb4\x4d\x16\x87\x5d\x46\xb4\x56\xc3\x00"
  "\x67\xf2\xf4\x7b\x27\xe0\xda\x75\x0f\xf5\x44\xf6"
  "\x52\x89\x46\xdf\x7e\x27\x55\x20\x79\x7d\xf3\xba"
  "\x7d\x8b\xf4\x3b\x89\x4b\xd1\x11\x69\xd9\x66\x2c"
  "\xad\x6a\x42\xb5\x3d\x1e\xa3\x91\xa6\x77\xe0\x28"
  "\x31\x41\xb2\xd4\xac\xd8\xd0\xbb\x5b\x4f\x74\xc7"
  "\x62\xe1\xf2\xfb\xe7\x6a\x76\x95\x01\x9c\x14\x97"
  "\x74\xa5\xda\x54\x8a\x13\x85\x87\x12\xcb\xa6\x3a"
  "\xf6\x3a\x6d\xc6\x5c\x2c\x10\xbf\xa2\xc3\xc1\xca"
  "\x1c\x19\x4e\x73\x1c\x35\x89\x9c\x39\x6c\xd3\x69"
  "\x8d\x25\x54\x8d\x76\x66\xdb\x89\xa8\x2a\x1d\x7e"
  "\xe9\xbb\xb3\x86\x5a\xfb\x5a\x38\xa9\xbb\x08\x87"
  "\x56\x97\xc7\x2e\x7b\x86\x96\x73\x01\x69\xb6\xd3"
  "\xd8\xb9\x88\x6b\xb2\x6c\x26\xba\x56\x09\xaf\x16"
  "\x96\xed\x3d\x75\xf7\xbb\x77\x97\x58\x71\x0c\x8c"
  "\xd4\xbc\xe6\x55\xbf\xe0\x99\x85\x96\x44\xcc\x9e"
  "\x7c\x44\x18\x10\x94\xd3\xc6\x21\xe5\x43\x5a\x2a"
  "\x3b\x16\x71\xc8\xbc\x58\x02\x15\x28\x8d\xc5\xb2"
  "\x2f\xe5\xa0\x88\xd4\x80\xff\x4b\x5f\xd8\x32\xad"
  "\x2a\x5e\xb2\x7c\x09\xc1\x5c\xdd\x87\x6b\xce\x28"
  "\x6f\x61\x91\xc6\x59\x89\x56\x04\xd8\xac\x47\x27"
  "\x5c\x44\x74\x45\xe7\x6b\x83\x9c\x1c\xbb\x00\x24"
  "\x95\xd0\x5b\xb5\x41\x9c\x04\x33\xb5\x0d\xb1\x2c"
  "\xa0\x5b\xbc\xcf\xb5\x55\xd5\x7d\x33\x27\x47\xde"
  "\x5f\xce\x69\x2f\x92\xd3\x5c\xde\x4e\xb4\x55\xb9"
  "\x47\x30\x14\x5a\x5e\xcc\x33\xba\x3a\x84\x6c\x3b"
  "\xd3\xcd\x40\x77\x86\x8a\x9b\xf5\x41\x11\xdc\x96"
  "\xec\x6c\xfc\x69\x4c\xd7\x1e\x6a\xaf\x98\xe6\x50"
  "\xa6\x7f\x47\x59\x99\x93\xdd\x4e\x0d\x80\xc1\x83"
  "\x87\x0f\x72\x31\xbf\x59\x75\xa8\xb2\xe0\x77\xc6"
  "\x82\xec\x87\x38\x39\xaf\xf0\xf6\xa8\xfd\x8a\xd7"
  "\x50\x08\x9e\x49\xfe\x55\x1a\xce\x11\xb3\xd7\x66"
  "\x07\xf6\x5c\xff\x86\x5f\x91\x3f\x68\x00\x1b\x8c"
  "\x2c\x98\xf7\xc4\xb7\xc9\x10\xc1\xca\xfb\x4b\x56"
  "\x49\x6a\xe8\xfe\xf6\xda\xb2\xf5\xd3\xa8\xb0\xa4"
  "\xdb\xcb\xf8\xf6\x0e\xd8\xbc\x50\xb7\x3d\xa0\xf4"
  "\xb1\xc8\x3d\xd9\xdd\x0a\x22\x29\xf9\x33\xfb\xfb"
  "\x35\x76\x40\xf1\xdd\x50\xbe\x12\x1b\x87\x71\x8f"
  "\x5d\x14\x02\x50\xd5\x32\x5b\x29\xf6\x1a\x63\xa6"
  "\x29\x28\x65\xb2\xa4\xdd\x66\xad\x4e\x49\x87\x80"
  "\x2c\xfe\x25\xf7\x28\x7e\xdf\xcc\x42\xc4\x09\xc7"
  "\xc6\xb7\x24\x8c\xfc\x6d\x60\xa8\xe7\x5a\x1f\x03"
  "\x03\xa6\xec\x80\x85\xd2\xe2\xb7\x7c\xea\x77\x2e"
  "\xb9\xd2\x6b\xf9\x11\x85\x3c\xcf\x2d\xab\x7d\xa6"
  "\x05\x0b\x0c\xa9\x2b\x26\xb0\x7b\x88\x1d\x18\x5b"
  "\x2a\x92\x7a\x46\x4d\x2f\xec\x31\x7b\xf8\x4a\x97"
  "\x48\x82\x35\x4c\xbc\xe1\x99\xf4\x3a\x03\xd1\xb5"
  "\xc7\xf4\xd3\x6a\x3f\xd0\x91\x12\xda\x1a\xe4\x0a"
  "\x16\xd4\xb4\x55\x58\x96\x28\x93\xff\x85\x46\x06"
  "\x74\xe9\xc3\xc1\x52\x1a\xe0\xc3\x5a\xdc\xb0\x81"
  "\xcd\xcf\x1f\x97\x3d\x61\x5c\xce\x67\x12\x6a\x3d"
  "\x5c\x3c\xe8\x6a\x06\x2e\x9b\x28\x4c\x90\x24\x7c"
  "\xd2\x55\xba\x02\xf4\x8d\x33\xf6\x20\xc1\x45\xc1"
  "\xe6\x35\x73\x7c\x68\xe2\xb2\xaa\x52\xfc\xf8\x28"
  "\x71\x24\x84\xb7\xd7\xfb\xfc\xbe\x64\x8c\x83\xd0"
  "\xc2\x9e\xfe\xdf\x42\xf1\x4f\x44\xe7\x60\x8f\x3a"
  "\x26\xae\xa7\xee\xc5\x2d\xd6\xa4\x47\x21\x50\xc3"
  "\x48\x0d\x25\xfc\x2e\x29\x75\x3f\xc3\x16\xd6\xcd"
  "\x6f\x5a\x63\x38\x38\xc6\x4b\xba\x9b\x02\x3b\x95"
  "\xed\xf6\x51\x88\x49\x45\x37\x5d\x62\x2b\xe0\xd5"
  "\xf2\xec\x5a\x85\xe0\xe3\xf7\xd1\x43\x3f\x40\xc6"
  "\x48\xf5\xaa\xf7\xec\x69\xb3\x73\x2c\x3f\x11\xd9"
  "\x76\x62\x17\xa0\xc6\x3b\x7b\xb1\x47\x9b\xe8\x3b"
  "\x76\x42\x82\x5c\xb6\x3f\x6b\xa4\x80\xbe\xef\x81"
  "\xbf\xe2\x67\x4a\x06\xa2\x58\x2b\xc8\xeb\x62\xfa"
  "\xed\x82\x06\xb5\x8c\xca\x09\x6f\x49\x9c\xa4\xa0"
  "\x29\xff\xfa\x09\x37\xa7\x70\x39\xf9\x4b\x3f\xf0"
  "\xb5\x04\x33\x29\x4d\x32\x00\xef\x4b\x65\xc3\x85"
  "\xb3\x1d\xd5\x21\xaf\xc5\xe2\x30\xe6\x0f\x83\x32"
  "\x0b\x05\x7c\x69\x45\x93\x0d\x8f\x78\xa5\x2a\xf6"
  "\xfe\xf0\x8c\xe6\xe4\xb8\xa7\x08\xfd\x3c\xd3\x50"
  "\x7b\xe5\x46\x3e\xa4\xea\x68\x44\xd7\x15\xaa\x33"
  "\xd1\x8b\xb4\x44\xbf\x8d\x1f\x70\x5b\x36\xfa\xa7"
  "\xe4\x04\x54\x34\x54\x24\x4a\x81\xf0\x11\xfb\x0a"
  "\xbb\x73\x67\xab\x37\xc4\x47\x77\x9b\x31\x50\x94"
  "\xfa\xb0\x5c\x10\x17\xc8\xdd\xdb\x46\xf8\xaf\x95"
  "\x66\x8a\xd2\x66\x8d\x65\xbe\xc4\xd4\x3e\x0d\x13"
  "\x5b\x30\xd2\xdf\x58\x30\x16\x45\x45\x9e\x6c\xb4"
  "\x94\xc9\xe1\x7a\x9c\xcc\x5e\xa4\xf5\xe8\x0c\x37"
  "\x4a\x46\xf5\xed\xb1\xa7\x43\x62\x85\xa3\xa0\xe0"
  "\xb3\x03\x47\xe0\xed\x29\xbd\x9b\x7b\x54\x55\x60"
  "\xe3\x1c\x77\x8d\x66\x30\xda\x1d\x43\xe1\xa2\x66"
  "\x3a\x02\xaa\x2f\x06\xc9\xb2";

#include "libicuuc-arabic.hex"

unsigned long
elfhash (char *name, unsigned long m)
{
  unsigned long h = 0, g;
  while (*name)
    {
      h = (h << 4) + *name++;
      if (g = h & 0xF0000000)
	h ^= g >> 24;
      h &= ~g;
    }
  return h % m;
}
unsigned long
readdword (FILE * fil)
{
  unsigned long buf = 0;
  unsigned long ret = -1;
  unsigned long cnt = fread (&buf, 1, 4, fil);
  if (cnt == 4)
    ret = buf;
  return ret;
}
unsigned char
readword (FILE * fil)
{
  unsigned int buf = 0;
  unsigned int ret = -1;
  unsigned long cnt = fread (&buf, 1, 2, fil);
  if (cnt == 2)
    ret = buf;
  return ret;
}
unsigned char
readbyte (FILE * fil)
{
  unsigned char buf = 0;
  unsigned char ret = -1;
  unsigned long cnt = fread (&buf, 1, 1, fil);
  if (cnt == 1)
    ret = buf;
  return ret;
}
unsigned long
writedword (FILE * fil, unsigned long wrd)
{
  unsigned long ret = 0;
  unsigned long cnt = fwrite (&wrd, 1, 4, fil);
  if (cnt == 4)
    ret = cnt;
  return ret;
}
unsigned long
writeword (FILE * fil, unsigned int wrd)
{
  unsigned int ret = 0;
  unsigned long cnt = fwrite (&wrd, 1, 2, fil);
  if (cnt == 2)
    ret = cnt;
  return ret;
}
unsigned long
writebyte (FILE * fil, unsigned char byt)
{
  unsigned long ret = 0;
  unsigned long cnt = fwrite (&byt, 1, 1, fil);
  if (cnt == 1)
    ret = cnt;
  return ret;
}
unsigned long
readstring (FILE * fil, char *str, unsigned long len)
{
  unsigned long ret = 0;
  unsigned long cnt = fread (str, 1, len, fil);
  if (cnt == len)
    ret = cnt;
  return ret;
}
unsigned long
writestring (FILE * fil, char *str, unsigned long len)
{
  unsigned long ret = 0;
  unsigned long cnt = fwrite (str, 1, len, fil);
  if (cnt == len)
    ret = cnt;
  return ret;
}

void
update_prog_hdr (FILE * fil)
{
  unsigned int i = 0;
  unsigned char access = 0;
  for (i = 0; i < progsnum; i++)

    {
      fseek (fil, progssec * i + progs + 0x18, SEEK_SET);
      access = readbyte (fil);
      if ((access & 0x1) == 0x1)

	{
	  fseek (fil, progssec * i + progs + 0x18, SEEK_SET);
	  //printf ("prog section # %d access %d\n", i, access);
	  writebyte (fil, access | 0x2);
	}
    }
}
void
update_text_section (FILE * fil)
{
  char *sectionname = malloc (256 * sizeof (char));
  unsigned int i = 0;
  unsigned char access = 0;
  unsigned long sym = 0;
  for (i = 0; i < secnum; i++)

    {
      fseek (fil, secrec * i + sections + 0x8, SEEK_SET);
      access = readbyte (fil);
      fseek (fil, secrec * i + sections + 0x0, SEEK_SET);
      sym = readdword (fil);
      fseek (fil, secstr + sym, SEEK_SET);
      readstring (fil, sectionname, 256);

//printf("%d %s \n",sym,sectionname);
      if (!strcmp (sectionname, ".dynamic"))

	{
	  fseek (fil, secrec * i + sections + 0x10, SEEK_SET);
	  dynamic = readdword (fil);
	  dynamicnum = readdword (fil) >> 2;
	  //printf ("dynamic@ %lx\n", dynamic);
	}
      if (!strcmp (sectionname, ".hash"))

	{
	  fseek (fil, secrec * i + sections + 0x10, SEEK_SET);
	  hash = readdword (fil);
	  fseek (fil, hash, SEEK_SET);
	  hashbkt = hash + 0x8;
	  hashbkts = readdword (fil);
	  hashchns = readdword (fil);
	  hashchn = (hashbkts << 2) + hashbkt;
	  /*
	     printf ("hash@ %lx bkt@ %lx siz %ld chn@ %lx %ld\n", hash,
	     hashbkt, hashbkts, hashchn, hashchns);
	   */
	}
      if (!strcmp (sectionname, ".dynstr"))

	{
	  fseek (fil, secrec * i + sections + 0x10, SEEK_SET);
	  dynstr = readdword (fil);
	  dynstrsize = readdword (fil);
	  //printf ("dynstr pos %lx\n", dynstr);
	  //printf ("dynstrsize %lx\n", dynstrsize);
	}
      if (!strcmp (sectionname, ".dynsym"))

	{
	  fseek (fil, secrec * i + sections + 0x10, SEEK_SET);
	  dynsym = readdword (fil);
	  fseek (fil, secrec * i + sections + 0x14, SEEK_SET);
	  numsym = readdword (fil) >> 4;
	  //printf ("dynsym position %lx num %d\n", dynsym, numsym);
	}
      if ((access & 0x1) == 0x0 && !strcmp (sectionname, ".text"))

	{
	  fseek (fil, secrec * i + sections + 0x8, SEEK_SET);
	  //printf ("section # %d access %d\n", i, access);
	  writebyte (fil, access | 0x1);
	}
    }
  free (sectionname);
}

void
remove_symbol_hash (FILE * fil, char *symbol)
{
  char *symbolname = malloc (256 * sizeof (char));
  unsigned long chn = 0;
  unsigned long nchn = 0;
  unsigned long currsym = 0;
  unsigned long tchn = 0;
  //printf ("elf hash for %s is %lx\n", symbol, elfhash (symbol, hashbkts));
  fseek (fil, hashbkt + (elfhash (symbol, hashbkts) << 2), SEEK_SET);
  chn = 0;
  tchn = 0;
  nchn = readdword (fil);

//printf("%lx \n",chn);

  do

    {
      fseek (fil, dynsym + (nchn << 4) + 0x0, SEEK_SET);
      currsym = readdword (fil);
      fseek (fil, dynstr + currsym, SEEK_SET);
      readstring (fil, symbolname, 256);
      //printf ("[%s] \n", symbolname);
      if (!strcmp (symbolname, symbol))

	{
	  if (chn == 0)

	    {
	      fseek (fil, hashchn + (nchn << 2), SEEK_SET);
	      tchn = readdword (fil);
	      fseek (fil, hashbkt + (elfhash (symbol, hashbkts) << 2),
		     SEEK_SET);
	      writedword (fil, tchn);
	    }

	  else

	    {
	      fseek (fil, hashchn + (nchn << 2), SEEK_SET);
	      tchn = readdword (fil);
	      fseek (fil, hashchn + (chn << 2), SEEK_SET);
	      writedword (fil, tchn);
	    }
	}
      fseek (fil, hashchn + (nchn << 2), SEEK_SET);
      chn = nchn;
      nchn = readdword (fil);
    }
  while (nchn != 0);
  free (symbolname);
}

void
add_symbol_hash (FILE * fil, unsigned long sym, char *symbol)
{
  char *symbolname = malloc (256 * sizeof (char));
  unsigned long chn = 0;
  unsigned long nchn = 0;
  unsigned long currsym = 0;
  unsigned long tchn = 0;
  //printf ("elf hash for %s is %lx\n", symbol, elfhash (symbol, hashbkts));
  fseek (fil, hashbkt + (elfhash (symbol, hashbkts) << 2), SEEK_SET);
  chn = 0;
  tchn = 0;
  nchn = readdword (fil);
  while (nchn != 0)

    {
      fseek (fil, hashchn + (nchn << 2), SEEK_SET);
      chn = nchn;
      nchn = readdword (fil);
    }
  if (chn == 0)

    {
      fseek (fil, hashbkt + (elfhash (symbol, hashbkts) << 2), SEEK_SET);
      writedword (fil, sym);
      fseek (fil, hashchn + (sym << 2), SEEK_SET);
      writedword (fil, 0);
    }

  else

    {
      fseek (fil, hashchn + (chn << 2), SEEK_SET);
      tchn = readdword (fil);
      //printf ("%d hashchain\n", readdword (fil));
      fseek (fil, hashchn + (chn << 2), SEEK_SET);
      writedword (fil, sym);
      fseek (fil, hashchn + (sym << 2), SEEK_SET);
      writedword (fil, 0);
    }
}

unsigned char **
allsymbols (FILE * fil)
{
  unsigned char *symbolnames =
    malloc ((dynstrsize + (numsym << 4)) * sizeof (unsigned char));
  unsigned char **symboltab = malloc ((numsym << 1) * sizeof (void *));
  unsigned char *symbolname = malloc (sizeof (unsigned char) << 8);
  unsigned long currsym = 0;
  unsigned int i = 0;

  fseek (fil, dynstr, SEEK_SET);
  fread (symbolnames, sizeof (unsigned char), dynstrsize, fil);
  fseek (fil, dynsym, SEEK_SET);
  fread (symbolnames + dynstrsize, sizeof (unsigned char), numsym << 4, fil);

  for (i = 0; i < numsym; i++)

    {
      fseek (fil, dynsym + (i << 4) + 0x0, SEEK_SET);
      currsym = readdword (fil);
      *(symboltab + (i << 1) + 0) = symbolnames + currsym;
      *(symboltab + (i << 1) + 1) = symbolnames + dynstrsize + (i << 4);

//symbol names
//printf("%d %s \n",i,symbolname);

    }
  *(symboltab + 0) = symbolnames;
  free (symbolname);
  return symboltab;
}

unsigned long
find_symbol (FILE * fil, char *symbol)
{
  char *symbolname = malloc (256 * sizeof (unsigned char));
  unsigned long currsym = 0;
  unsigned int i = 0;
  unsigned long found = 0;
  for (i = 0; i < numsym; i++)

    {
      fseek (fil, dynsym + (i << 4) + 0x0, SEEK_SET);
      currsym = readdword (fil);
      fseek (fil, dynstr + currsym, SEEK_SET);
      readstring (fil, symbolname, 256);

//symbol names
//printf("%d %s \n",i,symbolname);
      if (!strcmp (symbolname, symbol))

	{
	  found = i;
	  if (!strcmp (symbolname, "JNI_OnLoad"))
	    {
	      fseek (fil, dynsym + (i << 4) + 0x4, SEEK_SET);
	      JNI_OnLoad = readdword (fil);
	    }
	  break;
	}
    }
  free (symbolname);
  return found;
}

void
rename_symbol (FILE * fil, char *symbol, char *newsymbol)
{
  unsigned long currsym = 0;
  unsigned long i = 0;
  if ((i = find_symbol (fil, symbol)) != 0)
    {
      fseek (fil, dynsym + (i << 4) + 0x0, SEEK_SET);
      currsym = readdword (fil);
      remove_symbol_hash (fil, symbol);
      fseek (fil, dynstr + currsym, SEEK_SET);
      writestring (fil, newsymbol, strlen (symbol));
      add_symbol_hash (fil, i, newsymbol);
    }
}

void
rename_library (FILE * fil, char *orglibnam, char *newlibnam)
{
  char *libname = malloc (256 * sizeof (char));
  unsigned long currlib = 0;
  unsigned long currtag = 0;
  unsigned int i = 0;
  for (i = 0; i < dynamicnum; i++)

    {
      fseek (fil, dynamic + (i << 2) + 0x0, SEEK_SET);
      currtag = readdword (fil);
      if (currtag == 0xe || currtag == 0x1)
	{
	  fseek (fil, dynamic + (i << 2) + 0x4, SEEK_SET);
	  currlib = readdword (fil);
	  fseek (fil, dynstr + currlib, SEEK_SET);
	  readstring (fil, libname, 256);
/*      
printf ("tag: %lx lib: %d %s \n", currtag, i, libname);
*/
	  if (!strcmp (libname, orglibnam))

	    {
	      fseek (fil, dynstr + currlib, SEEK_SET);
	      writestring (fil, newlibnam, strlen (newlibnam));
	    }
	}
    }
  free (libname);
}
unsigned long
findpatterns (unsigned char *buffer, unsigned char *pattern,
	      unsigned long length, unsigned long *locations,
	      unsigned long number)
{
  unsigned long found = 0;
  unsigned long i = 0;
  unsigned long j = 0;
  unsigned long flag = 0;
  unsigned long num = 0;
  for (i = 0; i < filesize - length; i++)

    {
      flag = -1;
      for (j = 0; j < length; j++)
	if (buffer[i + j] != pattern[j])
	  {
	    flag = 0;
	    break;
	  }
      if (flag == -1)

	{
	  //printf ("Found pattern!!!\n");
	  locations[num++] = i;
	  found++;
	}
    }
  return found;
}
unsigned long
replace (unsigned char *libwebcore_buffer, FILE * fil, unsigned char *pattern,
	 unsigned char *replacement, unsigned long length)
{
  unsigned long replaced = 0;
  unsigned long locations[] = { 0 };
  findpatterns (libwebcore_buffer, pattern, length, locations, 1);
  //printf ("replacing....!!\n");
  if (locations[0] != 0)
    {
      fseek (fil, locations[0], SEEK_SET);
      fwrite (replacement, 1, length, fil);
      replaced++;
    }
  return replaced;
}

void
copyfile (FILE * fil, unsigned char *newfile)
{
  unsigned char *buffer = malloc (filesize * sizeof (char));
  FILE *nfil = fopen (newfile, "wb");
  fseek (fil, 0, SEEK_SET);
  fread (buffer, 1, filesize, fil);
  fwrite (buffer, 1, filesize, nfil);
  fclose (nfil);
  free (buffer);
}

unsigned char *
read_file (FILE * fil)
{
  unsigned char *buffer = malloc (filesize * sizeof (unsigned char));
  fseek (fil, 0, SEEK_SET);
  fread (buffer, 1, filesize, fil);
  return buffer;
}

void
write_libicuuc_arabic (char *name)
{
  unsigned char *newfile = malloc (256 * sizeof (char));
  unsigned char *citer = NULL;
  unsigned char *bkslash = NULL;
  strcpy (nlwc + 0x409, "-arabic.so");
  printf
    ("You will need to use libicuuc-arabic.so because your libicuuc.so is not supported!\n");


  strcpy (newfile, name);
  for (citer = newfile; *citer != NULL; citer++)
    {
      if (*citer == '\\' || *citer == '/')
	bkslash = citer;
    }
  if (bkslash != NULL)
    {
      *(++bkslash) = NULL;
      strcat (newfile, "libicuuc-arabic.so");
    }
  else
    strcpy (newfile, "libicuuc-arabic.so");

  newlibicuuc_arabic = fopen (newfile, "wb");
  fwrite (libicuuc_arabic, 1, 186260, newlibicuuc_arabic);
  fclose (newlibicuuc_arabic);
  free (newfile);
}

/*
void
Compress1 (int *outBufSize, char *outBuf, int inBufSize, char *inBuf)
{
  unsigned propsSize = LZMA_PROPS_SIZE;
  unsigned destLen = inBufSize + inBufSize / 3 + 128;

  int res = LzmaCompress (&outBuf[LZMA_PROPS_SIZE], &destLen,
			  &inBuf[0], inBufSize,
			  &outBuf[0], &propsSize,
			  9, 0, -1, -1, -1, -1, -1);
  *outBufSize = destLen + propsSize;
}
*/

static void
Uncompress1 (int *outBufSize, char *outBuf, int inBufSize, char *inBuf)
{
  unsigned dstLen = -1;
  unsigned srcLen = inBufSize - LZMA_PROPS_SIZE;
  SRes res = LzmaUncompress (&outBuf[0], &dstLen,
			     &inBuf[LZMA_PROPS_SIZE], &srcLen,
			     &inBuf[0], LZMA_PROPS_SIZE);
  *outBufSize = dstLen;
}

unsigned long
attemptDisableComplex_drawText (int argc, char *argv[],
				char *libwebcore_buffer)
{
  unsigned long status = -1;

  patterns a;
  patterns_internal *b;
  int ti;

  a.numpattern = 5;
  a.pattern = (patterns_internal **) malloc (sizeof (void *) * a.numpattern);
  b = malloc (sizeof (patterns_internal));
  b->code = 0;
  b->numchar = 10;
  b->original = "\x50\xB1\x20\x46\x29\x46\x32\x46\x3B\x46";
  b->replacement = "\xC0\x46\x20\x46\x29\x46\x32\x46\x3B\x46";
  a.pattern[0] = b;

  b = malloc (sizeof (patterns_internal));
  b->code = 1;
  b->numchar = 10;
  b->original = "\x00\x28\x09\xD0\x0A\x98\x03\x99\x2A\x1C";
  b->replacement = "\x00\x28\xc0\x46\x0A\x98\x03\x99\x2A\x1C";
  a.pattern[1] = b;

  b = malloc (sizeof (patterns_internal));
  b->code = 2;
  b->numchar = 10;
  b->original = "\x00\x28\x09\xD0\x0A\x98\x03\x99\x00\x90";
  b->replacement = "\x00\x28\xc0\x46\x0A\x98\x03\x99\x00\x90";
  a.pattern[2] = b;

  b = malloc (sizeof (patterns_internal));
  b->code = 3;
  b->numchar = 10;
  b->original = "\x40\xB1\x00\x93\x20\x46\x61\x46\x2A\x46";
  b->replacement = "\xc0\x46\x00\x93\x20\x46\x61\x46\x2A\x46";
  a.pattern[3] = b;

  b = malloc (sizeof (patterns_internal));
  b->code = 4;
  b->numchar = 16;
  b->original =
    "\x00\x00\x50\xE3\x07\x00\x00\x1A\x04\x00\xA0\xE1\x0A\x10\xA0\xE1";
  b->replacement =
    "\x00\x00\x50\xE3\x07\x00\x00\xEA\x04\x00\xA0\xE1\x0A\x10\xA0\xE1";
  a.pattern[4] = b;


  printf ("Attempting to disable complex drawText: ");

  for (ti = 0; ti < a.numpattern; ti++)
    {
      if (replace
	  (libwebcore_buffer, libwebcore, a.pattern[ti]->original,
	   a.pattern[ti]->replacement, a.pattern[ti]->numchar) != 0)
	{
	  status = a.pattern[ti]->code;
	  break;
	}

    }
  if (status == -1)
    printf ("Failed!\n");
  else
    printf ("Succeeded %ld!\n", status);





  for (ti = 0; ti < a.numpattern; ti++)
    {
//free (a.pattern[ti]->original);
//free (a.pattern[ti]->replacement);
      free (a.pattern[ti]);
    }
  free (a.pattern);


  return (status == -1 ? 0 : -1);
}

unsigned long
PachLibwebcore (unsigned char *p_buffer, FILE * p_file,
		unsigned long sizeofbuffer)
{
  unsigned long found = -1;

  unsigned long status = PATCHER_STATUS_ERROR;

  patterns a;
  patterns_internal *b;
  int ti;

  a.numpattern = 3;
  a.pattern = (patterns_internal **) malloc (sizeof (void *) * a.numpattern);
  b = malloc (sizeof (patterns_internal));
  b->code = 0;
  b->numchar = 6;
  b->original = "\x33\x9a\x42\x31\xd9\x30";
  b->replacement = "\x33\x9a\x42\x25\xd9\x30";
  a.pattern[0] = b;

  b = malloc (sizeof (patterns_internal));
  b->code = 1;
  b->numchar = 10;
  b->original = "\xf2\xcf\x50\x83\x42\x32\xd9\x30\x30\x83";
  b->replacement = "\xf2\x90\x50\x83\x42\x32\xd9\x6f\x30\x83";
  a.pattern[1] = b;

  b = malloc (sizeof (patterns_internal));
  b->code = 2;
  b->numchar = 10;
  b->original = "\x57\x40\xf2\xcf\x56\x40\xf2\xff\x55\x41";
  b->replacement = "\x57\x40\xf2\x00\x56\x40\xf2\xff\x55\x41";
  a.pattern[2] = b;


  printf ("Attempting to apply hebrew patch to libwebcore: ");

  if (libwebcore != NULL)
    {

      for (ti = 0; ti < a.numpattern; ti++)
	{
	  if (replace
	      (p_buffer, libwebcore, a.pattern[ti]->original,
	       a.pattern[ti]->replacement, a.pattern[ti]->numchar) != 0)
	    {
	      found = a.pattern[ti]->code;
	      status = PATCHER_STATUS_OK;
	      break;
	    }

	}
      if (status == PATCHER_STATUS_ERROR)
	printf ("Failed!\n");
      else
	printf ("Succeeded %ld (%s)!\n", found,
		found == 0 ? "Not Optimized Type" : found ==
		1 ? "Optimized Type 1" : "Optimized Type 2");


    }
  else
    {
      PRINT_LOG ("Failed to open lib__bcore.so");
    }


  for (ti = 0; ti < a.numpattern; ti++)
    {
//free (a.pattern[ti]->original);
//free (a.pattern[ti]->replacement);
      free (a.pattern[ti]);
    }
  free (a.pattern);



  return status;





}

unsigned long
attemptWebkit_Arabic_Patch (int argc, char *argv[])
{
  unsigned char *newfile = malloc (256 * sizeof (unsigned char));
  unsigned char *tempstr = malloc (sizeof (unsigned char) << 8);
  unsigned char *libwebcore_buffer = NULL;
  unsigned char *citer = NULL;
  unsigned char *bkslash = NULL;
  unsigned long iter = 0;

  unsigned char *patterns2[] = {
    "\x80\x68\x88\xB0\x0A\x68\x00\x25\x43\x69\x06\xA8\x0D\x60\x19\x46",
    "\x88\xB0\x80\x68\x0A\x68\x43\x69\x00\x25\x06\xA8\x0D\x60\x19\x46",
    "\x80\x68\x0A\x68\x88\xB0\x46\x69\x00\x25\x0D\x60\x06\xA8\x31\x1C",
    "\x80\x68\x88\xB0\x0A\x68\x46\x69\x00\x25\x0D\x60\x06\xA8\x31\x1c",
    "\x80\x68\x88\xB0\x0A\x68\x06\x69\x00\x25\x0D\x60\x06\xA8\x31\x1C",
    "\x80\x68\x0A\x68\x88\xB0\x06\x69\x00\x25\x0D\x60\x06\xA8\x31\x1C",
    "\x80\x68\x0A\x68\x06\x69\x88\xB0\x00\x25\x0D\x60\x06\xA8\x31\x1C",
    "\x80\x68\x0A\x68\xD0\xF8\x14\xC0\x00\x25\x06\xA8\x0D\x60\x61\x46",
    "\x88\xB0\x0A\x68\x00\x25\xD0\xF8\x14\xC0\x06\xA8\x0D\x60\x61\x46",
    "\x1C\x20\x8D\xE2\x1C\x30\x8D\xE5\xF9\x64\x06\xEB\x20\x70\x94\xE5",
    "\x09\x98\x06\xF7\x62\xF9\x23\x6A\x07\x93\x13\xB1\x1E\x68\x71\x1C",
    "\x2B\x6A\x2E\x1C\x20\x36\x07\x93\x00\x2B\x02\xD0\x19\x68\x01\x31",
    "\x05\x1C\x00\x20\x08\x60\x20\x36\x19\x1C\x07\x92\x20\x1C\x07\xAA",
    "\x20\x06\x04\x46\x2B\x69\x06\xAD\x00\x20\x08\x60\x19\x46\x07\x92"
  };

  unsigned char *patterns22[] = {
    "\x22\x6A\x00\x23\x50\x68\x91\x68\x1A\x46\x03\xE0\x30\xF8\x13\x50",
    "\x25\x6A\x00\x22\x00\x23\xA8\x68\x69\x68\x03\xE0\x0E\x88\x01\x32",
    "\x25\x6A\x00\x23\x00\x22\xA8\x68\x69\x68\x03\xE0\x0E\x88\x01\x32",
    "\x25\x6A\x00\x22\xA8\x68\x69\x68\x00\x23\x03\xE0\x0e\x88\x01\x32",
    "\xD4\xF8\x20\xE0\x00\x23\xDE\xF8\x04\x00\xDE\xF8\x08\x10\x1A\x46",
    "\xD4\xF8\x20\xE0\x00\x23\x1A\x46\xDE\xF8\x04\x00\xDE\xF8\x08\x10",
    "\x20\x30\x94\xE5\x08\x00\x93\xE5\x04\xC0\x93\xE5\x00\x00\x50\xE3",
    "\x2E\x6A\x00\x22\xB0\x68\x71\x68\x00\x23\x03\xE0\x0C\x88\x01\x32",
    "\x2E\x6A\x00\x22\x00\x23\x70\x68\xB1\x68\x03\xE0\x0C\x88\x01\x32",
    "\x28\x6A\xFF\xF7\x1F\xFC\x38\x35\x2E\x78\xC3\x01\x7F\x20\x06\x40",
    "\xD4\xF8\x20\xC0\x00\x23\x1A\x46\xDC\xF8\x08\x00\xDC\xF8\x04\x10"
  };

  unsigned char *patterns3[] = {
    "\x4F\xF6\x80\x7E\x94\xF8\x38\x00\x02\xEA\x0E\x0C\x94\xF8\x39\x30",
    "\x94\xF8\x38\x00\x94\xF8\x39\x30\x4F\xF6\x80\x7E\x6F\xF3\x00\x03",
    "\x01\x32\x02\x31\x3B\x43\x82\x42\xF9\xD3\x10\x4E\x27\x1C\x38\x37",
    "\x02\x31\x2B\x43\x82\x42\xF9\xD3\x11\x4F\x22\x1C\x38\x32\x10\x78",
    "\x2B\x43\x02\x31\x82\x42\xf9\xd3\x11\x4f\x22\x1c\x38\x32\x10\x78",
    "\x29\x78\x40\x22\x99\x43\x29\x70\x2E\x78\x96\x43\x2E\x70\x20\x6a",
    "\x02\x31\x3B\x43\x82\x42\xF9\xD3\x27\x1C\x38\x37\x0F\x4E\x38\x78",
    "\x4F\xF6\x80\x7E\x94\xF8\x38\x00\x05\xEA\x0E\x02\x94\xF8\x39\x30",
    "\x94\xF8\x38\x00\x94\xF8\x39\x30\x4F\xF6\x80\x7C\x6F\xF3\x00\x03",
    "\x4F\xF6\x80\x7C\x94\xF8\x38\x00\x02\xEA\x0C\x0E\x94\xF8\x39\x30",
    "\x02\x31\x2B\x43\x82\x42\xF9\xD3\x22\x1C\x38\x32\x10\x4F\x10\x78",
    "\x22\x38\xA0\xE1\x01\x20\x73\xE2\x00\x20\xA0\x33\x38\xE0\xD4\xE5",
    "\x39\xE0\x01\x93\x13\xB1\x19\x68\x48\x1C\x18\x60\x68\x46\x01\xA9",
    "\x2E\x1C\x20\x36\x01\x93\x00\x2B\x02\xD0\x1F\x68\x01\x37\x1F\x60",
    "\x01\x32\x02\x31\x3B\x43\x82\x42\xF9\xD3\x27\x1C\x38\x37\x0F\x49",
    "\x82\x42\xF9\xD3\x11\x4A\x26\x1C\x38\x36\x30\x78\x13\x40\x59\x42",
    "\x0e\x02\x8B\x42\xF8\xD3\x4F\xF6\x80\x70\x94\xF8\x38\xE0\x02\xEA"
  };

  unsigned char *patterns32[] = {
    "\x00\x23\x03\x60\x43\x60\x83\x60\xC3\x60\x70\x47\x81\x68\x4B\x69",
    "\x03\x60\x43\x60\x83\x60\xC3\x60\x70\x47\xC0\x46\x81\x68\x4B\x69",
    "\x03\x60\x43\x60\x83\x60\xC3\x60\x70\x47\xC0\x46\x81\x68\x0B\x69",
    "\x00\x23\x03\x60\x43\x60\x83\x60\xC3\x60\x70\x47\x81\x68\x4B\x69",
    "\x04\x30\x80\xE5\x08\x30\x80\xE5\x1E\xFF\x2F\xE1\x08\x10\x90\xE5",
    "\x00\x23\x03\x60\x43\x60\x83\x60\xC3\x60\x70\x47\x81\x68\x0B\x69"
  };

  unsigned char jumpPatchARM32[] =
    "\x04x70\x2d\xe5\x00\x70\x9f\xe5\x17\xff\x2f\xe1";

  unsigned long locations1[] = { 0 };
  unsigned long locations2[] = { 0, 0 };
  unsigned long locations12[] = { 0 };
  unsigned long locations22[] = { 0 };
  unsigned long temp = 0;
  unsigned long mode = 1;	//Default 1=Thumb, 0=ARM32 bit
  unsigned long prefroyo = 0;
  unsigned long status = 0;
  enum patch_types
  { v0 = 0, v1 = 1, v2 = 2, v3 = 3, v4 = 4, v5 = 5, v6 = 6, v7 = 7, v8 =
      8, v9 = 9, v10 = 10, v11 = 11, unknown = -1
  } patch_type = unknown;

  nlwc = malloc (5284);
  Uncompress1 (&temp, nlwc, 1819, nlwc_compressed);

  libicuuc_arabic = malloc (186260);
  Uncompress1 (&temp, libicuuc_arabic, 55659, libicuuc_arabic_compressed);

  printf
    ("This patch (v3.8BETA) was developed by Brightidea @ xda-dev on 15th of Aug '2011\n");
  printf
    ("My thread's URL: http://forum.xda-developers.com/showthread.php?t=1218960\n");
  printf
    ("Thanks to Madmack for making this possible by sharing his method on the blog http://blog.devasque.com/\n\n");
  printf
    ("NOTE: I can neither gurantee it'll work nor claim it won't harm your system\n\n");
  printf ("*USE AT YOUR OWN RISK*\n\n");
  if (argc == 1)
    {
      printf ("Usage: webkit_arabic_patch.exe [path]\\libwebcore.so\n");
      free (newfile);
      free (tempstr);
      free (libicuuc_arabic);
      free (nlwc);
      newfile = NULL;
      tempstr = NULL;
      libicuuc_arabic = NULL;
      nlwc = NULL;
      status |= 1 | 2;
      return status;
    }
  libwebcore = fopen (argv[1], "rb+");
  if (libwebcore == NULL)
    {
      printf ("Error opening file");
      free (newfile);
      free (tempstr);
      free (libicuuc_arabic);
      free (nlwc);
      newfile = NULL;
      tempstr = NULL;
      libicuuc_arabic = NULL;
      nlwc = NULL;
      status |= 1 | 2;
      return status;
    }
  hdr = readdword (libwebcore);
  if (hdr != 0x464c457fL)

    {
      printf ("Error in shared object header!\n");
      fclose (libwebcore);
      libwebcore = NULL;
      free (newfile);
      free (tempstr);
      free (libicuuc_arabic);
      free (nlwc);
      newfile = NULL;
      tempstr = NULL;
      libicuuc_arabic = NULL;
      nlwc = NULL;
      status |= 1 | 2;
      return status;
    }
  printf ("Applying patch...\n");
  fseek (libwebcore, 0, SEEK_END);
  filesize = ftell (libwebcore);
  if (filesize == 0)
    {
      printf ("error opening file..\n");
      fclose (libwebcore);
      libwebcore = NULL;
      free (newfile);
      free (tempstr);
      free (libicuuc_arabic);
      free (nlwc);
      newfile = NULL;
      tempstr = NULL;
      libicuuc_arabic = NULL;
      nlwc = NULL;
      status |= 1 | 2;
      return status;
    }
  libwebcore_buffer = read_file (libwebcore);
  strcpy (newfile, argv[1]);
  strcat (newfile, ".bak");
  copyfile (libwebcore, newfile);
  fseek (libwebcore, 0x1c, SEEK_SET);
  progs = readdword (libwebcore);
  fseek (libwebcore, 0x20, SEEK_SET);
  sections = readdword (libwebcore);
  fseek (libwebcore, 0x2a, SEEK_SET);
  progssec = readword (libwebcore);
  fseek (libwebcore, 0x2c, SEEK_SET);
  progsnum = readword (libwebcore);
  fseek (libwebcore, 0x2e, SEEK_SET);
  secrec = readword (libwebcore);
  fseek (libwebcore, 0x30, SEEK_SET);
  secnum = readword (libwebcore);
  fseek (libwebcore, 0x32, SEEK_SET);
  strtabidx = readword (libwebcore);
  fseek (libwebcore, secrec * strtabidx + sections + 0x10, SEEK_SET);
  secstr = readdword (libwebcore);
  /*
     printf
     ("sections %d  record size %d  file position %lx  string table index %d\n",
     secnum, secrec, sections, strtabidx);
     printf ("progs %d  record size %d  file position %lx\n", progsnum,
     progssec, progs);
     printf ("secstr %lx\n", secstr);
   */
  update_prog_hdr (libwebcore);
  if (filesize >= secrec * secnum + sections + 8)

    {
      //fseek (libwebcore, secrec * secnum + sections, SEEK_SET);//this method fails with some retouched shared objects
      fseek (libwebcore, -8, SEEK_END);	//another technique which works better as far as I can tell
      *(tempstr + 8) = '\0';
      fread (tempstr, sizeof (unsigned char), 8, libwebcore);
      if (!strncmp ("PRE ", tempstr + 4, 4))
	{
	  prelinked_base = *((unsigned long *) tempstr);
	  printf ("Pre-linked ELF detected - prelink address @ %lx\n",
		  prelinked_base);
	}
    }
  update_text_section (libwebcore);
  libicuuc_44_available = (find_symbol (libwebcore, "u_tolower_44") != 0);

  printf ("libicuuc.so v4.4 Available?: %s\n",
	  libicuuc_44_available ? "Yes" : "No");

  attemptDisableComplex_drawText (argc, argv, libwebcore_buffer);

  for (iter = 0; iter < 14; iter++)
    {
      memset (locations1, 0, sizeof (unsigned long) * 1);
      findpatterns (libwebcore_buffer, patterns2[iter], 16, locations1, 1);
      if (locations1[0] != 0)
	break;
    }

  for (iter = 0; iter < 11; iter++)
    {
      memset (locations12, 0, sizeof (unsigned long) * 1);
      findpatterns (libwebcore_buffer, patterns22[iter], 16, locations12, 1);
      if (locations12[0] != 0)
	break;
    }

  for (iter = 0; iter < 17; iter++)
    {
      memset (locations2, 0, sizeof (unsigned long) * 2);
      findpatterns (libwebcore_buffer, patterns3[iter], 16, locations2, 2);
      if (locations2[0] != 0 && locations2[1] != 0)
	break;
    }
  if (iter < 17)
    printf ("found %d!", iter);
  else
    printf ("not found!");

  switch (iter)
    {
    case 0:
    case 1:
      patch_type = v0;
      printf ("sgs2 and like! -");
      break;
    case 2:
    case 3:
    case 4:
      patch_type = v1;
      printf ("armv6 (omnia, sgs 3, etc..) -");
      break;
    case 5:
      patch_type = v10;
      printf ("HTC ??? and like -");
    case 6:
      patch_type = v11;
      printf ("sg y and like -");
    case 7:
    case 8:
    case 9:
      patch_type = v2;
      printf ("archos, htc desire z, arm v6 and like -");
      break;
    case 10:
      patch_type = v3;
      printf ("superpad 2 and like -");
      break;
    case 11:
      patch_type = v4;
      printf ("joker rom and like -");
      break;
    case 12:
      patch_type = v5;
      printf ("test and like -");
      break;
    case 13:
      patch_type = v6;
      printf ("galaxy spica and like -");
      break;
    case 14:
      patch_type = v7;
      printf ("arm v6 and like -");
      break;
    case 15:
      patch_type = v8;
      printf ("HTC Magic and like -");
      break;
    case 16:
      patch_type = v9;
      printf ("Nook touch and like -");
      break;
    default:
      printf ("undetermined! - ");
      break;
    }

  for (iter = 0; iter < 6; iter++)
    {
      memset (locations22, 0, sizeof (unsigned long) * 1);
      findpatterns (libwebcore_buffer, patterns32[iter], 16, locations22, 1);
      if (locations22[0] != 0)
	break;
    }

  if (!libicuuc_44_available)
    write_libicuuc_arabic (argv[1]);

  switch (patch_type)
    {
    case v0:
      break;
    case v1:
      *(unsigned long *) (nlwc + 0x810) = 0xe1933001;
      *(unsigned long *) (nlwc + 0x814) = 0xe5c43019;
      *(unsigned long *) (nlwc + 0x82c) = 0xe5902078;
      *(unsigned long *) (nlwc + 0x880) = 0xe1933001;
      *(unsigned long *) (nlwc + 0x884) = 0xe5c43019;
      *(unsigned long *) (nlwc + 0x89c) = 0xe5902078;
      break;
    case v2:
      *(unsigned long *) (nlwc + 0x814) = 0xe5c4e019;
      *(unsigned long *) (nlwc + 0x884) = 0xe5c4e019;
      break;
    case v3:
      *(unsigned long *) (nlwc + 0x80c) = 0xe1900001;
      *(unsigned long *) (nlwc + 0x810) = 0xe5c40019;
      *(unsigned long *) (nlwc + 0x814) = 0xe1b00004;
      *(unsigned long *) (nlwc + 0x82c) = 0xe59f300c;
      *(unsigned long *) (nlwc + 0x840) = 0x000001cd;
      *(unsigned long *) (nlwc + 0x87c) = 0xe1900001;
      *(unsigned long *) (nlwc + 0x880) = 0xe5c40019;
      *(unsigned long *) (nlwc + 0x884) = 0xe1b00004;
      *(unsigned long *) (nlwc + 0x89c) = 0xe59f300c;
      *(unsigned long *) (nlwc + 0x8b0) = 0x000001cd;
      break;
    case v4:
      *(unsigned long *) (nlwc + 0x7a4) = 0xe5d3202a;
      *(unsigned long *) (nlwc + 0x7ac) = 0xe1a00000;
      *(unsigned long *) (nlwc + 0x814) = 0xe5c4e019;
      *(unsigned long *) (nlwc + 0x82c) = 0xe5901078;
      *(unsigned long *) (nlwc + 0x884) = 0xe5c4e019;
      *(unsigned long *) (nlwc + 0x89c) = 0xe5901078;
      mode = 0;			//arm32bit
      break;
    case v5:
      *(unsigned long *) (nlwc + 0x82c) = 0xe3b02001;
      *(unsigned long *) (nlwc + 0x89c) = 0xe3b02001;
      break;
    case v6:
      *(unsigned long *) (nlwc + 0x77c) = 0xe5805000;
      *(unsigned long *) (nlwc + 0x794) = 0xe5953004;
      *(unsigned long *) (nlwc + 0x7f4) = 0xe5805000;
      *(unsigned long *) (nlwc + 0x864) = 0xe5805000;

      *(unsigned long *) (nlwc + 0x80c) = 0xe1b00005;
      *(unsigned long *) (nlwc + 0x810) = 0xe1944002;
      *(unsigned long *) (nlwc + 0x814) = 0xe5c54019;
      *(unsigned long *) (nlwc + 0x82c) = 0xe59f300c;
      *(unsigned long *) (nlwc + 0x840) = 0x000001cd;

      *(unsigned long *) (nlwc + 0x87c) = 0xe1b00005;
      *(unsigned long *) (nlwc + 0x880) = 0xe1944002;
      *(unsigned long *) (nlwc + 0x884) = 0xe5c54019;
      *(unsigned long *) (nlwc + 0x89c) = 0xe59f300c;
      *(unsigned long *) (nlwc + 0x8b0) = 0x000001cd;


      break;
    case v7:
      *(unsigned long *) (nlwc + 0x80c) = 0xe1900001;
      *(unsigned long *) (nlwc + 0x810) = 0xe5c40019;
      *(unsigned long *) (nlwc + 0x814) = 0xe1b00004;
      *(unsigned long *) (nlwc + 0x82c) = 0xe59f300c;
      *(unsigned long *) (nlwc + 0x840) = 0x000001cd;
      *(unsigned long *) (nlwc + 0x87c) = 0xe1900001;
      *(unsigned long *) (nlwc + 0x880) = 0xe5c40019;
      *(unsigned long *) (nlwc + 0x884) = 0xe1b00004;
      *(unsigned long *) (nlwc + 0x89c) = 0xe59f300c;
      *(unsigned long *) (nlwc + 0x8b0) = 0x000001cd;
      break;
    case v8:
      *(unsigned long *) (nlwc + 0x77c) = 0xe5805000;
      *(unsigned long *) (nlwc + 0x794) = 0xe5953004;
      *(unsigned long *) (nlwc + 0x7a4) = 0xe5D31029;

      *(unsigned long *) (nlwc + 0x810) = 0xe1933001;
      *(unsigned long *) (nlwc + 0x814) = 0xe5c43019;
      *(unsigned long *) (nlwc + 0x828) = 0xE2800008;
      *(unsigned long *) (nlwc + 0x82C) = 0xE590207C;

      *(unsigned long *) (nlwc + 0x880) = 0xe1933001;
      *(unsigned long *) (nlwc + 0x884) = 0xe5c43019;
      *(unsigned long *) (nlwc + 0x898) = 0xE2800008;
      *(unsigned long *) (nlwc + 0x89C) = 0xE590207C;

      prefroyo = 1;

      break;
    case v9:
      *(unsigned long *) (nlwc + 0x7a4) = 0xe5D31029;
      *(unsigned long *) (nlwc + 0x7b8) = 0xe3530002;

      *(unsigned long *) (nlwc + 0x80c) = 0xe5c40019;
      *(unsigned long *) (nlwc + 0x810) = 0xe5c4c039;
      *(unsigned long *) (nlwc + 0x814) = 0xe1a00004;
      *(unsigned long *) (nlwc + 0x82c) = 0xe1a00000;


      prefroyo = 1;
      break;

    case v10:
      *(unsigned long *) (nlwc + 0x77c) = 0xe5805000;
      *(unsigned long *) (nlwc + 0x794) = 0xe5953004;
      *(unsigned long *) (nlwc + 0x7a4) = 0xe5D31029;

      *(unsigned long *) (nlwc + 0x810) = 0xe1933000;
      *(unsigned long *) (nlwc + 0x814) = 0xe5c40019;
      *(unsigned long *) (nlwc + 0x828) = 0xE2800008;
      *(unsigned long *) (nlwc + 0x82C) = 0xE590607C;

      *(unsigned long *) (nlwc + 0x880) = 0xe1933000;
      *(unsigned long *) (nlwc + 0x884) = 0xe5c40019;
      *(unsigned long *) (nlwc + 0x898) = 0xE2800008;
      *(unsigned long *) (nlwc + 0x89C) = 0xE590607C;

//prefroyo = 1;

      break;
    case v11:
      *(unsigned long *) (nlwc + 0x80c) = 0xe1933001;
      *(unsigned long *) (nlwc + 0x814) = 0xe5c43019;
      *(unsigned long *) (nlwc + 0x830) = 0xe5902078;
      *(unsigned long *) (nlwc + 0x82c) = 0xe28dd00c;
      *(unsigned long *) (nlwc + 0x87c) = 0xe1933001;
      *(unsigned long *) (nlwc + 0x884) = 0xe5c43019;
      *(unsigned long *) (nlwc + 0x8A0) = 0xe5902078;
      *(unsigned long *) (nlwc + 0x89c) = 0xe28dd00c;

      break;
    default:			//v0
      break;
    }


  if (prefroyo != 0)
    {				//Starting from Froyo StringImpl.h reverses the order of m_data (class object displacement @4, index 1) and m_length (class/object displacement @8, index 2)
      *(unsigned long *) (nlwc + 0xb58) = 0xE5910004;
      *(unsigned long *) (nlwc + 0xb78) = 0xE5931004;
      *(unsigned long *) (nlwc + 0xb84) = 0xE5930008;


      *(unsigned long *) (nlwc + 0xb98) = 0xeaffffd7;

      *(unsigned long *) (nlwc + 0xafc) = 0xe595e000;
      *(unsigned long *) (nlwc + 0xb00) = 0xe59e0008;
      *(unsigned long *) (nlwc + 0xb04) = 0xea000024;
      *(unsigned long *) (nlwc + 0xba0) = 0xe59ec004;
    }

  if (mode == 0)		//ARM32bit modifications
    {
      memcpy (nlwc + 0xbbc, jumpPatchARM32, 12 * sizeof (unsigned char));

      nlwc[0x914] = 0x18;
      nlwc[0x91c] = 0x10;
      nlwc[0x940] = 0x18;
      nlwc[0x944] = 0x10;
      nlwc[0x968] = 0x18;
      nlwc[0x96c] = 0x10;
    }

  printf
    ("pattern1 @ %lx, pattern2 @ %lx & %lx, pattern12 @ %lx, pattern22 @ %lx\n",
     locations1[0], locations2[0], locations2[1], locations12[0],
     locations22[0]);

  printf
    ("Now attempting Hebrew Patch by Erasmux, Mena and Classicaldude from www.iandroid.co.il ..\n");
  status |= (PachLibwebcore (libwebcore_buffer, libwebcore, filesize) << 1);

  strcpy (newfile, argv[1]);
  for (citer = newfile; *citer != NULL; citer++)
    {
      if (*citer == '\\' || *citer == '/')
	bkslash = citer;
    }
  if (bkslash != NULL)
    {
      *(++bkslash) = NULL;
      strcat (newfile, "lib__bcore.so");
    }
  else
    memcpy (newfile + 3, "__", 2 * sizeof (unsigned char));

  printf ("\nNow attempting to create libwebcore.so...\n");
  if (locations1[0] == 0 || locations2[0] == 0 || locations2[1] == 0
      || locations12[0] == 0 || locations22[0] == 0)
    {
      printf ("Could not find all patching points!\n");
      fclose (libwebcore);
      libwebcore = NULL;
      free (newfile);
      free (tempstr);
      free (libicuuc_arabic);
      free (nlwc);
      free (libwebcore_buffer);
      newfile = NULL;
      tempstr = NULL;
      libicuuc_arabic = NULL;
      nlwc = NULL;
      libwebcore_buffer = NULL;
      status |= 1;
      return status;
    }
  else
    {
      printf ("\nWriting file %s\n", newfile);
      rename_symbol (libwebcore, "JNI_OnLoad", "__I_OnLoad");
      printf ("JNI_OnLoad @ %lx\n", JNI_OnLoad);
      rename_library (libwebcore, "libwebcore.so", "lib__bcore.so");
      fclose (libwebcore);
      libwebcore = NULL;
      remove (newfile);
      rename (argv[1], newfile);

    }

  newlibwebcore = fopen (argv[1], "wb");

  temp = locations1[0] - JNI_OnLoad + 0x30 + 1 + (mode == 1 ? 0 : 0);
  memcpy (&nlwc[0x9c4], &temp, 4 * sizeof (unsigned char));
  temp = locations1[0] - JNI_OnLoad + 0x30 + 1 + 0xe + (mode == 1 ? 0 : 1);
  memcpy (&nlwc[0xa10], &temp, 4 * sizeof (unsigned char));
  temp = locations12[0] - JNI_OnLoad + 1 + (mode == 1 ? 0 : -1);
  memcpy (&nlwc[0xa14], &temp, 4 * sizeof (unsigned char));
  temp = locations2[0] - JNI_OnLoad + 0x30 + 1 + (mode == 1 ? 0 : 0);
  memcpy (&nlwc[0x9cc], &temp, 4 * sizeof (unsigned char));
  temp = locations2[0] - JNI_OnLoad + 0x30 + 1 + 0xc + (mode == 1 ? 0 : 3);
  memcpy (&nlwc[0xa20], &temp, 4 * sizeof (unsigned char));
  temp = locations22[0] - JNI_OnLoad + 1 + 0xc + (mode == 1 ? 0 : -1);
  memcpy (&nlwc[0xa1c], &temp, 4 * sizeof (unsigned char));
  temp = locations2[1] - JNI_OnLoad + 0x30 + 1 + (mode == 1 ? 0 : 0);
  memcpy (&nlwc[0x9d4], &temp, 4 * sizeof (unsigned char));
  temp = locations2[1] - JNI_OnLoad + 0x30 + 1 + 0xc + (mode == 1 ? 0 : 3);
  memcpy (&nlwc[0xa28], &temp, 4 * sizeof (unsigned char));
  fwrite (nlwc, 1, 5284, newlibwebcore);
  printf ("...Complete...!!\n");
  fclose (newlibwebcore);
  newlibwebcore = NULL;
  free (newfile);
  free (tempstr);
  free (libwebcore_buffer);
  free (libicuuc_arabic);
  free (nlwc);
  return status;
}

unsigned long
tryOptimizedLibandroid_Emad (unsigned char *p_buffer,
			     unsigned long sizeofbuffer,
			     unsigned long prelink_base_runtime)
{
  unsigned long status = PATCHER_STATUS_ERROR;
  unsigned char native_drawtext[] = "native_drawText";
  unsigned char signature[] = "(I[CIIFFI)V";
  unsigned long a_native_drawtext[32];
  unsigned long a_signature[32];
  unsigned long a_patterns[32];
  unsigned long n_native_drawtext = 0;
  unsigned long n_signature = 0;
  unsigned long n_patterns = 0;
  unsigned long i = 0;
  unsigned long j = 0;
  unsigned long k = 0;
  unsigned long found = 0;
  unsigned long pattern[2];
  memset (a_native_drawtext, 0, sizeof (a_native_drawtext));
  memset (a_signature, 0, sizeof (a_native_drawtext));
  memset (a_patterns, 0, sizeof (a_patterns));
  memset (pattern, 0, sizeof (pattern));

  for (i = 0; i < (sizeofbuffer - sizeof (native_drawtext)); i++)
    {

      if (!memcmp (p_buffer + i, native_drawtext, sizeof (native_drawtext)))
	a_native_drawtext[n_native_drawtext++] = i + prelink_base_runtime;

      if (!memcmp (p_buffer + i, signature, sizeof (signature)))
	a_signature[n_signature++] = i + prelink_base_runtime;

    }

  for (i = 0; i < n_native_drawtext; i++)
    for (j = 0; j < n_signature; j++)
      {
	pattern[0] = a_native_drawtext[i];
	pattern[1] = a_signature[j];
	for (k = 0; k < (sizeofbuffer - sizeof (pattern)); k += 4)
	  if (!memcmp (p_buffer + k, pattern, sizeof (pattern)))
	    {
	      a_patterns[n_patterns++] = k;
	    }

      }

  for (i = 0; i < n_patterns; i++)
    {
      memcpy (pattern, p_buffer + a_patterns[i], sizeof (unsigned long));
      PRINT_LOG
	("found (and patched) matching location @ %lx for native_drawText @ %lx signature @ %lx\n",
	 a_patterns[i], pattern[0], pattern[1]);
      pattern[0] += 7;
      memcpy (p_buffer + a_patterns[i], pattern, sizeof (unsigned long));
      found++;
      status = PATCHER_STATUS_OK;
    }

  if (found == 0)
    {
      PRINT_LOG ("Didn't find native_drawtext");
      PRINT_LOG ("Didn't find pointer to drawText");
    }
  return status;
}

unsigned long
tryNotOptimizedLibandroid_Emad (unsigned char *p_buffer,
				unsigned long sizeofbuffer,
				unsigned long prelink_base_runtime)
{
  unsigned long status = PATCHER_STATUS_ERROR;
  unsigned char native_drawtext[] = "native_drawText";
  unsigned char drawtext[] = "drawText";
  unsigned char signature[] =
    "(Ljava/lang/String;FFLandroid/graphics/Paint;)V";
  unsigned long a_drawtext[32];
  unsigned long a_native_drawtext[32];
  unsigned long a_signature[32];
  unsigned long a_patterns[32];
  unsigned long n_drawtext = 0;
  unsigned long n_native_drawtext = 0;
  unsigned long n_signature = 0;
  unsigned long n_patterns = 0;
  unsigned long i = 0;
  unsigned long j = 0;
  unsigned long k = 0;
  unsigned long found = 0;
  unsigned long pattern[2];
  memset (a_drawtext, 0, sizeof (a_native_drawtext));
  memset (a_native_drawtext, 0, sizeof (a_native_drawtext));
  memset (a_signature, 0, sizeof (a_native_drawtext));
  memset (a_patterns, 0, sizeof (a_patterns));
  memset (pattern, 0, sizeof (pattern));

  for (i = 0; i < (sizeofbuffer - sizeof (native_drawtext)); i++)
    {

      if (!memcmp (p_buffer + i, drawtext, sizeof (drawtext)))
	a_drawtext[n_drawtext++] = i + prelink_base_runtime;

      if (!memcmp (p_buffer + i, native_drawtext, sizeof (native_drawtext)))
	a_native_drawtext[n_native_drawtext++] = i + prelink_base_runtime;

      if (!memcmp (p_buffer + i, signature, sizeof (signature)))
	a_signature[n_signature++] = i + prelink_base_runtime;

    }

  for (i = 0; i < n_drawtext; i++)
    for (j = 0; j < n_signature; j++)
      {
	pattern[0] = a_drawtext[i];
	pattern[1] = a_signature[j];
	for (k = 0; k < (sizeofbuffer - sizeof (pattern)); k += 4)
	  if (!memcmp (p_buffer + k, pattern, sizeof (pattern)))
	    {
	      a_patterns[n_patterns++] = k;
	    }

      }

  for (i = 0; i < n_patterns; i++)
    {
      memcpy (pattern, p_buffer + a_patterns[i], sizeof (unsigned long));
      PRINT_LOG
	("found (and patched) matching location @ %lx for drawText @ %lx signature @ %lx\n",
	 a_patterns[i], pattern[0], pattern[1]);
      pattern[0] = a_native_drawtext[0];
      memcpy (p_buffer + a_patterns[i], pattern, sizeof (unsigned long));
      found++;
      status = PATCHER_STATUS_OK;
    }

  if (found == 0)
    {
      PRINT_LOG ("Didn't find native_drawtext");
      PRINT_LOG ("Didn't find pointer to drawText");
    }
  return status;
}

unsigned long
PachLibAndroidRuntime (int argc, char *argv[])
{
  unsigned long status = PATCHER_STATUS_ERROR;
  unsigned long lSize;
  unsigned long result;
  unsigned long prelink_base_runtime = 0;
  unsigned char *p_buffer = NULL;
  unsigned long found = 0;
  FILE *pFile;
  unsigned int sizeofbuffer;
  unsigned char *newfile = malloc (256 * sizeof (char));
  unsigned char *citer = NULL;
  unsigned char *bkslash = NULL;

  if (argc == 2)
    strcpy (newfile, argv[1]);
  else
    strcpy (newfile, "libandroid_runtime.so");

  for (citer = newfile; *citer != NULL; citer++)
    {
      if (*citer == '\\' || *citer == '/')
	bkslash = citer;
    }
  if (bkslash != NULL)
    {
      *(++bkslash) = NULL;
      strcat (newfile, "libandroid_runtime.so");
    }
  else
    strcpy (newfile, "libandroid_runtime.so");


  pFile = fopen (newfile, "r+b");
  if (pFile != NULL)
    {
      PRINT_LOG
	("Now attempting libandroid_runtime.so patch - this part had a complete rework by Brightidea");
      PRINT_LOG
	("Message from the original developers of Libpatcher:\nFor more questions please visit, http://iandroid.co.il/forum/topic5657.html");
      PRINT_LOG
	("A lot of work was spent on this program if it helped you ,please consider donating");

      PRINT_LOG ("Trying to patch %s", newfile);
      PRINT_LOG ("File libandroid_runtime.so successfully opened");
      fseek (pFile, 0, SEEK_END);
      lSize = ftell (pFile);
      p_buffer = malloc (sizeof (unsigned char) * lSize);
      sizeofbuffer = lSize;
      PRINT_LOG ("Size of file libandroid_runtime.so is %d", lSize);
      fseek (pFile, 0, SEEK_SET);
      result = fread (p_buffer, 1, lSize, pFile);
      fclose (pFile);

      if (!strncmp ("PRE ", p_buffer + lSize - 4, 4))
	{

	  prelink_base_runtime = *((unsigned long *) (p_buffer + lSize - 8));
	  PRINT_LOG ("Pre-linked ELF detected - prelink address @ %lx\n",
		     prelink_base_runtime);

	}

      PRINT_LOG ("Read %d bytes from file error=%d ", result, ferror (pFile));

      if (tryNotOptimizedLibandroid_Emad
	  (p_buffer, sizeofbuffer, prelink_base_runtime) == PATCHER_STATUS_OK)
	{
	  found = 1;
	  PRINT_LOG ("File libandroid_runtime.so type is :  Not Optimized ");

	}
      else
	if (tryOptimizedLibandroid_Emad
	    (p_buffer, sizeofbuffer,
	     prelink_base_runtime) == PATCHER_STATUS_OK)
	{
	  found = 1;
	  PRINT_LOG ("File libandroid_runtime.so type is :  Optimized ");

	}

      if (found == 1)
	{
	  strcpy (newfile + strlen (newfile) - 3, "_fixed.so");
	  pFile = fopen (newfile, "w+b");
	  if (pFile != NULL)
	    {
	      PRINT_LOG ("File patched!");
	      PRINT_LOG ("Wrote %d bytes to file libandroid_runtime_fixed.so",
			 fwrite ((void *) p_buffer, 1, lSize, pFile));
	      fclose (pFile);
	      status = PATCHER_STATUS_OK;
	    }
	  else
	    {
	      printf ("failed to open create libandroid_runtime_fixed.so");
	      status = PATCHER_STATUS_ERROR;
	    }
	}
      else
	{
	  PRINT_LOG ("Sorry, couldn't pach the file libandroid_runtime.so");
	  status = PATCHER_STATUS_ERROR;
	}

    }
  else
    {
//      PRINT_LOG ("Failed to  open file libandroid_runtime.so");
      status = PATCHER_STATUS_ERROR;
    }
  if (p_buffer != NULL)
    {
      free (p_buffer);
      p_buffer = NULL;
    }
  free (newfile);
  return status;
}

int
main (int argc, char *argv[])
{
  int status = 0;

/*
int outlen = 0;
char *buffer22 = NULL;

buffer22=malloc(5284);
Compress1(&outlen,buffer22,5284,nlwc);

newlibwebcore = fopen ("libwebcore-compressed.so", "wb");
fwrite (buffer22, 1, outlen, newlibwebcore);
fclose (newlibwebcore);
free(buffer22);

buffer22=malloc(186260);
Compress1(&outlen,buffer22,186260,libicuuc_arabic);

newlibicuuc_arabic = fopen ("libicuuc-arabic-compressed.so", "wb");
fwrite (buffer22, 1, outlen, newlibicuuc_arabic);
fclose (newlibicuuc_arabic);
free(buffer22);

buffer22=malloc(5284);
Uncompress1(&outlen,buffer22,1819,nlwc_compressed);

newlibwebcore = fopen ("libwebcore-uncompressed.so", "wb");
fwrite (buffer22, 1, outlen, newlibwebcore);
fclose (newlibwebcore);
free(buffer22);

buffer22=malloc(186260);
Uncompress1(&outlen,buffer22,55659,libicuuc_arabic_compressed);
                 
newlibicuuc_arabic = fopen ("libicuuc-arabic-uncompressed.so", "wb");
fwrite (buffer22, 1, outlen, newlibicuuc_arabic);
fclose (newlibicuuc_arabic);
free(buffer22);
*/

  status = attemptWebkit_Arabic_Patch (argc, argv);
  status |= (PachLibAndroidRuntime (argc, argv) << 2);
  return status;
}
