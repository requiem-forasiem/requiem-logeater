/* Test of POSIX compatible vsnprintf() and snprintf() functions.
   Copyright (C) 2007-2010 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Bruno Haible <bruno@clisp.org>, 2007.  */

#include "nan.h"

/* The SGI MIPS floating-point format does not distinguish 0.0 and -0.0.  */
static int
have_minus_zero ()
{
  static double plus_zero = 0.0;
  double minus_zero = - plus_zero;
  return memcmp (&plus_zero, &minus_zero, sizeof (double)) != 0;
}

/* HP cc on HP-UX 10.20 has a bug with the constant expression -0.0.
   So we use -zerod instead.  */
double zerod = 0.0;

/* On HP-UX 10.20, negating 0.0L does not yield -0.0L.
   So we use minus_zerol instead.
   IRIX cc can't put -0.0L into .data, but can compute at runtime.
   Note that the expression -LDBL_MIN * LDBL_MIN does not work on other
   platforms, such as when cross-compiling to PowerPC on MacOS X 10.5.  */
#if defined __hpux || defined __sgi
static long double
compute_minus_zerol (void)
{
  return -LDBL_MIN * LDBL_MIN;
}
# define minus_zerol compute_minus_zerol ()
#else
long double minus_zerol = -0.0L;
#endif

/* Representation of an 80-bit 'long double' as an initializer for a sequence
   of 'unsigned int' words.  */
#ifdef WORDS_BIGENDIAN
# define LDBL80_WORDS(exponent,manthi,mantlo) \
    { ((unsigned int) (exponent) << 16) | ((unsigned int) (manthi) >> 16), \
      ((unsigned int) (manthi) << 16) | (unsigned int) (mantlo) >> 16),    \
      (unsigned int) (mantlo) << 16                                        \
    }
#else
# define LDBL80_WORDS(exponent,manthi,mantlo) \
    { mantlo, manthi, exponent }
#endif

static int
strmatch (const char *pattern, const char *string)
{
  if (strlen (pattern) != strlen (string))
    return 0;
  for (; *pattern != '\0'; pattern++, string++)
    if (*pattern != '*' && *string != *pattern)
      return 0;
  return 1;
}

/* Test whether string[start_index..end_index-1] is a valid textual
   representation of NaN.  */
static int
strisnan (const char *string, size_t start_index, size_t end_index, int uppercase)
{
  if (start_index < end_index)
    {
      if (string[start_index] == '-')
        start_index++;
      if (start_index + 3 <= end_index
          && memcmp (string + start_index, uppercase ? "NAN" : "nan", 3) == 0)
        {
          start_index += 3;
          if (start_index == end_index
              || (string[start_index] == '(' && string[end_index - 1] == ')'))
            return 1;
        }
    }
  return 0;
}

static void
test_function (int (*my_snprintf) (char *, size_t, const char *, ...))
{
  char buf[8];
  int size;

  /* Test return value convention.  */

  for (size = 0; size <= 8; size++)
    {
      int retval;

      memcpy (buf, "DEADBEEF", 8);
      retval = my_snprintf (buf, size, "%d", 12345);
      ASSERT (retval == 5);
      if (size < 6)
        {
          if (size > 0)
            {
              ASSERT (memcmp (buf, "12345", size - 1) == 0);
              ASSERT (buf[size - 1] == '\0');
            }
          ASSERT (memcmp (buf + size, "DEADBEEF" + size, 8 - size) == 0);
        }
      else
        {
          ASSERT (memcmp (buf, "12345\0EF", 8) == 0);
        }
    }

  /* Test support of size specifiers as in C99.  */

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%ju %d", (uintmax_t) 12345671, 33, 44, 55);
    ASSERT (strcmp (result, "12345671 33") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%zu %d", (size_t) 12345672, 33, 44, 55);
    ASSERT (strcmp (result, "12345672 33") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%tu %d", (ptrdiff_t) 12345673, 33, 44, 55);
    ASSERT (strcmp (result, "12345673 33") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", (long double) 1.5, 33, 44, 55);
    ASSERT (strcmp (result, "1.5 33") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the 'a' and 'A' conversion specifier for hexadecimal
     output of floating-point numbers.  */

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%a %d", 3.1416015625, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.922p+1 33") == 0
            || strcmp (result, "0x3.244p+0 33") == 0
            || strcmp (result, "0x6.488p-1 33") == 0
            || strcmp (result, "0xc.91p-2 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%A %d", -3.1416015625, 33, 44, 55);
    ASSERT (strcmp (result, "-0X1.922P+1 33") == 0
            || strcmp (result, "-0X3.244P+0 33") == 0
            || strcmp (result, "-0X6.488P-1 33") == 0
            || strcmp (result, "-0XC.91P-2 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%a %d", 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "0x0p+0 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%a %d", -zerod, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0x0p+0 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%a %d", 1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "inf 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%a %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "-inf 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%a %d", NaNd (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding near the decimal point.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.0a %d", 1.5, 33, 44, 55);
    ASSERT (strcmp (result, "0x2p+0 33") == 0
            || strcmp (result, "0x3p-1 33") == 0
            || strcmp (result, "0x6p-2 33") == 0
            || strcmp (result, "0xcp-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding with precision 0.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.0a %d", 1.51, 33, 44, 55);
    ASSERT (strcmp (result, "0x2p+0 33") == 0
            || strcmp (result, "0x3p-1 33") == 0
            || strcmp (result, "0x6p-2 33") == 0
            || strcmp (result, "0xcp-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding with precision 1.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.1a %d", 1.51, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.8p+0 33") == 0
            || strcmp (result, "0x3.0p-1 33") == 0
            || strcmp (result, "0x6.1p-2 33") == 0
            || strcmp (result, "0xc.1p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding with precision 2.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2a %d", 1.51, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.83p+0 33") == 0
            || strcmp (result, "0x3.05p-1 33") == 0
            || strcmp (result, "0x6.0ap-2 33") == 0
            || strcmp (result, "0xc.14p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding with precision 3.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.3a %d", 1.51, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.829p+0 33") == 0
            || strcmp (result, "0x3.052p-1 33") == 0
            || strcmp (result, "0x6.0a4p-2 33") == 0
            || strcmp (result, "0xc.148p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding can turn a ...FFF into a ...000.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.3a %d", 1.49999, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.800p+0 33") == 0
            || strcmp (result, "0x3.000p-1 33") == 0
            || strcmp (result, "0x6.000p-2 33") == 0
            || strcmp (result, "0xc.000p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding can turn a ...FFF into a ...000.
       This shows a MacOS X 10.3.9 (Darwin 7.9) bug.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.1a %d", 1.999, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.0p+1 33") == 0
            || strcmp (result, "0x2.0p+0 33") == 0
            || strcmp (result, "0x4.0p-1 33") == 0
            || strcmp (result, "0x8.0p-2 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Width.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%10a %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "  0x1.cp+0 33") == 0
            || strcmp (result, "  0x3.8p-1 33") == 0
            || strcmp (result, "    0x7p-2 33") == 0
            || strcmp (result, "    0xep-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Small precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.10a %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.c000000000p+0 33") == 0
            || strcmp (result, "0x3.8000000000p-1 33") == 0
            || strcmp (result, "0x7.0000000000p-2 33") == 0
            || strcmp (result, "0xe.0000000000p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Large precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.50a %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.c0000000000000000000000000000000000000000000000000p+0 33") == 0
            || strcmp (result, "0x3.80000000000000000000000000000000000000000000000000p-1 33") == 0
            || strcmp (result, "0x7.00000000000000000000000000000000000000000000000000p-2 33") == 0
            || strcmp (result, "0xe.00000000000000000000000000000000000000000000000000p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_LEFT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%-10a %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.cp+0   33") == 0
            || strcmp (result, "0x3.8p-1   33") == 0
            || strcmp (result, "0x7p-2     33") == 0
            || strcmp (result, "0xep-3     33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SHOWSIGN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%+a %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "+0x1.cp+0 33") == 0
            || strcmp (result, "+0x3.8p-1 33") == 0
            || strcmp (result, "+0x7p-2 33") == 0
            || strcmp (result, "+0xep-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SPACE.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "% a %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, " 0x1.cp+0 33") == 0
            || strcmp (result, " 0x3.8p-1 33") == 0
            || strcmp (result, " 0x7p-2 33") == 0
            || strcmp (result, " 0xep-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#a %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.cp+0 33") == 0
            || strcmp (result, "0x3.8p-1 33") == 0
            || strcmp (result, "0x7.p-2 33") == 0
            || strcmp (result, "0xe.p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#a %d", 1.0, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.p+0 33") == 0
            || strcmp (result, "0x2.p-1 33") == 0
            || strcmp (result, "0x4.p-2 33") == 0
            || strcmp (result, "0x8.p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with finite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%010a %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "0x001.cp+0 33") == 0
            || strcmp (result, "0x003.8p-1 33") == 0
            || strcmp (result, "0x00007p-2 33") == 0
            || strcmp (result, "0x0000ep-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%010a %d", 1.0 / 0.0, 33, 44, 55);
    /* "0000000inf 33" is not a valid result; see
       <http://lists.gnu.org/archive/html/bug-gnulib/2007-04/msg00107.html> */
    ASSERT (strcmp (result, "       inf 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%050a %d", NaNd (), 33, 44, 55);
    /* "0000000nan 33" is not a valid result; see
       <http://lists.gnu.org/archive/html/bug-gnulib/2007-04/msg00107.html> */
    ASSERT (strlen (result) == 50 + 3
            && strisnan (result, strspn (result, " "), strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", 3.1416015625L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.922p+1 33") == 0
            || strcmp (result, "0x3.244p+0 33") == 0
            || strcmp (result, "0x6.488p-1 33") == 0
            || strcmp (result, "0xc.91p-2 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LA %d", -3.1416015625L, 33, 44, 55);
    ASSERT (strcmp (result, "-0X1.922P+1 33") == 0
            || strcmp (result, "-0X3.244P+0 33") == 0
            || strcmp (result, "-0X6.488P-1 33") == 0
            || strcmp (result, "-0XC.91P-2 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "0x0p+0 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", minus_zerol, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0x0p+0 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", 1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "inf 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "-inf 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", NaNl (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
#if CHECK_PRINTF_SAFE && ((defined __ia64 && LDBL_MANT_DIG == 64) || (defined __x86_64__ || defined __amd64__) || (defined __i386 || defined __i386__ || defined _I386 || defined _M_IX86 || defined _X86_))
  { /* Quiet NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0xC3333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  {
    /* Signalling NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x83333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  /* The isnanl function should recognize Pseudo-NaNs, Pseudo-Infinities,
     Pseudo-Zeroes, Unnormalized Numbers, and Pseudo-Denormals, as defined in
       Intel IA-64 Architecture Software Developer's Manual, Volume 1:
       Application Architecture.
       Table 5-2 "Floating-Point Register Encodings"
       Figure 5-6 "Memory to Floating-Point Register Data Translation"
   */
  { /* Pseudo-NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x40000001, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Infinity.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x00000000, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Zero.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x4004, 0x00000000, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Unnormalized number.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x4000, 0x63333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Denormal.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x0000, 0x83333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%La %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
#endif

  { /* Rounding near the decimal point.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.0La %d", 1.5L, 33, 44, 55);
    ASSERT (strcmp (result, "0x2p+0 33") == 0
            || strcmp (result, "0x3p-1 33") == 0
            || strcmp (result, "0x6p-2 33") == 0
            || strcmp (result, "0xcp-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding with precision 0.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.0La %d", 1.51L, 33, 44, 55);
    ASSERT (strcmp (result, "0x2p+0 33") == 0
            || strcmp (result, "0x3p-1 33") == 0
            || strcmp (result, "0x6p-2 33") == 0
            || strcmp (result, "0xcp-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding with precision 1.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.1La %d", 1.51L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.8p+0 33") == 0
            || strcmp (result, "0x3.0p-1 33") == 0
            || strcmp (result, "0x6.1p-2 33") == 0
            || strcmp (result, "0xc.1p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding with precision 2.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2La %d", 1.51L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.83p+0 33") == 0
            || strcmp (result, "0x3.05p-1 33") == 0
            || strcmp (result, "0x6.0ap-2 33") == 0
            || strcmp (result, "0xc.14p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding with precision 3.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.3La %d", 1.51L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.829p+0 33") == 0
            || strcmp (result, "0x3.052p-1 33") == 0
            || strcmp (result, "0x6.0a4p-2 33") == 0
            || strcmp (result, "0xc.148p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding can turn a ...FFF into a ...000.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.3La %d", 1.49999L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.800p+0 33") == 0
            || strcmp (result, "0x3.000p-1 33") == 0
            || strcmp (result, "0x6.000p-2 33") == 0
            || strcmp (result, "0xc.000p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Rounding can turn a ...FFF into a ...000.
       This shows a MacOS X 10.3.9 (Darwin 7.9) bug and a
       glibc 2.4 bug <http://sourceware.org/bugzilla/show_bug.cgi?id=2908>.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.1La %d", 1.999L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.0p+1 33") == 0
            || strcmp (result, "0x2.0p+0 33") == 0
            || strcmp (result, "0x4.0p-1 33") == 0
            || strcmp (result, "0x8.0p-2 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Width.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%10La %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "  0x1.cp+0 33") == 0
            || strcmp (result, "  0x3.8p-1 33") == 0
            || strcmp (result, "    0x7p-2 33") == 0
            || strcmp (result, "    0xep-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Small precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.10La %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.c000000000p+0 33") == 0
            || strcmp (result, "0x3.8000000000p-1 33") == 0
            || strcmp (result, "0x7.0000000000p-2 33") == 0
            || strcmp (result, "0xe.0000000000p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Large precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.50La %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.c0000000000000000000000000000000000000000000000000p+0 33") == 0
            || strcmp (result, "0x3.80000000000000000000000000000000000000000000000000p-1 33") == 0
            || strcmp (result, "0x7.00000000000000000000000000000000000000000000000000p-2 33") == 0
            || strcmp (result, "0xe.00000000000000000000000000000000000000000000000000p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_LEFT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%-10La %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.cp+0   33") == 0
            || strcmp (result, "0x3.8p-1   33") == 0
            || strcmp (result, "0x7p-2     33") == 0
            || strcmp (result, "0xep-3     33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SHOWSIGN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%+La %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "+0x1.cp+0 33") == 0
            || strcmp (result, "+0x3.8p-1 33") == 0
            || strcmp (result, "+0x7p-2 33") == 0
            || strcmp (result, "+0xep-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SPACE.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "% La %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, " 0x1.cp+0 33") == 0
            || strcmp (result, " 0x3.8p-1 33") == 0
            || strcmp (result, " 0x7p-2 33") == 0
            || strcmp (result, " 0xep-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#La %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.cp+0 33") == 0
            || strcmp (result, "0x3.8p-1 33") == 0
            || strcmp (result, "0x7.p-2 33") == 0
            || strcmp (result, "0xe.p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#La %d", 1.0L, 33, 44, 55);
    ASSERT (strcmp (result, "0x1.p+0 33") == 0
            || strcmp (result, "0x2.p-1 33") == 0
            || strcmp (result, "0x4.p-2 33") == 0
            || strcmp (result, "0x8.p-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with finite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%010La %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "0x001.cp+0 33") == 0
            || strcmp (result, "0x003.8p-1 33") == 0
            || strcmp (result, "0x00007p-2 33") == 0
            || strcmp (result, "0x0000ep-3 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%010La %d", 1.0L / 0.0L, 33, 44, 55);
    /* "0000000inf 33" is not a valid result; see
       <http://lists.gnu.org/archive/html/bug-gnulib/2007-04/msg00107.html> */
    ASSERT (strcmp (result, "       inf 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%050La %d", NaNl (), 33, 44, 55);
    /* "0000000nan 33" is not a valid result; see
       <http://lists.gnu.org/archive/html/bug-gnulib/2007-04/msg00107.html> */
    ASSERT (strlen (result) == 50 + 3
            && strisnan (result, strspn (result, " "), strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the %f format directive.  */

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%f %d", 12.75, 33, 44, 55);
    ASSERT (strcmp (result, "12.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A larger positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%f %d", 1234567.0, 33, 44, 55);
    ASSERT (strcmp (result, "1234567.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Small and large positive numbers.  */
    static struct { double value; const char *string; } data[] =
      {
        { 1.234321234321234e-37, "0.000000" },
        { 1.234321234321234e-36, "0.000000" },
        { 1.234321234321234e-35, "0.000000" },
        { 1.234321234321234e-34, "0.000000" },
        { 1.234321234321234e-33, "0.000000" },
        { 1.234321234321234e-32, "0.000000" },
        { 1.234321234321234e-31, "0.000000" },
        { 1.234321234321234e-30, "0.000000" },
        { 1.234321234321234e-29, "0.000000" },
        { 1.234321234321234e-28, "0.000000" },
        { 1.234321234321234e-27, "0.000000" },
        { 1.234321234321234e-26, "0.000000" },
        { 1.234321234321234e-25, "0.000000" },
        { 1.234321234321234e-24, "0.000000" },
        { 1.234321234321234e-23, "0.000000" },
        { 1.234321234321234e-22, "0.000000" },
        { 1.234321234321234e-21, "0.000000" },
        { 1.234321234321234e-20, "0.000000" },
        { 1.234321234321234e-19, "0.000000" },
        { 1.234321234321234e-18, "0.000000" },
        { 1.234321234321234e-17, "0.000000" },
        { 1.234321234321234e-16, "0.000000" },
        { 1.234321234321234e-15, "0.000000" },
        { 1.234321234321234e-14, "0.000000" },
        { 1.234321234321234e-13, "0.000000" },
        { 1.234321234321234e-12, "0.000000" },
        { 1.234321234321234e-11, "0.000000" },
        { 1.234321234321234e-10, "0.000000" },
        { 1.234321234321234e-9, "0.000000" },
        { 1.234321234321234e-8, "0.000000" },
        { 1.234321234321234e-7, "0.000000" },
        { 1.234321234321234e-6, "0.000001" },
        { 1.234321234321234e-5, "0.000012" },
        { 1.234321234321234e-4, "0.000123" },
        { 1.234321234321234e-3, "0.001234" },
        { 1.234321234321234e-2, "0.012343" },
        { 1.234321234321234e-1, "0.123432" },
        { 1.234321234321234, "1.234321" },
        { 1.234321234321234e1, "12.343212" },
        { 1.234321234321234e2, "123.432123" },
        { 1.234321234321234e3, "1234.321234" },
        { 1.234321234321234e4, "12343.212343" },
        { 1.234321234321234e5, "123432.123432" },
        { 1.234321234321234e6, "1234321.234321" },
        { 1.234321234321234e7, "12343212.343212" },
        { 1.234321234321234e8, "123432123.432123" },
        { 1.234321234321234e9, "1234321234.321234" },
        { 1.234321234321234e10, "12343212343.2123**" },
        { 1.234321234321234e11, "123432123432.123***" },
        { 1.234321234321234e12, "1234321234321.23****" },
        { 1.234321234321234e13, "12343212343212.3*****" },
        { 1.234321234321234e14, "123432123432123.******" },
        { 1.234321234321234e15, "1234321234321234.000000" },
        { 1.234321234321234e16, "123432123432123**.000000" },
        { 1.234321234321234e17, "123432123432123***.000000" },
        { 1.234321234321234e18, "123432123432123****.000000" },
        { 1.234321234321234e19, "123432123432123*****.000000" },
        { 1.234321234321234e20, "123432123432123******.000000" },
        { 1.234321234321234e21, "123432123432123*******.000000" },
        { 1.234321234321234e22, "123432123432123********.000000" },
        { 1.234321234321234e23, "123432123432123*********.000000" },
        { 1.234321234321234e24, "123432123432123**********.000000" },
        { 1.234321234321234e25, "123432123432123***********.000000" },
        { 1.234321234321234e26, "123432123432123************.000000" },
        { 1.234321234321234e27, "123432123432123*************.000000" },
        { 1.234321234321234e28, "123432123432123**************.000000" },
        { 1.234321234321234e29, "123432123432123***************.000000" },
        { 1.234321234321234e30, "123432123432123****************.000000" },
        { 1.234321234321234e31, "123432123432123*****************.000000" },
        { 1.234321234321234e32, "123432123432123******************.000000" },
        { 1.234321234321234e33, "123432123432123*******************.000000" },
        { 1.234321234321234e34, "123432123432123********************.000000" },
        { 1.234321234321234e35, "123432123432123*********************.000000" },
        { 1.234321234321234e36, "123432123432123**********************.000000" }
      };
    size_t k;
    for (k = 0; k < SIZEOF (data); k++)
      {
        char result[100];
        int retval =
          my_snprintf (result, sizeof (result), "%f", data[k].value);
        ASSERT (strmatch (data[k].string, result));
        ASSERT (retval == strlen (result));
      }
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%f %d", -0.03125, 33, 44, 55);
    ASSERT (strcmp (result, "-0.031250 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%f %d", 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "0.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%f %d", -zerod, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%f %d", 1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "inf 33") == 0
            || strcmp (result, "infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%f %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "-inf 33") == 0
            || strcmp (result, "-infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%f %d", NaNd (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Width.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%10f %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "  1.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_LEFT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%-10f %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.750000   33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SHOWSIGN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%+f %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "+1.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SPACE.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "% f %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, " 1.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#f %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.f %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "2. 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with finite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015f %d", 1234.0, 33, 44, 55);
    ASSERT (strcmp (result, "00001234.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015f %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "           -inf 33") == 0
            || strcmp (result, "      -infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%050f %d", NaNd (), 33, 44, 55);
    ASSERT (strlen (result) == 50 + 3
            && strisnan (result, strspn (result, " "), strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.f %d", 1234.0, 33, 44, 55);
    ASSERT (strcmp (result, "1234 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with no rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2f %d", 999.951, 33, 44, 55);
    ASSERT (strcmp (result, "999.95 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2f %d", 999.996, 33, 44, 55);
    ASSERT (strcmp (result, "1000.00 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", 12.75L, 33, 44, 55);
    ASSERT (strcmp (result, "12.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A larger positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", 1234567.0L, 33, 44, 55);
    ASSERT (strcmp (result, "1234567.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Small and large positive numbers.  */
    static struct { long double value; const char *string; } data[] =
      {
        { 1.234321234321234e-37L, "0.000000" },
        { 1.234321234321234e-36L, "0.000000" },
        { 1.234321234321234e-35L, "0.000000" },
        { 1.234321234321234e-34L, "0.000000" },
        { 1.234321234321234e-33L, "0.000000" },
        { 1.234321234321234e-32L, "0.000000" },
        { 1.234321234321234e-31L, "0.000000" },
        { 1.234321234321234e-30L, "0.000000" },
        { 1.234321234321234e-29L, "0.000000" },
        { 1.234321234321234e-28L, "0.000000" },
        { 1.234321234321234e-27L, "0.000000" },
        { 1.234321234321234e-26L, "0.000000" },
        { 1.234321234321234e-25L, "0.000000" },
        { 1.234321234321234e-24L, "0.000000" },
        { 1.234321234321234e-23L, "0.000000" },
        { 1.234321234321234e-22L, "0.000000" },
        { 1.234321234321234e-21L, "0.000000" },
        { 1.234321234321234e-20L, "0.000000" },
        { 1.234321234321234e-19L, "0.000000" },
        { 1.234321234321234e-18L, "0.000000" },
        { 1.234321234321234e-17L, "0.000000" },
        { 1.234321234321234e-16L, "0.000000" },
        { 1.234321234321234e-15L, "0.000000" },
        { 1.234321234321234e-14L, "0.000000" },
        { 1.234321234321234e-13L, "0.000000" },
        { 1.234321234321234e-12L, "0.000000" },
        { 1.234321234321234e-11L, "0.000000" },
        { 1.234321234321234e-10L, "0.000000" },
        { 1.234321234321234e-9L, "0.000000" },
        { 1.234321234321234e-8L, "0.000000" },
        { 1.234321234321234e-7L, "0.000000" },
        { 1.234321234321234e-6L, "0.000001" },
        { 1.234321234321234e-5L, "0.000012" },
        { 1.234321234321234e-4L, "0.000123" },
        { 1.234321234321234e-3L, "0.001234" },
        { 1.234321234321234e-2L, "0.012343" },
        { 1.234321234321234e-1L, "0.123432" },
        { 1.234321234321234L, "1.234321" },
        { 1.234321234321234e1L, "12.343212" },
        { 1.234321234321234e2L, "123.432123" },
        { 1.234321234321234e3L, "1234.321234" },
        { 1.234321234321234e4L, "12343.212343" },
        { 1.234321234321234e5L, "123432.123432" },
        { 1.234321234321234e6L, "1234321.234321" },
        { 1.234321234321234e7L, "12343212.343212" },
        { 1.234321234321234e8L, "123432123.432123" },
        { 1.234321234321234e9L, "1234321234.321234" },
        { 1.234321234321234e10L, "12343212343.2123**" },
        { 1.234321234321234e11L, "123432123432.123***" },
        { 1.234321234321234e12L, "1234321234321.23****" },
        { 1.234321234321234e13L, "12343212343212.3*****" },
        { 1.234321234321234e14L, "123432123432123.******" },
        { 1.234321234321234e15L, "1234321234321234.000000" },
        { 1.234321234321234e16L, "123432123432123**.000000" },
        { 1.234321234321234e17L, "123432123432123***.000000" },
        { 1.234321234321234e18L, "123432123432123****.000000" },
        { 1.234321234321234e19L, "123432123432123*****.000000" },
        { 1.234321234321234e20L, "123432123432123******.000000" },
        { 1.234321234321234e21L, "123432123432123*******.000000" },
        { 1.234321234321234e22L, "123432123432123********.000000" },
        { 1.234321234321234e23L, "123432123432123*********.000000" },
        { 1.234321234321234e24L, "123432123432123**********.000000" },
        { 1.234321234321234e25L, "123432123432123***********.000000" },
        { 1.234321234321234e26L, "123432123432123************.000000" },
        { 1.234321234321234e27L, "123432123432123*************.000000" },
        { 1.234321234321234e28L, "123432123432123**************.000000" },
        { 1.234321234321234e29L, "123432123432123***************.000000" },
        { 1.234321234321234e30L, "123432123432123****************.000000" },
        { 1.234321234321234e31L, "123432123432123*****************.000000" },
        { 1.234321234321234e32L, "123432123432123******************.000000" },
        { 1.234321234321234e33L, "123432123432123*******************.000000" },
        { 1.234321234321234e34L, "123432123432123********************.000000" },
        { 1.234321234321234e35L, "123432123432123*********************.000000" },
        { 1.234321234321234e36L, "123432123432123**********************.000000" }
      };
    size_t k;
    for (k = 0; k < SIZEOF (data); k++)
      {
        char result[100];
        int retval =
          my_snprintf (result, sizeof (result), "%Lf", data[k].value);
        ASSERT (strmatch (data[k].string, result));
        ASSERT (retval == strlen (result));
      }
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", -0.03125L, 33, 44, 55);
    ASSERT (strcmp (result, "-0.031250 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "0.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", minus_zerol, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", 1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "inf 33") == 0
            || strcmp (result, "infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "-inf 33") == 0
            || strcmp (result, "-infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", NaNl (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
#if CHECK_PRINTF_SAFE && ((defined __ia64 && LDBL_MANT_DIG == 64) || (defined __x86_64__ || defined __amd64__) || (defined __i386 || defined __i386__ || defined _I386 || defined _M_IX86 || defined _X86_))
  { /* Quiet NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0xC3333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  {
    /* Signalling NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x83333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  /* The isnanl function should recognize Pseudo-NaNs, Pseudo-Infinities,
     Pseudo-Zeroes, Unnormalized Numbers, and Pseudo-Denormals, as defined in
       Intel IA-64 Architecture Software Developer's Manual, Volume 1:
       Application Architecture.
       Table 5-2 "Floating-Point Register Encodings"
       Figure 5-6 "Memory to Floating-Point Register Data Translation"
   */
  { /* Pseudo-NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x40000001, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Infinity.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x00000000, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Zero.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x4004, 0x00000000, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Unnormalized number.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x4000, 0x63333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Denormal.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x0000, 0x83333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lf %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
#endif

  { /* Width.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%10Lf %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "  1.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_LEFT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%-10Lf %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.750000   33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SHOWSIGN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%+Lf %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "+1.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SPACE.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "% Lf %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, " 1.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#Lf %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.Lf %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "2. 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with finite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015Lf %d", 1234.0L, 33, 44, 55);
    ASSERT (strcmp (result, "00001234.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015Lf %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "           -inf 33") == 0
            || strcmp (result, "      -infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%050Lf %d", NaNl (), 33, 44, 55);
    ASSERT (strlen (result) == 50 + 3
            && strisnan (result, strspn (result, " "), strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.Lf %d", 1234.0L, 33, 44, 55);
    ASSERT (strcmp (result, "1234 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with no rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2Lf %d", 999.951L, 33, 44, 55);
    ASSERT (strcmp (result, "999.95 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2Lf %d", 999.996L, 33, 44, 55);
    ASSERT (strcmp (result, "1000.00 33") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the %F format directive.  */

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%F %d", 12.75, 33, 44, 55);
    ASSERT (strcmp (result, "12.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A larger positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%F %d", 1234567.0, 33, 44, 55);
    ASSERT (strcmp (result, "1234567.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%F %d", -0.03125, 33, 44, 55);
    ASSERT (strcmp (result, "-0.031250 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%F %d", 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "0.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%F %d", -zerod, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%F %d", 1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "INF 33") == 0
            || strcmp (result, "INFINITY 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%F %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "-INF 33") == 0
            || strcmp (result, "-INFINITY 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%F %d", NaNd (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 1)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015F %d", 1234.0, 33, 44, 55);
    ASSERT (strcmp (result, "00001234.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015F %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "           -INF 33") == 0
            || strcmp (result, "      -INFINITY 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.F %d", 1234.0, 33, 44, 55);
    ASSERT (strcmp (result, "1234 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with no rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2F %d", 999.951, 33, 44, 55);
    ASSERT (strcmp (result, "999.95 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2F %d", 999.996, 33, 44, 55);
    ASSERT (strcmp (result, "1000.00 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LF %d", 12.75L, 33, 44, 55);
    ASSERT (strcmp (result, "12.750000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A larger positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LF %d", 1234567.0L, 33, 44, 55);
    ASSERT (strcmp (result, "1234567.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LF %d", -0.03125L, 33, 44, 55);
    ASSERT (strcmp (result, "-0.031250 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LF %d", 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "0.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LF %d", minus_zerol, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LF %d", 1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "INF 33") == 0
            || strcmp (result, "INFINITY 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LF %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "-INF 33") == 0
            || strcmp (result, "-INFINITY 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%LF %d", NaNl (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 1)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015LF %d", 1234.0L, 33, 44, 55);
    ASSERT (strcmp (result, "00001234.000000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015LF %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "           -INF 33") == 0
            || strcmp (result, "      -INFINITY 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.LF %d", 1234.0L, 33, 44, 55);
    ASSERT (strcmp (result, "1234 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with no rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2LF %d", 999.951L, 33, 44, 55);
    ASSERT (strcmp (result, "999.95 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.2LF %d", 999.996L, 33, 44, 55);
    ASSERT (strcmp (result, "1000.00 33") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the %e format directive.  */

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%e %d", 12.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.275000e+01 33") == 0
            || strcmp (result, "1.275000e+001 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A larger positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%e %d", 1234567.0, 33, 44, 55);
    ASSERT (strcmp (result, "1.234567e+06 33") == 0
            || strcmp (result, "1.234567e+006 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Small and large positive numbers.  */
    static struct { double value; const char *string; } data[] =
      {
        { 1.234321234321234e-37, "1.234321e-37" },
        { 1.234321234321234e-36, "1.234321e-36" },
        { 1.234321234321234e-35, "1.234321e-35" },
        { 1.234321234321234e-34, "1.234321e-34" },
        { 1.234321234321234e-33, "1.234321e-33" },
        { 1.234321234321234e-32, "1.234321e-32" },
        { 1.234321234321234e-31, "1.234321e-31" },
        { 1.234321234321234e-30, "1.234321e-30" },
        { 1.234321234321234e-29, "1.234321e-29" },
        { 1.234321234321234e-28, "1.234321e-28" },
        { 1.234321234321234e-27, "1.234321e-27" },
        { 1.234321234321234e-26, "1.234321e-26" },
        { 1.234321234321234e-25, "1.234321e-25" },
        { 1.234321234321234e-24, "1.234321e-24" },
        { 1.234321234321234e-23, "1.234321e-23" },
        { 1.234321234321234e-22, "1.234321e-22" },
        { 1.234321234321234e-21, "1.234321e-21" },
        { 1.234321234321234e-20, "1.234321e-20" },
        { 1.234321234321234e-19, "1.234321e-19" },
        { 1.234321234321234e-18, "1.234321e-18" },
        { 1.234321234321234e-17, "1.234321e-17" },
        { 1.234321234321234e-16, "1.234321e-16" },
        { 1.234321234321234e-15, "1.234321e-15" },
        { 1.234321234321234e-14, "1.234321e-14" },
        { 1.234321234321234e-13, "1.234321e-13" },
        { 1.234321234321234e-12, "1.234321e-12" },
        { 1.234321234321234e-11, "1.234321e-11" },
        { 1.234321234321234e-10, "1.234321e-10" },
        { 1.234321234321234e-9, "1.234321e-09" },
        { 1.234321234321234e-8, "1.234321e-08" },
        { 1.234321234321234e-7, "1.234321e-07" },
        { 1.234321234321234e-6, "1.234321e-06" },
        { 1.234321234321234e-5, "1.234321e-05" },
        { 1.234321234321234e-4, "1.234321e-04" },
        { 1.234321234321234e-3, "1.234321e-03" },
        { 1.234321234321234e-2, "1.234321e-02" },
        { 1.234321234321234e-1, "1.234321e-01" },
        { 1.234321234321234, "1.234321e+00" },
        { 1.234321234321234e1, "1.234321e+01" },
        { 1.234321234321234e2, "1.234321e+02" },
        { 1.234321234321234e3, "1.234321e+03" },
        { 1.234321234321234e4, "1.234321e+04" },
        { 1.234321234321234e5, "1.234321e+05" },
        { 1.234321234321234e6, "1.234321e+06" },
        { 1.234321234321234e7, "1.234321e+07" },
        { 1.234321234321234e8, "1.234321e+08" },
        { 1.234321234321234e9, "1.234321e+09" },
        { 1.234321234321234e10, "1.234321e+10" },
        { 1.234321234321234e11, "1.234321e+11" },
        { 1.234321234321234e12, "1.234321e+12" },
        { 1.234321234321234e13, "1.234321e+13" },
        { 1.234321234321234e14, "1.234321e+14" },
        { 1.234321234321234e15, "1.234321e+15" },
        { 1.234321234321234e16, "1.234321e+16" },
        { 1.234321234321234e17, "1.234321e+17" },
        { 1.234321234321234e18, "1.234321e+18" },
        { 1.234321234321234e19, "1.234321e+19" },
        { 1.234321234321234e20, "1.234321e+20" },
        { 1.234321234321234e21, "1.234321e+21" },
        { 1.234321234321234e22, "1.234321e+22" },
        { 1.234321234321234e23, "1.234321e+23" },
        { 1.234321234321234e24, "1.234321e+24" },
        { 1.234321234321234e25, "1.234321e+25" },
        { 1.234321234321234e26, "1.234321e+26" },
        { 1.234321234321234e27, "1.234321e+27" },
        { 1.234321234321234e28, "1.234321e+28" },
        { 1.234321234321234e29, "1.234321e+29" },
        { 1.234321234321234e30, "1.234321e+30" },
        { 1.234321234321234e31, "1.234321e+31" },
        { 1.234321234321234e32, "1.234321e+32" },
        { 1.234321234321234e33, "1.234321e+33" },
        { 1.234321234321234e34, "1.234321e+34" },
        { 1.234321234321234e35, "1.234321e+35" },
        { 1.234321234321234e36, "1.234321e+36" }
      };
    size_t k;
    for (k = 0; k < SIZEOF (data); k++)
      {
        char result[100];
        int retval =
          my_snprintf (result, sizeof (result), "%e", data[k].value);
        const char *expected = data[k].string;
        ASSERT (strcmp (result, expected) == 0
                /* Some implementations produce exponents with 3 digits.  */
                || (strlen (result) == strlen (expected) + 1
                    && memcmp (result, expected, strlen (expected) - 2) == 0
                    && result[strlen (expected) - 2] == '0'
                    && strcmp (result + strlen (expected) - 1,
                               expected + strlen (expected) - 2)
                       == 0));
        ASSERT (retval == strlen (result));
      }
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%e %d", -0.03125, 33, 44, 55);
    ASSERT (strcmp (result, "-3.125000e-02 33") == 0
            || strcmp (result, "-3.125000e-002 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%e %d", 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "0.000000e+00 33") == 0
            || strcmp (result, "0.000000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%e %d", -zerod, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0.000000e+00 33") == 0
              || strcmp (result, "-0.000000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%e %d", 1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "inf 33") == 0
            || strcmp (result, "infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%e %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "-inf 33") == 0
            || strcmp (result, "-infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%e %d", NaNd (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Width.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%15e %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "   1.750000e+00 33") == 0
            || strcmp (result, "  1.750000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_LEFT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%-15e %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.750000e+00    33") == 0
            || strcmp (result, "1.750000e+000   33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SHOWSIGN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%+e %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "+1.750000e+00 33") == 0
            || strcmp (result, "+1.750000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SPACE.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "% e %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, " 1.750000e+00 33") == 0
            || strcmp (result, " 1.750000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#e %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.750000e+00 33") == 0
            || strcmp (result, "1.750000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.e %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "2.e+00 33") == 0
            || strcmp (result, "2.e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.e %d", 9.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.e+01 33") == 0
            || strcmp (result, "1.e+001 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with finite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015e %d", 1234.0, 33, 44, 55);
    ASSERT (strcmp (result, "0001.234000e+03 33") == 0
            || strcmp (result, "001.234000e+003 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015e %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "           -inf 33") == 0
            || strcmp (result, "      -infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%050e %d", NaNd (), 33, 44, 55);
    ASSERT (strlen (result) == 50 + 3
            && strisnan (result, strspn (result, " "), strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.e %d", 1234.0, 33, 44, 55);
    ASSERT (strcmp (result, "1e+03 33") == 0
            || strcmp (result, "1e+003 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with no rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.4e %d", 999.951, 33, 44, 55);
    ASSERT (strcmp (result, "9.9995e+02 33") == 0
            || strcmp (result, "9.9995e+002 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.4e %d", 999.996, 33, 44, 55);
    ASSERT (strcmp (result, "1.0000e+03 33") == 0
            || strcmp (result, "1.0000e+003 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", 12.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.275000e+01 33") == 0
            || strcmp (result, "1.275000e+001 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A larger positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", 1234567.0L, 33, 44, 55);
    ASSERT (strcmp (result, "1.234567e+06 33") == 0
            || strcmp (result, "1.234567e+006 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Small and large positive numbers.  */
    static struct { long double value; const char *string; } data[] =
      {
        { 1.234321234321234e-37L, "1.234321e-37" },
        { 1.234321234321234e-36L, "1.234321e-36" },
        { 1.234321234321234e-35L, "1.234321e-35" },
        { 1.234321234321234e-34L, "1.234321e-34" },
        { 1.234321234321234e-33L, "1.234321e-33" },
        { 1.234321234321234e-32L, "1.234321e-32" },
        { 1.234321234321234e-31L, "1.234321e-31" },
        { 1.234321234321234e-30L, "1.234321e-30" },
        { 1.234321234321234e-29L, "1.234321e-29" },
        { 1.234321234321234e-28L, "1.234321e-28" },
        { 1.234321234321234e-27L, "1.234321e-27" },
        { 1.234321234321234e-26L, "1.234321e-26" },
        { 1.234321234321234e-25L, "1.234321e-25" },
        { 1.234321234321234e-24L, "1.234321e-24" },
        { 1.234321234321234e-23L, "1.234321e-23" },
        { 1.234321234321234e-22L, "1.234321e-22" },
        { 1.234321234321234e-21L, "1.234321e-21" },
        { 1.234321234321234e-20L, "1.234321e-20" },
        { 1.234321234321234e-19L, "1.234321e-19" },
        { 1.234321234321234e-18L, "1.234321e-18" },
        { 1.234321234321234e-17L, "1.234321e-17" },
        { 1.234321234321234e-16L, "1.234321e-16" },
        { 1.234321234321234e-15L, "1.234321e-15" },
        { 1.234321234321234e-14L, "1.234321e-14" },
        { 1.234321234321234e-13L, "1.234321e-13" },
        { 1.234321234321234e-12L, "1.234321e-12" },
        { 1.234321234321234e-11L, "1.234321e-11" },
        { 1.234321234321234e-10L, "1.234321e-10" },
        { 1.234321234321234e-9L, "1.234321e-09" },
        { 1.234321234321234e-8L, "1.234321e-08" },
        { 1.234321234321234e-7L, "1.234321e-07" },
        { 1.234321234321234e-6L, "1.234321e-06" },
        { 1.234321234321234e-5L, "1.234321e-05" },
        { 1.234321234321234e-4L, "1.234321e-04" },
        { 1.234321234321234e-3L, "1.234321e-03" },
        { 1.234321234321234e-2L, "1.234321e-02" },
        { 1.234321234321234e-1L, "1.234321e-01" },
        { 1.234321234321234L, "1.234321e+00" },
        { 1.234321234321234e1L, "1.234321e+01" },
        { 1.234321234321234e2L, "1.234321e+02" },
        { 1.234321234321234e3L, "1.234321e+03" },
        { 1.234321234321234e4L, "1.234321e+04" },
        { 1.234321234321234e5L, "1.234321e+05" },
        { 1.234321234321234e6L, "1.234321e+06" },
        { 1.234321234321234e7L, "1.234321e+07" },
        { 1.234321234321234e8L, "1.234321e+08" },
        { 1.234321234321234e9L, "1.234321e+09" },
        { 1.234321234321234e10L, "1.234321e+10" },
        { 1.234321234321234e11L, "1.234321e+11" },
        { 1.234321234321234e12L, "1.234321e+12" },
        { 1.234321234321234e13L, "1.234321e+13" },
        { 1.234321234321234e14L, "1.234321e+14" },
        { 1.234321234321234e15L, "1.234321e+15" },
        { 1.234321234321234e16L, "1.234321e+16" },
        { 1.234321234321234e17L, "1.234321e+17" },
        { 1.234321234321234e18L, "1.234321e+18" },
        { 1.234321234321234e19L, "1.234321e+19" },
        { 1.234321234321234e20L, "1.234321e+20" },
        { 1.234321234321234e21L, "1.234321e+21" },
        { 1.234321234321234e22L, "1.234321e+22" },
        { 1.234321234321234e23L, "1.234321e+23" },
        { 1.234321234321234e24L, "1.234321e+24" },
        { 1.234321234321234e25L, "1.234321e+25" },
        { 1.234321234321234e26L, "1.234321e+26" },
        { 1.234321234321234e27L, "1.234321e+27" },
        { 1.234321234321234e28L, "1.234321e+28" },
        { 1.234321234321234e29L, "1.234321e+29" },
        { 1.234321234321234e30L, "1.234321e+30" },
        { 1.234321234321234e31L, "1.234321e+31" },
        { 1.234321234321234e32L, "1.234321e+32" },
        { 1.234321234321234e33L, "1.234321e+33" },
        { 1.234321234321234e34L, "1.234321e+34" },
        { 1.234321234321234e35L, "1.234321e+35" },
        { 1.234321234321234e36L, "1.234321e+36" }
      };
    size_t k;
    for (k = 0; k < SIZEOF (data); k++)
      {
        char result[100];
        int retval =
          my_snprintf (result, sizeof (result), "%Le", data[k].value);
        const char *expected = data[k].string;
        ASSERT (strcmp (result, expected) == 0
                /* Some implementations produce exponents with 3 digits.  */
                || (strlen (result) == strlen (expected) + 1
                    && memcmp (result, expected, strlen (expected) - 2) == 0
                    && result[strlen (expected) - 2] == '0'
                    && strcmp (result + strlen (expected) - 1,
                               expected + strlen (expected) - 2)
                       == 0));
        ASSERT (retval == strlen (result));
      }
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", -0.03125L, 33, 44, 55);
    ASSERT (strcmp (result, "-3.125000e-02 33") == 0
            || strcmp (result, "-3.125000e-002 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "0.000000e+00 33") == 0
            || strcmp (result, "0.000000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", minus_zerol, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0.000000e+00 33") == 0
              || strcmp (result, "-0.000000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", 1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "inf 33") == 0
            || strcmp (result, "infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "-inf 33") == 0
            || strcmp (result, "-infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", NaNl (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
#if CHECK_PRINTF_SAFE && ((defined __ia64 && LDBL_MANT_DIG == 64) || (defined __x86_64__ || defined __amd64__) || (defined __i386 || defined __i386__ || defined _I386 || defined _M_IX86 || defined _X86_))
  { /* Quiet NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0xC3333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  {
    /* Signalling NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x83333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  /* The isnanl function should recognize Pseudo-NaNs, Pseudo-Infinities,
     Pseudo-Zeroes, Unnormalized Numbers, and Pseudo-Denormals, as defined in
       Intel IA-64 Architecture Software Developer's Manual, Volume 1:
       Application Architecture.
       Table 5-2 "Floating-Point Register Encodings"
       Figure 5-6 "Memory to Floating-Point Register Data Translation"
   */
  { /* Pseudo-NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x40000001, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Infinity.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x00000000, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Zero.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x4004, 0x00000000, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Unnormalized number.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x4000, 0x63333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Denormal.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x0000, 0x83333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Le %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
#endif

  { /* Width.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%15Le %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "   1.750000e+00 33") == 0
            || strcmp (result, "  1.750000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_LEFT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%-15Le %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.750000e+00    33") == 0
            || strcmp (result, "1.750000e+000   33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SHOWSIGN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%+Le %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "+1.750000e+00 33") == 0
            || strcmp (result, "+1.750000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SPACE.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "% Le %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, " 1.750000e+00 33") == 0
            || strcmp (result, " 1.750000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#Le %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.750000e+00 33") == 0
            || strcmp (result, "1.750000e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.Le %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "2.e+00 33") == 0
            || strcmp (result, "2.e+000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.Le %d", 9.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.e+01 33") == 0
            || strcmp (result, "1.e+001 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with finite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015Le %d", 1234.0L, 33, 44, 55);
    ASSERT (strcmp (result, "0001.234000e+03 33") == 0
            || strcmp (result, "001.234000e+003 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015Le %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "           -inf 33") == 0
            || strcmp (result, "      -infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%050Le %d", NaNl (), 33, 44, 55);
    ASSERT (strlen (result) == 50 + 3
            && strisnan (result, strspn (result, " "), strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.Le %d", 1234.0L, 33, 44, 55);
    ASSERT (strcmp (result, "1e+03 33") == 0
            || strcmp (result, "1e+003 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with no rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.4Le %d", 999.951L, 33, 44, 55);
    ASSERT (strcmp (result, "9.9995e+02 33") == 0
            || strcmp (result, "9.9995e+002 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.4Le %d", 999.996L, 33, 44, 55);
    ASSERT (strcmp (result, "1.0000e+03 33") == 0
            || strcmp (result, "1.0000e+003 33") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the %g format directive.  */

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%g %d", 12.75, 33, 44, 55);
    ASSERT (strcmp (result, "12.75 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A larger positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%g %d", 1234567.0, 33, 44, 55);
    ASSERT (strcmp (result, "1.23457e+06 33") == 0
            || strcmp (result, "1.23457e+006 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Small and large positive numbers.  */
    static struct { double value; const char *string; } data[] =
      {
        { 1.234321234321234e-37, "1.23432e-37" },
        { 1.234321234321234e-36, "1.23432e-36" },
        { 1.234321234321234e-35, "1.23432e-35" },
        { 1.234321234321234e-34, "1.23432e-34" },
        { 1.234321234321234e-33, "1.23432e-33" },
        { 1.234321234321234e-32, "1.23432e-32" },
        { 1.234321234321234e-31, "1.23432e-31" },
        { 1.234321234321234e-30, "1.23432e-30" },
        { 1.234321234321234e-29, "1.23432e-29" },
        { 1.234321234321234e-28, "1.23432e-28" },
        { 1.234321234321234e-27, "1.23432e-27" },
        { 1.234321234321234e-26, "1.23432e-26" },
        { 1.234321234321234e-25, "1.23432e-25" },
        { 1.234321234321234e-24, "1.23432e-24" },
        { 1.234321234321234e-23, "1.23432e-23" },
        { 1.234321234321234e-22, "1.23432e-22" },
        { 1.234321234321234e-21, "1.23432e-21" },
        { 1.234321234321234e-20, "1.23432e-20" },
        { 1.234321234321234e-19, "1.23432e-19" },
        { 1.234321234321234e-18, "1.23432e-18" },
        { 1.234321234321234e-17, "1.23432e-17" },
        { 1.234321234321234e-16, "1.23432e-16" },
        { 1.234321234321234e-15, "1.23432e-15" },
        { 1.234321234321234e-14, "1.23432e-14" },
        { 1.234321234321234e-13, "1.23432e-13" },
        { 1.234321234321234e-12, "1.23432e-12" },
        { 1.234321234321234e-11, "1.23432e-11" },
        { 1.234321234321234e-10, "1.23432e-10" },
        { 1.234321234321234e-9, "1.23432e-09" },
        { 1.234321234321234e-8, "1.23432e-08" },
        { 1.234321234321234e-7, "1.23432e-07" },
        { 1.234321234321234e-6, "1.23432e-06" },
        { 1.234321234321234e-5, "1.23432e-05" },
        { 1.234321234321234e-4, "0.000123432" },
        { 1.234321234321234e-3, "0.00123432" },
        { 1.234321234321234e-2, "0.0123432" },
        { 1.234321234321234e-1, "0.123432" },
        { 1.234321234321234, "1.23432" },
        { 1.234321234321234e1, "12.3432" },
        { 1.234321234321234e2, "123.432" },
        { 1.234321234321234e3, "1234.32" },
        { 1.234321234321234e4, "12343.2" },
        { 1.234321234321234e5, "123432" },
        { 1.234321234321234e6, "1.23432e+06" },
        { 1.234321234321234e7, "1.23432e+07" },
        { 1.234321234321234e8, "1.23432e+08" },
        { 1.234321234321234e9, "1.23432e+09" },
        { 1.234321234321234e10, "1.23432e+10" },
        { 1.234321234321234e11, "1.23432e+11" },
        { 1.234321234321234e12, "1.23432e+12" },
        { 1.234321234321234e13, "1.23432e+13" },
        { 1.234321234321234e14, "1.23432e+14" },
        { 1.234321234321234e15, "1.23432e+15" },
        { 1.234321234321234e16, "1.23432e+16" },
        { 1.234321234321234e17, "1.23432e+17" },
        { 1.234321234321234e18, "1.23432e+18" },
        { 1.234321234321234e19, "1.23432e+19" },
        { 1.234321234321234e20, "1.23432e+20" },
        { 1.234321234321234e21, "1.23432e+21" },
        { 1.234321234321234e22, "1.23432e+22" },
        { 1.234321234321234e23, "1.23432e+23" },
        { 1.234321234321234e24, "1.23432e+24" },
        { 1.234321234321234e25, "1.23432e+25" },
        { 1.234321234321234e26, "1.23432e+26" },
        { 1.234321234321234e27, "1.23432e+27" },
        { 1.234321234321234e28, "1.23432e+28" },
        { 1.234321234321234e29, "1.23432e+29" },
        { 1.234321234321234e30, "1.23432e+30" },
        { 1.234321234321234e31, "1.23432e+31" },
        { 1.234321234321234e32, "1.23432e+32" },
        { 1.234321234321234e33, "1.23432e+33" },
        { 1.234321234321234e34, "1.23432e+34" },
        { 1.234321234321234e35, "1.23432e+35" },
        { 1.234321234321234e36, "1.23432e+36" }
      };
    size_t k;
    for (k = 0; k < SIZEOF (data); k++)
      {
        char result[100];
        int retval =
          my_snprintf (result, sizeof (result), "%g", data[k].value);
        const char *expected = data[k].string;
        ASSERT (strcmp (result, expected) == 0
                /* Some implementations produce exponents with 3 digits.  */
                || (expected[strlen (expected) - 4] == 'e'
                    && strlen (result) == strlen (expected) + 1
                    && memcmp (result, expected, strlen (expected) - 2) == 0
                    && result[strlen (expected) - 2] == '0'
                    && strcmp (result + strlen (expected) - 1,
                               expected + strlen (expected) - 2)
                       == 0));
        ASSERT (retval == strlen (result));
      }
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%g %d", -0.03125, 33, 44, 55);
    ASSERT (strcmp (result, "-0.03125 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%g %d", 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "0 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%g %d", -zerod, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%g %d", 1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "inf 33") == 0
            || strcmp (result, "infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%g %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "-inf 33") == 0
            || strcmp (result, "-infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%g %d", NaNd (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Width.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%10g %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "      1.75 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_LEFT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%-10g %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.75       33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SHOWSIGN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%+g %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "+1.75 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SPACE.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "% g %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, " 1.75 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#g %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.75000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.g %d", 1.75, 33, 44, 55);
    ASSERT (strcmp (result, "2. 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.g %d", 9.75, 33, 44, 55);
    ASSERT (strcmp (result, "1.e+01 33") == 0
            || strcmp (result, "1.e+001 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with finite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%010g %d", 1234.0, 33, 44, 55);
    ASSERT (strcmp (result, "0000001234 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015g %d", -1.0 / 0.0, 33, 44, 55);
    ASSERT (strcmp (result, "           -inf 33") == 0
            || strcmp (result, "      -infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%050g %d", NaNd (), 33, 44, 55);
    ASSERT (strlen (result) == 50 + 3
            && strisnan (result, strspn (result, " "), strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.g %d", 1234.0, 33, 44, 55);
    ASSERT (strcmp (result, "1e+03 33") == 0
            || strcmp (result, "1e+003 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with no rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.5g %d", 999.951, 33, 44, 55);
    ASSERT (strcmp (result, "999.95 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.5g %d", 999.996, 33, 44, 55);
    ASSERT (strcmp (result, "1000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", 12.75L, 33, 44, 55);
    ASSERT (strcmp (result, "12.75 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* A larger positive number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", 1234567.0L, 33, 44, 55);
    ASSERT (strcmp (result, "1.23457e+06 33") == 0
            || strcmp (result, "1.23457e+006 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Small and large positive numbers.  */
    static struct { long double value; const char *string; } data[] =
      {
        { 1.234321234321234e-37L, "1.23432e-37" },
        { 1.234321234321234e-36L, "1.23432e-36" },
        { 1.234321234321234e-35L, "1.23432e-35" },
        { 1.234321234321234e-34L, "1.23432e-34" },
        { 1.234321234321234e-33L, "1.23432e-33" },
        { 1.234321234321234e-32L, "1.23432e-32" },
        { 1.234321234321234e-31L, "1.23432e-31" },
        { 1.234321234321234e-30L, "1.23432e-30" },
        { 1.234321234321234e-29L, "1.23432e-29" },
        { 1.234321234321234e-28L, "1.23432e-28" },
        { 1.234321234321234e-27L, "1.23432e-27" },
        { 1.234321234321234e-26L, "1.23432e-26" },
        { 1.234321234321234e-25L, "1.23432e-25" },
        { 1.234321234321234e-24L, "1.23432e-24" },
        { 1.234321234321234e-23L, "1.23432e-23" },
        { 1.234321234321234e-22L, "1.23432e-22" },
        { 1.234321234321234e-21L, "1.23432e-21" },
        { 1.234321234321234e-20L, "1.23432e-20" },
        { 1.234321234321234e-19L, "1.23432e-19" },
        { 1.234321234321234e-18L, "1.23432e-18" },
        { 1.234321234321234e-17L, "1.23432e-17" },
        { 1.234321234321234e-16L, "1.23432e-16" },
        { 1.234321234321234e-15L, "1.23432e-15" },
        { 1.234321234321234e-14L, "1.23432e-14" },
        { 1.234321234321234e-13L, "1.23432e-13" },
        { 1.234321234321234e-12L, "1.23432e-12" },
        { 1.234321234321234e-11L, "1.23432e-11" },
        { 1.234321234321234e-10L, "1.23432e-10" },
        { 1.234321234321234e-9L, "1.23432e-09" },
        { 1.234321234321234e-8L, "1.23432e-08" },
        { 1.234321234321234e-7L, "1.23432e-07" },
        { 1.234321234321234e-6L, "1.23432e-06" },
        { 1.234321234321234e-5L, "1.23432e-05" },
        { 1.234321234321234e-4L, "0.000123432" },
        { 1.234321234321234e-3L, "0.00123432" },
        { 1.234321234321234e-2L, "0.0123432" },
        { 1.234321234321234e-1L, "0.123432" },
        { 1.234321234321234L, "1.23432" },
        { 1.234321234321234e1L, "12.3432" },
        { 1.234321234321234e2L, "123.432" },
        { 1.234321234321234e3L, "1234.32" },
        { 1.234321234321234e4L, "12343.2" },
        { 1.234321234321234e5L, "123432" },
        { 1.234321234321234e6L, "1.23432e+06" },
        { 1.234321234321234e7L, "1.23432e+07" },
        { 1.234321234321234e8L, "1.23432e+08" },
        { 1.234321234321234e9L, "1.23432e+09" },
        { 1.234321234321234e10L, "1.23432e+10" },
        { 1.234321234321234e11L, "1.23432e+11" },
        { 1.234321234321234e12L, "1.23432e+12" },
        { 1.234321234321234e13L, "1.23432e+13" },
        { 1.234321234321234e14L, "1.23432e+14" },
        { 1.234321234321234e15L, "1.23432e+15" },
        { 1.234321234321234e16L, "1.23432e+16" },
        { 1.234321234321234e17L, "1.23432e+17" },
        { 1.234321234321234e18L, "1.23432e+18" },
        { 1.234321234321234e19L, "1.23432e+19" },
        { 1.234321234321234e20L, "1.23432e+20" },
        { 1.234321234321234e21L, "1.23432e+21" },
        { 1.234321234321234e22L, "1.23432e+22" },
        { 1.234321234321234e23L, "1.23432e+23" },
        { 1.234321234321234e24L, "1.23432e+24" },
        { 1.234321234321234e25L, "1.23432e+25" },
        { 1.234321234321234e26L, "1.23432e+26" },
        { 1.234321234321234e27L, "1.23432e+27" },
        { 1.234321234321234e28L, "1.23432e+28" },
        { 1.234321234321234e29L, "1.23432e+29" },
        { 1.234321234321234e30L, "1.23432e+30" },
        { 1.234321234321234e31L, "1.23432e+31" },
        { 1.234321234321234e32L, "1.23432e+32" },
        { 1.234321234321234e33L, "1.23432e+33" },
        { 1.234321234321234e34L, "1.23432e+34" },
        { 1.234321234321234e35L, "1.23432e+35" },
        { 1.234321234321234e36L, "1.23432e+36" }
      };
    size_t k;
    for (k = 0; k < SIZEOF (data); k++)
      {
        char result[100];
        int retval =
          my_snprintf (result, sizeof (result), "%Lg", data[k].value);
        const char *expected = data[k].string;
        ASSERT (strcmp (result, expected) == 0
                /* Some implementations produce exponents with 3 digits.  */
                || (expected[strlen (expected) - 4] == 'e'
                    && strlen (result) == strlen (expected) + 1
                    && memcmp (result, expected, strlen (expected) - 2) == 0
                    && result[strlen (expected) - 2] == '0'
                    && strcmp (result + strlen (expected) - 1,
                               expected + strlen (expected) - 2)
                       == 0));
        ASSERT (retval == strlen (result));
      }
  }

  { /* A negative number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", -0.03125L, 33, 44, 55);
    ASSERT (strcmp (result, "-0.03125 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "0 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative zero.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", minus_zerol, 33, 44, 55);
    if (have_minus_zero ())
      ASSERT (strcmp (result, "-0 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Positive infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", 1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "inf 33") == 0
            || strcmp (result, "infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Negative infinity.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "-inf 33") == 0
            || strcmp (result, "-infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", NaNl (), 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
#if CHECK_PRINTF_SAFE && ((defined __ia64 && LDBL_MANT_DIG == 64) || (defined __x86_64__ || defined __amd64__) || (defined __i386 || defined __i386__ || defined _I386 || defined _M_IX86 || defined _X86_))
  { /* Quiet NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0xC3333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  {
    /* Signalling NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x83333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  /* The isnanl function should recognize Pseudo-NaNs, Pseudo-Infinities,
     Pseudo-Zeroes, Unnormalized Numbers, and Pseudo-Denormals, as defined in
       Intel IA-64 Architecture Software Developer's Manual, Volume 1:
       Application Architecture.
       Table 5-2 "Floating-Point Register Encodings"
       Figure 5-6 "Memory to Floating-Point Register Data Translation"
   */
  { /* Pseudo-NaN.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x40000001, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Infinity.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0xFFFF, 0x00000000, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Zero.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x4004, 0x00000000, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Unnormalized number.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x4000, 0x63333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
  { /* Pseudo-Denormal.  */
    static union { unsigned int word[4]; long double value; } x =
      { LDBL80_WORDS (0x0000, 0x83333333, 0x00000000) };
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%Lg %d", x.value, 33, 44, 55);
    ASSERT (strlen (result) >= 3 + 3
            && strisnan (result, 0, strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }
#endif

  { /* Width.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%10Lg %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "      1.75 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_LEFT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%-10Lg %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.75       33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SHOWSIGN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%+Lg %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "+1.75 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_SPACE.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "% Lg %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, " 1.75 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#Lg %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.75000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.Lg %d", 1.75L, 33, 44, 55);
    ASSERT (strcmp (result, "2. 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ALT.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%#.Lg %d", 9.75L, 33, 44, 55);
    ASSERT (strcmp (result, "1.e+01 33") == 0
            || strcmp (result, "1.e+001 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with finite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%010Lg %d", 1234.0L, 33, 44, 55);
    ASSERT (strcmp (result, "0000001234 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with infinite number.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%015Lg %d", -1.0L / 0.0L, 33, 44, 55);
    ASSERT (strcmp (result, "           -inf 33") == 0
            || strcmp (result, "      -infinity 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* FLAG_ZERO with NaN.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%050Lg %d", NaNl (), 33, 44, 55);
    ASSERT (strlen (result) == 50 + 3
            && strisnan (result, strspn (result, " "), strlen (result) - 3, 0)
            && strcmp (result + strlen (result) - 3, " 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.Lg %d", 1234.0L, 33, 44, 55);
    ASSERT (strcmp (result, "1e+03 33") == 0
            || strcmp (result, "1e+003 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with no rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.5Lg %d", 999.951L, 33, 44, 55);
    ASSERT (strcmp (result, "999.95 33") == 0);
    ASSERT (retval == strlen (result));
  }

  { /* Precision with rounding.  */
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%.5Lg %d", 999.996L, 33, 44, 55);
    ASSERT (strcmp (result, "1000 33") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the %n format directive.  */

  {
    int count = -1;
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%d %n", 123, &count, 33, 44, 55);
    ASSERT (strcmp (result, "123 ") == 0);
    ASSERT (retval == strlen (result));
    ASSERT (count == 4);
  }

  /* Test the support of the POSIX/XSI format strings with positions.  */

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%2$d %1$d", 33, 55);
    ASSERT (strcmp (result, "55 33") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the grouping flag.  */

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "%'d %d", 1234567, 99);
    ASSERT (result[strlen (result) - 1] == '9');
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the left-adjust flag.  */

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "a%*sc", -3, "b");
    ASSERT (strcmp (result, "ab  c") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "a%-*sc", 3, "b");
    ASSERT (strcmp (result, "ab  c") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[100];
    int retval =
      my_snprintf (result, sizeof (result), "a%-*sc", -3, "b");
    ASSERT (strcmp (result, "ab  c") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of large precision.  */

  {
    char result[5000];
    int retval =
      my_snprintf (result, sizeof (result), "%.4000d %d", 1234567, 99);
    size_t i;
    for (i = 0; i < 4000 - 7; i++)
      ASSERT (result[i] == '0');
    ASSERT (strcmp (result + 4000 - 7, "1234567 99") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[5000];
    int retval =
      my_snprintf (result, sizeof (result), "%.*d %d", 4000, 1234567, 99);
    size_t i;
    for (i = 0; i < 4000 - 7; i++)
      ASSERT (result[i] == '0');
    ASSERT (strcmp (result + 4000 - 7, "1234567 99") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[5000];
    int retval =
      my_snprintf (result, sizeof (result), "%.4000d %d", -1234567, 99);
    size_t i;
    ASSERT (result[0] == '-');
    for (i = 0; i < 4000 - 7; i++)
      ASSERT (result[1 + i] == '0');
    ASSERT (strcmp (result + 1 + 4000 - 7, "1234567 99") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[5000];
    int retval =
      my_snprintf (result, sizeof (result), "%.4000u %d", 1234567, 99);
    size_t i;
    for (i = 0; i < 4000 - 7; i++)
      ASSERT (result[i] == '0');
    ASSERT (strcmp (result + 4000 - 7, "1234567 99") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[5000];
    int retval =
      my_snprintf (result, sizeof (result), "%.4000o %d", 1234567, 99);
    size_t i;
    for (i = 0; i < 4000 - 7; i++)
      ASSERT (result[i] == '0');
    ASSERT (strcmp (result + 4000 - 7, "4553207 99") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[5000];
    int retval =
      my_snprintf (result, sizeof (result), "%.4000x %d", 1234567, 99);
    size_t i;
    for (i = 0; i < 4000 - 6; i++)
      ASSERT (result[i] == '0');
    ASSERT (strcmp (result + 4000 - 6, "12d687 99") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char result[5000];
    int retval =
      my_snprintf (result, sizeof (result), "%#.4000x %d", 1234567, 99);
    size_t i;
    ASSERT (result[0] == '0');
    ASSERT (result[1] == 'x');
    for (i = 0; i < 4000 - 6; i++)
      ASSERT (result[2 + i] == '0');
    ASSERT (strcmp (result + 2 + 4000 - 6, "12d687 99") == 0);
    ASSERT (retval == strlen (result));
  }

  {
    char input[5000];
    char result[5000];
    int retval;
    size_t i;

    for (i = 0; i < sizeof (input) - 1; i++)
      input[i] = 'a' + ((1000000 / (i + 1)) % 26);
    input[i] = '\0';
    retval = my_snprintf (result, sizeof (result), "%.4000s %d", input, 99);
    ASSERT (memcmp (result, input, 4000) == 0);
    ASSERT (strcmp (result + 4000, " 99") == 0);
    ASSERT (retval == strlen (result));
  }

  /* Test the support of the %s format directive.  */

  /* To verify that these tests succeed, it is necessary to run them under
     a tool that checks against invalid memory accesses, such as ElectricFence
     or "valgrind --tool=memcheck".  */
  {
    size_t i;

    for (i = 1; i <= 8; i++)
      {
        char *block;
        char result[5000];
        int retval;

        block = (char *) malloc (i);
        memcpy (block, "abcdefgh", i);
        retval = my_snprintf (result, sizeof (result), "%.*s", (int) i, block);
        ASSERT (memcmp (result, block, i) == 0);
        ASSERT (result[i] == '\0');
        ASSERT (retval == strlen (result));
        free (block);
      }
  }
#if HAVE_WCHAR_T
  {
    size_t i;

    for (i = 1; i <= 8; i++)
      {
        wchar_t *block;
        size_t j;
        char result[5000];
        int retval;

        block = (wchar_t *) malloc (i * sizeof (wchar_t));
        for (j = 0; j < i; j++)
          block[j] = "abcdefgh"[j];
        retval = my_snprintf (result, sizeof (result), "%.*ls", (int) i, block);
        ASSERT (memcmp (result, "abcdefgh", i) == 0);
        ASSERT (result[i] == '\0');
        ASSERT (retval == strlen (result));
        free (block);
      }
  }
#endif
}
