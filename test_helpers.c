/** \file test_helpers.c
  *
  * \brief Common helper functions for unit tests.
  *
  * If TEST is not defined, this file will appear as an empty translation
  * unit to the compiler. Thus this file should not be compiled in non-test
  * builds.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "test_helpers.h"

/** Number of test cases which succeeded. */
static int succeeded;
/** Number of test cases which failed. */
static int failed;
/** Time when unit tests were started. */
static time_t start_time;

/** Skip whitespace in an open file, starting from the current position within
  * the file and ending such that the file position points to the first
  * non-whitespace character found.
  * \param f The file to skip whitespace in.
  */
void skipWhiteSpace(FILE *f)
{
	int one_char;
	do
	{
		one_char = fgetc(f);
	} while (((one_char == ' ') || (one_char == '\t') || (one_char == '\n') || (one_char == '\r'))
		&& !feof(f));
	ungetc(one_char, f);
}

/** Skip the contents of a line in an open file, starting from the current
  * position within the file and ending such that the file position points to
  * the first character of the next line.
  * \param f The file to skip a line in.
  */
void skipLine(FILE *f)
{
	int one_char;
	do
	{
		one_char = fgetc(f);
	} while ((one_char != '\n') && !feof(f));
}

/** Display a multi-precision integer of arbitrary size as a hex string.
  * \param number The byte array containing the integer.
  * \param size The size, in number of bytes, of the byte array.
  * \param is_big_endian This should be true if the integer is stored in
  *                      big-endian format and should be false if the number
  *                      is stored in little-endian format.
  */
void bigPrintVariableSize(const uint8_t *number, const unsigned int size, const bool is_big_endian)
{
	unsigned int i;
	if (is_big_endian)
	{
		for (i = 0; i < size; i++)
		{
			printf("%02x", number[i]);
		}
	}
	else
	{
		for (i = (uint8_t)(size - 1); i < size; i--)
		{
			printf("%02x", number[i]);
		}
	}
}

/** Display a 128 bit big-endian multi-precision integer as a hex string.
  * \param buffer 16 byte array containing the number to display.
  */
void printBigEndian16(const uint8_t *buffer)
{
	bigPrintVariableSize(buffer, 16, true);
}

/** Display a 256 bit little-endian multi-precision integer as a hex string.
  * \param buffer 32 byte array containing the number to display.
  */
void printLittleEndian32(const BigNum256 buffer)
{
	bigPrintVariableSize(buffer, 32, false);
}


/** Fill array with pseudo-random testing data.
  * \param out Byte array to fill.
  * \param len Number of bytes to write.
  */
void fillWithRandom(uint8_t *out, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
	{
		out[i] = (uint8_t)rand();
	}
}

/** Call this whenever a test case succeeds. */
void reportSuccess(void)
{
	succeeded++;
}

/** Call this whenever a test case fails. */
void reportFailure(void)
{
	failed++;
}

/** This must be called before running any unit tests.
  * \param source_file_name The name of the file being unit tested. The use
  *                         of the __FILE__ macro is probably a good idea.
  */
void initTests(const char *source_file_name)
{
	succeeded = 0;
	failed = 0;
	srand(42); // make sure tests which rely on rand() are deterministic
	printf("Running unit tests for file: %s\n", source_file_name);
	time(&start_time);
}

/** This must be called after running all unit tests for a file. It will
  * report test statistics.
  */
void finishTests(void)
{
	time_t finish_time;

	time(&finish_time);
	printf("Tests required about %g seconds\n", difftime(finish_time, start_time));
	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);
}

#endif // #ifdef TEST

