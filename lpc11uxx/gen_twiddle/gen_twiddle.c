/** \file gen_twiddle.c
  *
  * \brief Generates fixed-point twiddle factor lookup table.
  *
  * This generates the twiddle factor lookup table for use in fft.c. This
  * outputs the table as C source, with integer constants representing
  * sin(phi) in 16.16 fixed-point format.
  *
  * There are a couple of space optimisations:
  * - Only sin(phi) values for the first quadrant; phi in [0, pi / 2); are
  *   generated, since various symmetries of sin(phi) can be exploited in
  *   order to get values for the other quadrants.
  * - Only sin(phi) values are outputted, not cos(phi). Once again, the
  *   symmetry cos(phi) = sin(pi / 2 - phi) can be exploited to recover
  *   cos(phi) values from sin(phi) values.
  * - Only the fractional part of sin(phi) is outputted, since sin(phi) is in
  *   [0, 1) when phi is in [0, pi / 2).
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdlib.h>
#include <stdio.h>
#include <math.h>

/** Mmmm. Pie. */
#define PI					3.141592653589793238462643
/** Number of constants per line in C source output. */
#define VALUES_PER_LINE		8

int main(int argc, char **argv)
{
	int i;
	int fft_size;
	int table_size;
	unsigned int out; // C spec guarantees unsigned int can hold [0, 65535]

	if (argc != 2)
	{
		printf("Usage: %s <size>\n", argv[0]);
		printf("  <size>: size of (complex) FFT\n");
		printf("\n");
		exit(1);
	}
	if (sscanf(argv[1], "%d", &fft_size) != 1)
	{
		printf("Error: Invalid size\n");
		exit(1);
	}
	if (fft_size <= 0)
	{
		printf("Error: Invalid size\n");
		exit(1);
	}

	// A complex FFT of size fft_size would normally need fft_size / 2 twiddle
	// factors, corresponding to phi in [0, pi). But since fft.c uses various
	// symmetries of sin(phi), only the values in [0, pi / 2) are needed.
	table_size = (fft_size / 4);
	printf("// Table generated using gen_twiddle.\n");
	printf("// FFT size: %d.\n", fft_size);
	printf("const uint16_t twiddle_factor_lookup[%d] = {\n", table_size);
	for (i = 0; i < table_size; i++)
	{
		// The "* (double)0x00010000" is to convert to 16.16 fixed-point.
		// The "+ 0.5" is to get the (uint32_t) cast to round instead of
		// truncating.
		out = (unsigned int)(sin(i * (2.0 * PI / (double)fft_size)) * (double)0x00010000 + 0.5);
		printf("0x%04x", out);
		if (i != (table_size - 1))
		{
			printf(", ");
		}
		if ((i % VALUES_PER_LINE) == (VALUES_PER_LINE - 1))
		{
			printf("\n");
		}
	}
	printf("};\n");
}
