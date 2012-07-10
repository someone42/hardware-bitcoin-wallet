/** \file bdf_converter.c
  *
  * \brief Converts BDF files into a font table.
  *
  * Converts Glyph Bitmap Distribution Format (BDF) files into a font table
  * for use with ssd1306.c. The BDF specification was obtained from
  * http://partners.adobe.com/public/developer/en/font/5005.BDF_Spec.pdf on
  * 8-July-2012.
  *
  * The main tasks of this program are to parse the BDF file, convert the
  * bitmaps into vertical bitmaps and then output a packed font table as C
  * source.
  * The parser knows only a small subset of BDF, can only handle fixed-width
  * fonts and will probably choke on many BDF files. It was written with the
  * Terminus font family (see http://terminus-font.sourceforge.net/) in mind,
  * and it seems to successfully parse those BDF files.
  *
  * ssd1306.c requires the font table to be a packed vertical bitmap. The
  * packed vertical bitmap can be interpreted as follows: imagine the font
  * table as a single large little-endian multi-precision integer. Start
  * with the least significant bit and move to more significant bits. The
  * least significant bit represents the top-left pixel of the first glyph.
  * For each increment in bit significance, move down to the next pixel. If
  * you get to the bottom, move to the top of the next (towards the right)
  * column. If you get to the bottom of the last column, move to the top-left
  * pixel of the next glyph.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/** The encoding value of the last glyph to include in the font table, plus
  * one. Making this larger results in a larger font table. A value of 128
  * covers all ASCII characters. */
#define ENCODING_END		128
/** The encoding value of the first glyph to include in the font table. Making
  * this smaller results in a larger font table. A value of 32 is recommended,
  * to exclude non-printable characters. */
#define ENCODING_START		32
/** Number of bytes per line in C source output. */
#define VALUES_PER_LINE		16

/** Width, in pixels, of every glyph. */
static int width;
/** Height, in pixels, of every glyph. */
static int height;
/** Number of bytes required for each row in horizontal bitmap. */
static int bytes_per_row;
/** Storage for horizontal bitmaps obtained from BDF file. */
static int *bitmaps[ENCODING_END];
/** Number of bytes on current line of C source output. */
static int values_on_output_line;

/** Parse the definition of one glyph. The parser looks at everything between
  * the next occurence of "STARTCHAR <char_name>" and "ENDCHAR".
  * \param bdf The BDF file to parse.
  */
static void parseGlyph(FILE *bdf)
{
	char current_line[256];
	char char_name[256];
	int current_width; // width, in pixels, of current glyph
	int current_height; // height, in pixels, of current glyph
	int encoding; // encoding value (eg. 97 for "a")
	int seen_encoding; // has "ENCODING <encoding value>" been parsed?
	int seen_bbx; // has "BBX <width> <height>" been parsed?
	int seen_bitmap; // has "BITMAP" been parsed?
	int *current_bitmap;
	int i;

	// Look for "STARTCHAR <char_name>".
	while (!feof(bdf))
	{
		fgets(current_line, sizeof(current_line), bdf);
		if (sscanf(current_line, "STARTCHAR %s", char_name) == 1)
		{
			break;
		}
	}
	if (feof(bdf))
	{
		return;
	}

	encoding = 0;
	seen_encoding = 0;
	current_width = 0;
	current_height = 0;
	seen_bbx = 0;
	seen_bitmap = 0;
	current_bitmap = NULL;

	// Look for "ENCODING <encoding value>", "BBX <width> <height>",
	// "BITMAP" and "ENDCHAR".
	while (!feof(bdf))
	{
		fgets(current_line, sizeof(current_line), bdf);
		if (sscanf(current_line, "ENCODING %d", &encoding) == 1)
		{
			seen_encoding = 1;
		}
		else if (sscanf(current_line, "BBX %d %d", &current_width, &current_height) == 2)
		{
			seen_bbx = 1;
			if ((width == 0) || (height == 0))
			{
				// This is the first character, so set the expected width
				// and height of every glyph.
				width = current_width;
				height = current_height;
				bytes_per_row = (width + 7) >> 3; // round up
			}
			else
			{
				// The font should be fixed-width, so every glyph should
				// have the same width/height.
				if ((width != current_width) || (height != current_height))
				{
					printf("Error: font is not fixed-width\n");
					exit(1);
				}
			}
		}
		else if (!strcmp(current_line, "BITMAP\n"))
		{
			// Process bitmap data.
			seen_bitmap = 1;
			if (!seen_bbx)
			{
				printf("Error: got \"BITMAP\" before \"BBX\"\n");
				exit(1);
			}
			current_bitmap = malloc(sizeof(int) * bytes_per_row * height);
			for (i = 0; i < (bytes_per_row * height); i++)
			{
				fscanf(bdf, "%02x", &(current_bitmap[i]));
			}
		}
		else if (!strcmp(current_line, "ENDCHAR\n"))
		{
			// Commit bitmap data into bitmaps array.
			if (seen_encoding && seen_bbx && seen_bitmap)
			{
				if ((encoding >= 0) && (encoding < ENCODING_END))
				{
					bitmaps[encoding] = current_bitmap;
				}
			}
			return;
		}
	} // end while (!feof(bdf))
}

/** Output one byte of the font table in C source representation, placing
  * newlines every VALUES_PER_LINE values.
  * \param output_byte The value of the byte to output.
  * \param no_comma Set to non-zero to suppress trailing comma.
  */
static void outputTableByte(int output_byte, int no_comma)
{
	if (values_on_output_line != 0)
	{
		printf(" ");
	}
	printf("0x%02x", output_byte);
	if (!no_comma)
	{
		printf(",");
	}
	values_on_output_line++;
	if (values_on_output_line == VALUES_PER_LINE)
	{
		printf("\n");
		values_on_output_line = 0;
	}
}

int main(int argc, char **argv)
{
	char current_line[256];
	char font_name[256];
	int found_font_name;
	int i, j, k;
	int *null_bitmap; // bitmap of all 00s, to output when the font doesn't define a glyph
	int *current_bitmap;
	int output_byte;
	int mask;
	int bits_shifted;
	FILE *bdf;

	if (argc != 2)
	{
		printf("Usage: %s <bdf_file_name>\n", argv[0]);
		exit(1);
	}

	bdf = fopen(argv[1], "r");
	if (bdf == NULL)
	{
		printf("Error: couldn't open \"%s\" for reading\n", argv[1]);
		exit(1);
	}

	// Look for "FONT <str>".
	found_font_name = 0;
	while (!feof(bdf))
	{
		fgets(current_line, sizeof(current_line), bdf);
		if (sscanf(current_line, "FONT %s", font_name) == 1)
		{
			found_font_name = 1;
			printf("// Table generated from file \"%s\" using bdf_converter.\n", argv[1]);
			printf("// Font name: \"%s\".\n", font_name);
			printf("const uint8_t font_table[] = {\n");
			break;
		}
	}
	if (!found_font_name)
	{
		printf("Error: couldn't find \"FONT\" in \"%s\", is it a BDF file?\n", argv[1]);
		fclose(bdf);
		exit(1);
	}

	memset(bitmaps, 0, sizeof(bitmaps));
	width = 0;
	height = 0;
	bytes_per_row = 0;
	while (!feof(bdf))
	{
		parseGlyph(bdf);
	}
	fclose(bdf);

	// Convert horizontal bitmaps into packed vertical bitmaps.
	output_byte = 0;
	null_bitmap = calloc(bytes_per_row * height, sizeof(int));
	bits_shifted = 0;
	values_on_output_line = 0;
	for (i = ENCODING_START; i < ENCODING_END; i++)
	{
		if (bitmaps[i] != NULL)
		{
			current_bitmap = bitmaps[i];
		}
		else
		{
			// Font doesn't define the glyph with encoding value i. Just
			// use a bitmap of all 00s.
			current_bitmap = null_bitmap;
		}
		for (j = 0; j < width; j++)
		{
			for (k = 0; k < height; k++)
			{
				output_byte >>= 1;
				mask = 0x80 >> (j & 7);
				// Inspect pixel of glyph with encoding value i, at column
				// j and row k.
				if (current_bitmap[k * bytes_per_row + (j >> 3)] & mask)
				{
					output_byte |= 0x80;
				}
				bits_shifted++;
				if (bits_shifted == 8)
				{
					outputTableByte(output_byte, 0);
					output_byte = 0;
					bits_shifted = 0;
				}
			}
		} // end for (j = 0; j < width; j++)
	} // end for (i = ENCODING_START; i < ENCODING_END; i++)

	// Take care of incomplete byte (if there is one).
	if (bits_shifted != 0)
	{
		output_byte >>= (8 - bits_shifted);
		outputTableByte(output_byte, 0);
	}
	// Finish off table with extra 00, as needed by ssd1306.c.
	outputTableByte(0, 1);
	printf("};\n");

	exit(0);
}
