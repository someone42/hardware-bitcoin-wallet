# Makefile for unit tests.
#
# Previously, the unit tests were built by compiling everything with the flags
# -DTEST and -DTEST_<x>, where <x> is the uppercase name of the module
# (eg. -DTEST_AES for aes.c, -DTEST_SHA256 for sha256.c).
# For example, to build the sha256.c unit test suite, the command:
# "gcc -DTEST -DTEST_SHA256 *.c -o test_sha256" would be run.
# This Makefile automates that procedure.
# This requires GNU make 3.81 or higher, since it uses the secondary expansion
# feature.
#
# Every source file is compiled once for each test suite. This is
# done because changing preprocessor definitions using the "-D" flag could
# potentially have an effect on all source files. This does result in a lot
# of extra work. Fourtunately, the unit tests can all be built in parallel,
# so if you are building them on a multi-core machine, use the "-j" flag
# (eg. "make -j 2" for a dual-core machine) to speed things up.
#
# This file is licensed as described by the file LICENCE.

# List C source files here.
SRC = aes.c baseconv.c bignum256.c ecdsa.c endian.c fft.c fix16.c hash.c \
hmac_sha512.c messages.pb.c p2sh_addr_gen.c pb_decode.c pb_encode.c prandom.c \
ripemd160.c sha256.c statistics.c stream_comm.c test_helpers.c transaction.c \
wallet.c xex.c

# List file names (without .c extension) which have unit tests.
TESTLIST = aes baseconv bignum256 ecdsa hmac_sha512 p2sh_addr_gen prandom \
ripemd160 sha256 stream_comm transaction wallet xex

# Define programs and commands.
CC = gcc
REMOVE = rm -f
REMOVEDIR = rm -rf

# Define flags for C compiler.
GENDEPFLAGS = -MMD -MP -MF .dep/$(@F).d
CCFLAGS = -DTEST -DFIXMATH_NO_64BIT -ggdb -O0 -Wall -Wstrict-prototypes \
-Wundef -Wunreachable-code -Wsign-compare -Wextra -Wconversion -std=gnu99 \
$(GENDEPFLAGS)

# Define extra libraries to include.
LIBS = -lgmp

################################################################
# Below this point is stuff which is generally non-customisable.
################################################################

# Get the list of object files for each target.
OBJ = $(SRC:%.c=%.o)

# Get the list of target names.
TARGETLIST = $(addprefix test_,$(TESTLIST))

# Get the list of object directories.
OBJDIRLIST = $(addsuffix _obj,$(TARGETLIST))

# Get the list of all possible object files.
# This basically calculates the Cartesian product of the OBJDIRLIST and
# OBJ lists, inserting a "/" for each item.
OBJEXPAND = $(foreach OBJDIR,$(OBJDIRLIST),$(addprefix $(OBJDIR)/,$(OBJ)))

.PHONY: all clean

all: $(TARGETLIST)

# Make object directory.
$(OBJDIRLIST):
	$(shell mkdir $@ 2>/dev/null)

.SECONDEXPANSION:

# Link object files together to form an executable.
$(TARGETLIST): $(addprefix $$@_obj/,$(OBJ))
	$(CC) $^ $(LIBS) -o $@

# Compile a C source file into an object file.
# What does $(shell echo $(@D:%_obj=%) | tr '[:lower:]' '[:upper:]') do?
# It gets the name of the object directory, removes _obj from the end and
# converts it to uppercase.
$(OBJEXPAND): $$(subst .o,.c,$$(@F)) | $$(@D)
	$(CC) $(CCFLAGS) -c -o $@ -D$(shell echo $(@D:%_obj=%) | tr '[:lower:]' '[:upper:]') $<

clean:
	$(REMOVEDIR) $(OBJDIRLIST)
	$(REMOVE) $(addsuffix *,$(TARGETLIST))
	$(REMOVEDIR) .dep

# Include the dependency files.
-include $(shell mkdir .dep 2>/dev/null) $(wildcard .dep/*)
