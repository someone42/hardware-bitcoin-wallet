/** \file nvmem_manager.c
  *
  * \brief Translates non-volatile memory operations into flash access.
  *
  * Flash memory can be read with byte granularity but writes can only be
  * done with sector granularity. This is a problem: the platform-dependent
  * code treats non-volatile memory as something which can be written to
  * with byte granularity. Honouring every write could cause the flash memory
  * to wear out much more quickly.
  *
  * To deal with this problem, the functions in this file implement a
  * translation layer which uses a cache to accumulate writes within a sector.
  * nonVolatileFlush() can then be used to actually write the sector to
  * flash memory.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <string.h>
#include "../hwinterface.h"
#include "sst25x.h"

/** Whether write cache is valid. */
static bool write_cache_valid;
/** Sector address of current contents of write cache. This is only
  * well-defined if #write_cache_valid is true. */
static uint32_t write_cache_tag;
/** Current contents of write cache. This is only well-defined
  * if #write_cache_valid is true. */
static uint8_t write_cache[SECTOR_SIZE];

/** Bitmask applied to addresses to get the sector address. */
#define SECTOR_TAG_MASK			(~(SECTOR_SIZE - 1))
/** Bitmask applied to addresses to get the offset within a sector. */
#define SECTOR_OFFSET_MASK		(SECTOR_SIZE - 1)

/** Write to non-volatile storage.
  * \param data A pointer to the data to be written.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start writing to.
  * \param length The number of bytes to write.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning Writes may be buffered; use nonVolatileFlush() to be sure that
  *          data is actually written to non-volatile storage.
  */
NonVolatileReturn nonVolatileWrite(uint8_t *data, uint32_t address, uint32_t length)
{
	uint32_t address_tag;
	uint32_t end; // exclusive
	uint32_t data_index;
	NonVolatileReturn r;

	// As long as NV_MEMORY_SIZE is much smaller than 2 ^ 32, address + length
	// cannot overflow.
	if ((address >= NV_MEMORY_SIZE) || (length > NV_MEMORY_SIZE)
		|| ((address + length) > NV_MEMORY_SIZE))
	{
		return NV_INVALID_ADDRESS;
	}

	end = address + length;
	data_index = 0;
	while (address < end)
	{
		address_tag = address & SECTOR_TAG_MASK;
		if (!write_cache_valid || (address_tag != write_cache_tag))
		{
			// Address is not in cache; load sector into cache.
			if (write_cache_valid)
			{
				r = nonVolatileFlush();
				if (r != NV_NO_ERROR)
				{
					return r;
				}
			}
			write_cache_valid = true;
			write_cache_tag = address_tag;
			sst25xRead(write_cache, address_tag, SECTOR_SIZE);
		}
		// Address is guaranteed to be in cache; write to the cache.
		write_cache[address & SECTOR_OFFSET_MASK] = data[data_index];
		address++;
		data_index++;
	}
	return NV_NO_ERROR;
}

/** Read from non-volatile storage.
  * \param data A pointer to the buffer which will receive the data.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start reading from.
  * \param length The number of bytes to read.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileRead(uint8_t *data, uint32_t address, uint32_t length)
{
	uint32_t address_tag;
	uint32_t end; // exclusive
	uint32_t nv_read_length; // length of contiguous non-volatile read
	uint32_t data_index;

	// As long as NV_MEMORY_SIZE is much smaller than 2 ^ 32, address + length
	// cannot overflow.
	if ((address >= NV_MEMORY_SIZE) || (length > NV_MEMORY_SIZE)
		|| ((address + length) > NV_MEMORY_SIZE))
	{
		return NV_INVALID_ADDRESS;
	}

	end = address + length;
	nv_read_length = 0;
	data_index = 0;
	// The code below attempts to group non-volatile reads together. It is
	// possible (and simpler) to read one byte at a time, but that is much less
	// efficient. For example, in SST25x serial flash memory chips, reading a
	// byte at a time is about 5 times slower (per byte) than reading a large
	// array of bytes in a single command.
	// Since reads are expected to occur much more frequently than writes,
	// inefficient reading will incur a significant performance penalty.
	while (address < end)
	{
		address_tag = address & SECTOR_TAG_MASK;
		if (write_cache_valid && (address_tag == write_cache_tag))
		{
			if (nv_read_length > 0)
			{
				// Beginning of write cache; end of contiguous non-volatile
				// read.
				sst25xRead(&(data[data_index]), address - nv_read_length, nv_read_length);
				data_index += nv_read_length;
				nv_read_length = 0;
			}
			// Address is in cache; read from the cache.
			data[data_index] = write_cache[address & SECTOR_OFFSET_MASK];
			data_index++;
		}
		else
		{
			// Don't read just yet; queue it up and do all the reads together.
			nv_read_length++;
		}
		address++;
	}
	if (nv_read_length > 0)
	{
		// End of contiguous non-volatile read.
		sst25xRead(&(data[data_index]), address - nv_read_length, nv_read_length);
	}
	return NV_NO_ERROR;
}

/** Ensure that all buffered writes are committed to non-volatile storage.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileFlush(void)
{
	unsigned int i;
	uint8_t read_buffer[SECTOR_SIZE];

	if (write_cache_valid)
	{
		if (write_cache_tag >= NV_MEMORY_SIZE)
		{
			return NV_INVALID_ADDRESS;
		}

		// Erase sector and verify erase.
		sst25xEraseSector(write_cache_tag);
		sst25xRead(read_buffer, write_cache_tag, SECTOR_SIZE);
		for (i = 0; i < SECTOR_SIZE; i++)
		{
			if (read_buffer[i] != 0xff)
			{
				return NV_IO_ERROR; // erase did not complete properly
			}
		}

		// Program sector and verify program.
		sst25xProgramSector(write_cache, write_cache_tag);
		sst25xRead(read_buffer, write_cache_tag, SECTOR_SIZE);
		if (memcmp(read_buffer, write_cache, SECTOR_SIZE))
		{
			return NV_IO_ERROR; // program did not complete properly
		}

		write_cache_valid = false;
		write_cache_tag = 0;
		memset(write_cache, 0, sizeof(write_cache));
	}
	return NV_NO_ERROR;
}
