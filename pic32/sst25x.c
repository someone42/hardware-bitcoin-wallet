/** \file sst25x.c
  *
  * \brief Provides access to the SST25x series of serial flash memory chips.
  *
  * The SST25x series of serial flash memory chips are a group of external,
  * non-volatile memory chips from Silicon Storage Technology. Using
  * external (i.e. not integrated with the microcontroller) memory offers
  * more design flexibility, is typically more reliable and is cheaper (on a
  * cost-per-kilobyte basis) than internal memory.
  *
  * The functions in this file provide low-level, raw access to the flash
  * memory. Here "low-level" means that erase and program operations must occur
  * with sector granularity (see #SECTOR_SIZE) and no wear-levelling is
  * performed. Before calling any other function, initSST25x() must be called.
  *
  * While the code here is written for the SST25x series, other serial flash
  * memory chips (eg. from Winbond) have very similar interfaces. Thus the
  * code can probably be adapted to other serial flash memory chips relatively
  * easily.
  *
  * For hardware interfacing requirements, see initSST25x(). All references
  * to the "PIC32 family reference manual" refer to Section 23 (Serial
  * Peripheral Interface), revision G, obtained from
  * http://ww1.microchip.com/downloads/en/DeviceDoc/61106G.pdf on
  * 15 November 2012. All references to the "SST25VF080B datasheet" refer
  * to revision A, obtained from
  * http://ww1.microchip.com/downloads/en/DeviceDoc/25045A.pdf on
  * 10 January 2013.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <p32xxxx.h>
#include <stdint.h>
#include "pic32_system.h"
#include "sst25x.h"

/** One byte command op codes, taken from Table 5 of the SST25VF080B
  * datasheet. */
typedef enum SST25xOpCodesEnum
{
	/** Read memory, low speed (up to 25/33 MHz) version. */
	SST25X_READ					= 0x03,
	/** Read memory, high speed (up to 66/80 MHz) version. */
	SST25X_READ_HIGH_SPEED		= 0x0b,
	/** Erase 4 kilobyte sector. */
	SST25X_SECTOR_ERASE_4K		= 0x20,
	/** Erase 32 kilobyte sector. */
	SST25X_SECTOR_ERASE_32K		= 0x52,
	/** Erase 64 kilobyte sector. */
	SST25X_SECTOR_ERASE_64K		= 0xd8,
	/** Erase entire chip. */
	SST25X_CHIP_ERASE			= 0x60,
	/** Program 8 bits at specified address. */
	SST25X_BYTE_PROGRAM			= 0x02,
	/** Auto-address increment word program. */
	SST25X_AAI_WORD_PROGRAM		= 0xad,
	/** Read status register. */
	SST25X_READ_STATUS			= 0x05,
	/** Enable writes to status register. */
	SST25X_ENABLE_WRITE_STATUS	= 0x50,
	/** Write status register. */
	SST25X_WRITE_STATUS			= 0x01,
	/** Enable writes (program/erase). */
	SST25X_WRITE_ENABLE			= 0x06,
	/** Disable writes (program/erase). */
	SST25X_WRITE_DISABLE		= 0x04,
	/** Read device ID. */
	SST25X_READ_ID				= 0x90,
	/** Read device JEDEC ID. */
	SST25X_READ_JEDEC_ID		= 0x9f,
	/** Enable SO flash busy indicator. */
	SST25X_EBSY					= 0x70,
	/** Disable SO flash busy indicator. */
	SST25X_DBSY					= 0x80
} SST25xOpCodes;

/** Initialise the PIC32's SPI4 module to interface with the SST25x serial
  * flash. SCK4, SDI4 and SDO4 are expected to be directly connected to the
  * serial flash. SS4 should be connected to the serial flash's chip enable
  * pin and RB13 should be connected to the serial flash's write protect
  * pin. */
void initSST25x(void)
{
	uint32_t status;
	uint32_t junk;
	int i;
	uint8_t sst25x_status_register;

	AD1PCFGbits.PCFG8 = 1; // set SS4 as digital I/O
	AD1PCFGbits.PCFG13 = 1; // set RB13 as digital I/O
	AD1PCFGbits.PCFG14 = 1; // set SCK4 as digital I/O
	TRISBbits.TRISB13 = 0; // set RB13 as output
	PORTBbits.RB13 = 1; // disable hardware write protect
	TRISBbits.TRISB8 = 0; // set RB8 as output
	PORTBbits.RB8 = 1; // set slave select high
	// Wait 100 us for SST25x startup, as recommended in Table 16 of the
	// SST25VF080B datasheet.
	delayCycles(100 * CYCLES_PER_MICROSECOND);

	// The SPI initialisation sequence follows that which is described in
	// section 23.3.3.1 of the PIC32 family reference manual.
	status = disableInterrupts();
	SPI4CONbits.ON = 0; // stop and reset SPI module
	asm("nop"); // ensure at least one cycle follows clearing of ON bit
	// Make sure receive buffer is clear.
	for (i = 0; i < 16; i++)
	{
		junk = SPI4BUF;
	}
	SPI4CONbits.ENHBUF = 1; // enable enhanced buffer mode (i.e. enable FIFOs)
	SPI4BRG = 3; // set baud rate for 9 MHz operation
	SPI4STATbits.SPIROV = 0;
	SPI4CONbits.MSTEN = 1; // PIC32 is SPI master
	SPI4CONbits.CKP = 1; // idle high, active low
	SPI4CONbits.CKE = 0; // output transition on idle -> active
	SPI4CONbits.SMP = 0; // sample input in middle of data output time
	SPI4CONbits.MODE16 = 0; // 8 bit mode
	SPI4CONbits.MODE32 = 0; // 8 bit mode
	SPI4CONbits.DISSDO = 0; // enable SDO
	SPI4CONbits.SIDL = 0; // continue operation in idle mode
	SPI4CONbits.FRMEN = 0; // disable framed mode
	SPI4CONbits.MSSEN = 0; // disable slave select (that's controlled manually)
	SPI4CONbits.ON = 1; // start SPI module
	restoreInterrupts(status);

	// Disable block level write protection. See Table 3 of the SST25VF080B
	// datasheet.
 	sst25x_status_register = sst25xReadStatusRegister();
	sst25x_status_register &= 0xc3; // clear BP0, BP1, BP2 and BP3
	sst25xWriteStatusRegister(sst25x_status_register);
}

/** Queue one byte of data for transmission via. SPI4. This will block until
  * the data can be successfully queued.
  * \param data The byte to transmit.
  */
static void writeSPI(uint8_t data)
{
	// Wait until there is space in the transmit FIFO.
	while (SPI4STATbits.SPITBF != 0)
	{
		// do nothing
	}
	// TODO: workaround for that PIC32 errata about double writes/reads when
	// interrupts occur on SFSR access.
	SPI4BUF = data;
}

/** Read one byte of data receieved from SPI4. This will block until there is
  * at least one byte of data available.
  * \return The next received byte.
  */
static uint8_t readSPI(void)
{
	// Wait until at least one byte of data is available.
	while (SPI4STATbits.SPIRBE != 0)
	{
		// do nothing
	}
	// TODO: workaround for that PIC32 errata about double writes/reads when
	// interrupts occur on SFSR access.
	return (uint8_t)SPI4BUF;
}

/** Issue a command via. SPI4. Commands are used to read, write and configure
  * the SST25x serial flash. A command consists of a bunch of bytes to transmit
  * followed by a bunch of bytes to receive.
  * \param command_buffer Array of bytes to transmit.
  * \param command_length Number of bytes in command_buffer.
  * \param read_buffer Received bytes will be written into this array.
  * \param read_length Number of bytes to receive.
  */
static void spiCommand(const uint8_t *command_buffer, unsigned int command_length, uint8_t *read_buffer, unsigned int read_length)
{
	unsigned int i;
	uint8_t dummy;

	// Why is slave select controlled manually? When slave select is under
	// automatic control, it will be set high whenever the transmit buffer
	// underruns. When compiler optimisations are turned off, this happens a
	// lot. The SST25x interprets slave select transitioning to high as the
	// end of a command. Therefore, slave select is controlled manually to
	// avoid premature end-of-command signals.
	// As a bit of a bonus, interrupts can safely be left enabled, since
	// transmit buffer underruns are benign.
	PORTBbits.RB8 = 0; // set slave select low
	asm("nop"); // delay just to be sure
	// Command stage: write command, doing dummy reads. The dummy reads are
	// necessary because SPI master mode is synchronous: when SCLK is toggled,
	// the SPI module reads in a byte, regardless of whether there is anything
	// to read or not.
	for (i = 0; i < command_length; i++)
	{
		writeSPI(command_buffer[i]);
		dummy = readSPI();
	}
	// Read stage: write dummy values, reading values into the read buffer.
	for (i = 0; i < read_length; i++)
	{
		writeSPI(0);
		read_buffer[i] = readSPI();
	}
	asm("nop"); // delay just to be sure
	PORTBbits.RB8 = 1; // set slave select high
}

/** Read the SST25x status register (see page 7 of the SST25VF080B datasheet).
  * \return The current value of the status register.
  */
uint8_t sst25xReadStatusRegister(void)
{
	uint8_t command_buffer[1];
	uint8_t read_buffer[1];

	command_buffer[0] = SST25X_READ_STATUS;
	spiCommand(command_buffer, 1, read_buffer, 1);
	return read_buffer[0];
}

/** Write to the SST25x status register (see page 7 of the SST25VF080B
  * datasheet). It is a sufficient condition that the write protect pin is
  * high for this to succeed.
  * \param sst25x_status_register The desired new value of the status register.
  */
void sst25xWriteStatusRegister(uint8_t sst25x_status_register)
{
	uint8_t command_buffer[2];
	uint8_t read_buffer[1];

	command_buffer[0] = SST25X_ENABLE_WRITE_STATUS;
	spiCommand(command_buffer, 1, read_buffer, 0);
	command_buffer[0] = SST25X_WRITE_STATUS;
	command_buffer[1] = sst25x_status_register;
	spiCommand(command_buffer, 2, read_buffer, 0);
}

/** Enable write operations (program and erase) to the SST25x serial flash.
  * This must be called before issuing program or erase commands, otherwise
  * those commands will be ignored.
  */
static void sst25xWriteEnable(void)
{
	uint8_t command_buffer[1];
	uint8_t read_buffer[1];

	command_buffer[0] = SST25X_WRITE_ENABLE;
	spiCommand(command_buffer, 1, read_buffer, 0);
}

/** Disable write operations (program and erase) to the SST25x serial flash.
  * This should be called after issuing program and erase commands to place
  * the flash into a safe state (so that SPI line noise is unlikely to result
  * in data corruption).
  * This can also be used to exit auto-address increment mode.
  */
static void sst25xWriteDisable(void)
{
	uint8_t command_buffer[1];
	uint8_t read_buffer[1];

	command_buffer[0] = SST25X_WRITE_DISABLE;
	spiCommand(command_buffer, 1, read_buffer, 0);
}

/** Wait until the SST25x serial flash is ready for another write (program or
  * erase) operation. This should be called after every write operation. It
  * does not need to be called after read operations.
  */
static void sst25xWaitUntilNotBusy(void)
{
	uint8_t sst25x_status_register;
	do
	{
		sst25x_status_register = sst25xReadStatusRegister();
	} while ((sst25x_status_register & 0x01) != 0);
}

/** Read from SST25x serial flash. There are no restrictions on address
  * alignment or length. However, attempting to read beyond the end of the
  * flash will cause wraparound behaviour.
  * \param data The data read from the flash memory will be placed here.
  * \param address The flash memory address to begin reading from.
  * \param length The number of bytes to read.
  */
void sst25xRead(uint8_t *data, uint32_t address, uint32_t length)
{
	uint8_t command_buffer[4];

	command_buffer[0] = SST25X_READ;
	command_buffer[1] = (uint8_t)(address >> 16);
	command_buffer[2] = (uint8_t)(address >> 8);
	command_buffer[3] = (uint8_t)(address);
	spiCommand(command_buffer, 4, data, length);
}

/** Erase an entire sector (#SECTOR_SIZE bytes) of the SST25x serial flash.
  * Erasing a sector resets its contents to all 1s. Use sst25xProgramSector()
  * to write arbitrary data to the sector.
  * \param address The address of the sector to erase. This must be aligned
  *                to a multiple of #SECTOR_SIZE.
  */
void sst25xEraseSector(uint32_t address)
{
	uint8_t command_buffer[4];
	uint8_t read_buffer[1];

	address &= (0xffffffff ^ (SECTOR_SIZE - 1)); // align to multiple of SECTOR_SIZE
	sst25xWriteEnable();
	command_buffer[0] = SST25X_SECTOR_ERASE_4K;
	command_buffer[1] = (uint8_t)(address >> 16);
	command_buffer[2] = (uint8_t)(address >> 8);
	command_buffer[3] = (uint8_t)(address);
	spiCommand(command_buffer, 4, read_buffer, 0);
	sst25xWaitUntilNotBusy();
	sst25xWriteDisable(); // just to be safe
}

/** Program an entire sector (#SECTOR_SIZE bytes) of the SST25x serial flash.
  * Programming allows the sector to be written with arbitrary data. Before
  * calling this, the sector should be in an erased state (use
  * sst25xEraseSector() to do that).
  * \param data The data to program the sector with. This must be
  *             exactly #SECTOR_SIZE bytes in size
  * \param address The address of the sector to program. This must be aligned
  *                to a multiple of #SECTOR_SIZE.
  */
void sst25xProgramSector(uint8_t *data, uint32_t address)
{
	unsigned int i;
	uint8_t command_buffer[6];
	uint8_t read_buffer[1];

	address &= (0xffffffff ^ (SECTOR_SIZE - 1)); // align to multiple of SECTOR_SIZE
	// Use auto-address increment mode with software end-of-write detection.
	// This follows Figure 11 of the SST25VF080B datasheet.
	sst25xWriteEnable();
	command_buffer[0] = SST25X_AAI_WORD_PROGRAM;
	command_buffer[1] = (uint8_t)(address >> 16);
	command_buffer[2] = (uint8_t)(address >> 8);
	command_buffer[3] = (uint8_t)(address);
	command_buffer[4] = data[0];
	command_buffer[5] = data[1];
	spiCommand(command_buffer, 6, read_buffer, 0);
	sst25xWaitUntilNotBusy();
	for (i = 2; i < SECTOR_SIZE; i += 2)
	{
		command_buffer[0] = SST25X_AAI_WORD_PROGRAM;
		command_buffer[1] = data[i];
		command_buffer[2] = data[i + 1];
		spiCommand(command_buffer, 3, read_buffer, 0);
		sst25xWaitUntilNotBusy();
	}
	sst25xWriteDisable(); // exit AAI mode
	sst25xWaitUntilNotBusy(); // just to be safe
}
