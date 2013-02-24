/* ssd1306_bitbang.S
 *
 * Bit-bangs a serial interface (simplex "3-wire" SPI) to the SSD1306 using
 * the PIC32's GPIO. The PIC32's SPI module isn't used because it cannot
 * handle 9 bit frames. Transmit functionality is implemented in assembly to
 * ensure that timing is independent of C compiler optimisation level.
 */

.text
.set noreorder

/** Bunch of nops to make cycle time longer so that pins don't toggle too
  * fast for the SSD1306. */
#define HALF_BIT_DELAY		nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;

/** Size of each SPI frame, in number of bits. This must be greater than 3,
  * otherwise a shift amount below will become negative. */
#define FRAME_SIZE			9

/* void ssd1306BitBangOneFrame(volatile uint32_t *port, uint32_t frame_data, uint32_t sclk_pin, uint32_t sdin_pin)
 *
 * Bit-bangs one frame in a SPI-like manner using the PIC32's GPIO.
 * Because there are not enough parameters, the chip select line is not
 * controlled from within this function. It must be set explicitly by the
 * caller.
 * The SSD1306 can tolerate some bits being slower than others. Therefore it
 * is okay to leave interrupts enabled when calling this.
 *
 * Parameters:
 * a0 (port): Address of port to write to.
 * a1 (frame): Frame data.
 * a2 (sclk_pin): Value of OLED_SCLK (see definition in ssd1306.c).
 * a3 (sdin_pin): Value of OLED_SDIN (see definition in ssd1306.c).
 */
.global ssd1306BitBangOneFrame
ssd1306BitBangOneFrame:
	/* Equivalent C code is given in curly braces. The code here relies on
	 * the fact that the address of PORTxCLR is the address of PORTx + 4 and
	 * the address if PORTxSET is the address of PORTx + 8. */
	/* Delay after chip select is set low. */
	HALF_BIT_DELAY
	/* {bit_count = FRAME_SIZE;} */
	li		$t0, FRAME_SIZE
bit_loop:
	/* Set SCLK line low. */
	/* {PORTDCLR = OLED_SCLK;} */
	sw		$a2, 4($a0)
	/* Set SDIN to next data bit. */
	/* {next_bit = (frame >> (FRAME_SIZE - 3)) & 4;} */
	srl		$t1, $a1, FRAME_SIZE - 3
	andi	$t1, $t1, 4
	/* {if (next_bit != 0) PORTDSET = OLED_SDIN; else PORTDCLR = OLED_SDIN;} */
	addu	$t1, $t1, $a0
	sw		$a3, 4($t1)
	HALF_BIT_DELAY
	/* Set SCLK line high. */
	/* {PORTDSET = OLED_SCLK;} */
	sw		$a2, 8($a0)
	HALF_BIT_DELAY
	/* Move on to next bit (if there is one). */
	/* {frame <<= 1;} */
	/* {if (--bit_count != 0) goto bit_loop;} */
	addiu	$t0, $t0, -1
	bne		$t0, $zero, bit_loop
	sll		$a1, $a1, 1
	/* Delay before chip select is set high. */
	HALF_BIT_DELAY
	jr		$ra
	nop
