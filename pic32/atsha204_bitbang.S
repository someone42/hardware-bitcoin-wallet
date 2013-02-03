/* atsha204_bitbang.S
 *
 * Bit-bangs the single-wire interface to the Atmel ATSHA204 using the
 * PIC32's GPIO. This must be done in assembly because the ATSHA204 is
 * picky about timing, with a tolerance of only 5% for the timing of individual
 * bits.
 * All the functions here assume that the ATSHA204 SDA line is connected to
 * the first GPIO port (RA0/RB0/RC0/RD0 etc.) in the group.
 */

.text
.set noreorder

/** A bit must be sent every 4.34 us = 156.24 cycles (at CPU clock = 36 MHz).
  * The bit loop in atsha204SendToken() requires
  * 9 + 3 * (DELAY_LOOP_ITERATIONS) cycles (count them).
  */
#define DELAY_LOOP_ITERATIONS	49
/** To prevent glitches from interfering with with communication,
  * atsha204LookForBit() looks for a sustained signal. This value determines
  * how many iterations the signal must be sustained for. The search loop
  * in atsha204LookForBit() requires 12 cycles, so at CPU clock = 36 MHz, the
  * loop requires 0.333 microsecond. The ATSHA204 has a minimum pulse time of
  * 4.6 microsecond. This is (4.6 / 0.333) / 1.5, rounded down. The 1.5 is
  * a safety factor.
  */
#define GLITCH_FILTER_LENGTH	9

/* void atsha204SendToken(volatile uint32_t *port, uint32_t token, uint32_t size)
 *
 * Sends a single ATSHA204 token by bit-banging.
 *
 * Parameters:
 * a0 (port): Address of port to write to.
 * a1 (token): Token contents; least-significant bit will be sent first.
 * a2 (size): Token size, in number of bits.
 *
 * Warning: interrupts must be disabled and instruction caching must be turned
 * on. This is so that cycle timing is accurate.
 */
.global atsha204SendToken
atsha204SendToken:
	/* Equivalent C code is given in curly braces. */
bit_loop:
	/* Write bit to port. */
	/* {PORTF = (PORTF & ~1) | (token & 1);} */
	lw		$t0, 0($a0)
	andi	$t1, $a1, 1
	ins		$t0, $t1, 0, 1
	sw		$t0, 0($a0)
	/* {delayCycles(3 * DELAY_LOOP_ITERATIONS + 2);} */
	nop
	li		$t0, DELAY_LOOP_ITERATIONS
delay_loop:
	addiu	$t0, $t0, -1
	bne		$t0, $zero, delay_loop
	nop
	/* Move on to next bit, if there is one. */
	/* {token >>= 1;} */
	/* {if ((--token_size) != 0) goto bit_loop;} */
	addiu	$a2, $a2, -1
	bne		$a2, $zero, bit_loop
	srl		$a1, $a1, 1
	jr		$ra
	nop

/* void uint32_t atsha204LookForBit(volatile uint32_t *port, uint32_t desired_bit, uint32_t timeout_counter)
 *
 * Searches for a sustained low or high pulse on a GPIO port. "Sustained" means
 * that the pulse occurs for at least #GLITCH_FILTER_LENGTH loop iterations
 * (each loop iteration is 0.333 microsecond at 36 MHz). This function will
 * time out and stop searching after a supplied timeout length.
 *
 * Parameters:
 * a0 (port): Address of port to read from.
 * a1 (desired_bit): 0 = look for low, 1 = look for high.
 * a2 (timeout_counter): Timeout length (in number of iterations).
 * Returns: 1 if bit was found, 0 if timeout occurred.
 *
 * Warning: interrupts must be disabled and instruction caching must be turned
 * on. This is so that cycle timing is accurate.
 */
.global atsha204LookForBit
atsha204LookForBit:
	/* Equivalent C code is given in curly braces. */
	/* {desired_bit = (desired_bit & 1) ^ 1;} */
	andi	$a1, $a1, 1
	xori	$a1, $a1, 1
	/* {success_counter = 0;} */
	li		$t1, 0
	li		$t3, GLITCH_FILTER_LENGTH
search_loop:
	/* The idea here is bit == 1 means success, bit == 0 means failure. */
	/* {bit = (PORTF & 1) ^ desired_bit;} */
	lw		$t0, 0($a0)
	nop
	andi	$t0, $t0, 1
	xor		$t0, $t0, $a1
	/* {if (bit == 0) success_counter = 0; else success_counter++;} */
	subu	$t2, $zero, $t0
	and		$t1, $t1, $t2
	addu	$t1, $t1, $t0
	/* {if (success_counter == GLITCH_FILTER_LENGTH) goto found_bit;} */
	beq		$t1, $t3, found_bit
	nop
	/* {if ((--timeout_counter) != 0) goto search_loop;} */
	addu	$a2, $a2, -1
	bne		$a2, $zero, search_loop
	nop

	/* Timeout occurred. */
	/* {return 0;} */
	li		$v0, 0
	jr		$ra
	nop

found_bit:
	/* {return 1;} */
	li		$v0, 1
	jr		$ra
	nop
