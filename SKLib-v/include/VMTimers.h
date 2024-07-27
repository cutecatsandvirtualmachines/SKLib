#pragma once
#include <minwindef.h>

#define IO_TIMER1_PORT 0x40 /* 8253 Timer #1 */
#define NMISC_PORT 0x61
#define TIMER_REG_CNTR0 0 /* timer 0 counter port */
#define TIMER_REG_CNTR1 1 /* timer 1 counter port */
#define TIMER_REG_CNTR2 2 /* timer 2 counter port */
#define TIMER_REG_MODE 3 /* timer mode port */

/*
 * The outputs of the three timers are connected as follows:
 *
 * timer 0 -> irq 0
 * timer 1 -> dma chan 0 (for dram refresh)
 * timer 2 -> speaker (via keyboard controller)
 *
 * Timer 0 is used to call hard clock.
 * Timer 2 is used to generate console beeps.
 */
#define TIMER_CNTR0 (IO_TIMER1_PORT + TIMER_REG_CNTR0)
#define TIMER_CNTR1 (IO_TIMER1_PORT + TIMER_REG_CNTR1)
#define TIMER_CNTR2 (IO_TIMER1_PORT + TIMER_REG_CNTR2)
#define TIMER_MODE (IO_TIMER1_PORT + TIMER_REG_MODE)

#define IO_RTC 0x070 /* RTC */