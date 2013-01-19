/** \file ssd1306.h
  *
  * \brief Describes functions exported by ssd1306.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PIC32_SSD1306_H_INCLUDED
#define PIC32_SSD1306_H_INCLUDED

extern void initSSD1306(void);
extern void displayOn(void);
extern void displayOff(void);
extern void clearDisplay(void);
extern void nextLine(void);
extern void writeStringToDisplay(const char *str);
extern void writeStringToDisplayWordWrap(const char *str);
extern int displayCursorAtEnd(void);

#endif // #ifndef PIC32_SSD1306_H_INCLUDED
