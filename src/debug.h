#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <glib-2.0/glib.h>

void debug_print_gbyte_array(GByteArray * to_print, char * identifier);
void debug_print_mem(char * dat, size_t len, char * identifier);

#endif
