#ifndef IRREGINT_H
#define IRREGINT_H

#include <glib.h>

gboolean from_2x_uint4_to_uint8(guint8 * res, guint8 _4a, guint8 _4b);
void from_uint8_to_2x_uint4(guint8 input, guint8 * _4a, guint8 * _4b);

gboolean from_uint32_to_uint24(guchar * res, guint32 _32);
void from_uint24_to_uint32(guchar input[3], guint32 * _32);

#endif