#ifndef IRREGINT_H
#define IRREGINT_H

#define UINT24_MAX 16777215
#define UINT48_MAX 281474976710655

#include <glib.h>

gboolean from_2x_uint4_to_uint8(guint8 * res, guint8 _4a, guint8 _4b);
void from_uint8_to_2x_uint4(guint8 input, guint8 * _4a, guint8 * _4b);

gboolean from_uint32_to_uint24(guchar * res, guint32 _32);
void from_uint24_to_uint32(guchar * input, guint32 * _32);

gboolean from_uint64_to_uint48(guchar * res, guint64 _48);
void from_uint48_to_uint64(guchar * input, guint64 * _48);

void from_8x_bool_to_uint8(guint8 * res, gboolean _bools[8]);
void from_uint8_to_8x_bool(guint input, gboolean _bools[8]);

#endif