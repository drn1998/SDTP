#include <glib.h>
#include "irregint.h"

gboolean from_2x_uint4_to_uint8(guint8 * res, guint8 _4a, guint8 _4b) {
    if (G_UNLIKELY(_4a > 15 || _4b > 15)) {
        return FALSE;
    }

    *res = _4a;
    *res = *res << 4;
    *res = (*res | _4b);

    return TRUE;
}

void from_uint8_to_2x_uint4(guint8 input, guint8 * _4a, guint8 * _4b) {
    guint8 _input;

    _input = input;
    _input = _input & 0x0F; // 00001111 mask
    *_4b = _input;

    _input = input;
    _input = input >> 4;
    *_4a = _input;

    return;
}

gboolean from_uint32_to_uint24(guchar * res, guint32 _24) {
    gpointer ptr;
    
    if (G_UNLIKELY(_24 > UINT24_MAX)) {
        return FALSE;
    }

    ptr = &_24;
    ptr += 1;

    _24 = GUINT32_TO_BE(_24);

    memcpy(res, ptr, 3);

    return TRUE;
}

void from_uint24_to_uint32(guchar * input, guint32 * _24) {
    *_24 = 0;

    memcpy(_24, input, 3);
    *_24 = *_24 << 8;

    *_24 = GUINT32_FROM_BE(*_24);

    return;
}

gboolean from_uint64_to_uint48(guchar * res, guint64 _48) {
    gpointer ptr;
    
    if (G_UNLIKELY(_48 > UINT48_MAX)) {
        return FALSE;
    }

    ptr = &_48;
    ptr += 2;

    _48 = GUINT64_TO_BE(_48);

    memcpy(res, ptr, 6);

    return TRUE;
}

void from_uint48_to_uint64(guchar * input, guint64 * _48) {
    *_48 = 0;

    memcpy(_48, input, 6);
    *_48 = *_48 << 16;

    *_48 = GUINT64_FROM_BE(*_48);

    return;
}

void from_8x_bool_to_uint8(guint8 * res, gboolean _bools[8]) {
    register int i;

    for(i = 0; i < 8; i++)
        *res = (_bools[i] << i) | *res;

    return;
}

void from_uint8_to_8x_bool(guint8 input, gboolean _bools[8]) {
    register int i;

    for(i = 0; i < 8; i++)
        _bools[i] = (input >> i) & 1;

    return;
}