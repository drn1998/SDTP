#include <glib.h>

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
    if (G_UNLIKELY(_24 > 16777215)) {
        return FALSE;
    }

    printf("%u\n", _24);
    printf("%016x\n", _24);

    memcpy(res, &_24, 3);

    return TRUE;
}