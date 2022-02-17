#include <glib.h>
#include <stdio.h>
#include <gcrypt.h>
#include "hcommit_frame.h"
#include "util.h"

sdtp_commitment_frame * sdtp_commitment_frame_new() {
    sdtp_commitment_frame * s;

    s = g_new(sdtp_commitment_frame, 1);

    if(s == NULL)
        g_abort();
    
    s->data = g_byte_array_new();
    s->revelation = NULL;
    s->entropy_set = FALSE;
    memset(s->entropy, 0, ENTROPY_SIZE);

    return s;
}

void sdtp_commitment_frame_free(sdtp_commitment_frame * s) {
    g_byte_array_free(s->data, TRUE);
    if(s->revelation != NULL)
        g_date_time_unref(s->revelation);

    g_free(s);

    return;
}

void sdtp_commitment_frame_set_data(sdtp_commitment_frame * s, guchar * data, gsize len) {
    g_byte_array_assign(s->data, data, len);

    return;
}

int sdtp_commitment_frame_serialize(sdtp_commitment_frame * s, GByteArray * out) {
    guint64 time;

    if(s->revelation == NULL) {
        return -1;
    }

    if(s->entropy_set == FALSE) {
       gcry_randomize(s->entropy, ENTROPY_SIZE, GCRY_STRONG_RANDOM);
       s->entropy_set = TRUE;
    }

    time = htobe64(g_date_time_to_unix(s->revelation));

    g_byte_array_empty(out);

    g_byte_array_append(out, &time, sizeof(time));
    g_byte_array_append(out, s->entropy, ENTROPY_SIZE);
    g_byte_array_append(out, s->data->data, s->data->len);

    return 0;
}

void sdtp_commitment_frame_set_revelation(sdtp_commitment_frame * s, guint64 unix_revelation) {
    if(s->revelation != NULL)
        g_date_time_unref(s->revelation);
    
    s->revelation = g_date_time_new_from_unix_utc(unix_revelation);

    return;
}

int sdtp_commitment_frame_deserialize(sdtp_commitment_frame * s, guchar * in, gsize len) {
    guint offset = 0;

    guint64 time;
    gsize bdata_size;

    if(len < (sizeof(guint64)) + ENTROPY_SIZE)
        return -1;

    bdata_size = (len - (sizeof(guint64) + ENTROPY_SIZE));

    if(s->revelation != NULL)
        g_date_time_unref(s->revelation);

    memcpy(&time, in + offset, sizeof(time));
    offset += sizeof(time);

    s->revelation = g_date_time_new_from_unix_utc(be64toh(time));

    memcpy(s->entropy, in + offset, ENTROPY_SIZE);
    offset += ENTROPY_SIZE;

    g_byte_array_append(s->data, in + offset, bdata_size);

    return 0;
}