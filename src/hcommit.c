#include <glib.h>
#include <stdio.h>
#include <gcrypt.h>
#include "hcommit_frame.h"
#include "hcommit.h"
#include "util.h" 

SDTP_Commitment * sdtp_commitment_new() {
    SDTP_Commitment * s;

    s = g_new(SDTP_Commitment, 1);

    if(s == NULL)
        g_abort();

    s->frame = sdtp_commitment_frame_new();

    return s;
}

void sdtp_commitment_free(SDTP_Commitment * s) {
    sdtp_commitment_frame_free(s->frame);

    g_free(s);

    return;
}

void sdtp_commitment_content_set(SDTP_Commitment * s, guchar * data, gsize len) {
    sdtp_commitment_frame_set_data(s->frame, data, len);

    return;
}

void sdtp_commitment_revelation_set(SDTP_Commitment * s, guint64 unix_utc) {
    sdtp_commitment_frame_set_revelation(s->frame, unix_utc);

    return;
}

void sdtp_commitment_calculate_hash(SDTP_Commitment * s) {
    GByteArray * frame_data;
    gcry_md_hd_t hash_handle;
    guchar * md_result;

    frame_data = g_byte_array_new();

    sdtp_commitment_frame_serialize(s->frame, frame_data);

    gcry_md_open(&hash_handle, GCRY_MD_SHA256, 0);

    gcry_md_write(hash_handle, frame_data->data, frame_data->len);

    md_result = gcry_md_read(hash_handle, GCRY_MD_SHA256);

    memcpy(s->hash_value, md_result, HASH_SIZE);

    gcry_md_close(hash_handle);

    g_byte_array_free(frame_data, TRUE);
}

int sdtp_commitment_serialize(SDTP_Commitment * s, GByteArray * commit, GByteArray * reveal) {
    GByteArray * frame_data;

    g_byte_array_empty(commit);
    g_byte_array_empty(reveal);

    frame_data = g_byte_array_new();

    if(sdtp_commitment_frame_serialize(s->frame, frame_data) == -1)
        return -1;

    const guint8 content_id = 0x11;
    guint8 phase_id;

    sdtp_commitment_calculate_hash(s);

    // Serialize commit data
    phase_id = PHASE_COMMIT;

    g_byte_array_append(commit, &content_id, sizeof(content_id));
    g_byte_array_append(commit, &phase_id, sizeof(phase_id));
    g_byte_array_append(commit, s->hash_value, HASH_SIZE);


    // Serialize reveal data
    phase_id = PHASE_REVEAL;

    g_byte_array_append(reveal, &content_id, sizeof(content_id));
    g_byte_array_append(reveal, &phase_id, sizeof(phase_id));
    g_byte_array_append(reveal, frame_data->data, frame_data->len);


    g_byte_array_free(frame_data, TRUE);

    return 0;
}

sdtp_commitment_phase sdtp_commitment_data_get_phase (guchar * data, gsize len) {
    if(len < 2)
        return PHASE_INVALID;
    
    if(data[0] != 0x11)
        return PHASE_INVALID;
    
    if(data[1] == PHASE_COMMIT)
        return PHASE_COMMIT;
    
    if(data[1] == PHASE_REVEAL)
        return PHASE_REVEAL;
    
    return PHASE_INVALID;
}

int sdtp_commitment_deserialize(SDTP_Commitment * s, guchar * data, gsize len) {
    sdtp_commitment_phase p;

    guint offset = 0;
    GByteArray * frame_data;

    p = sdtp_commitment_data_get_phase(data, len);

    if(p == PHASE_INVALID)
        return -1;
    
    if(p == PHASE_COMMIT) {
        if(len != sizeof(guint8) + sizeof(guint8) + HASH_SIZE)
            return -1;

        offset += (sizeof(guint8) + sizeof(guint8));

        memcpy(s->hash_value, data + offset, HASH_SIZE);
    }

    if(p == PHASE_REVEAL) {
        if(len <= sizeof(guint8) + sizeof(guint8))
            return -1;

        offset += (sizeof(guint8) + sizeof(guint8));

        frame_data = g_byte_array_new();

        g_byte_array_assign(frame_data, data + offset, len - offset);

        if(sdtp_commitment_frame_deserialize(s->frame, frame_data->data, frame_data->len) == -1)
            return -1;

        s->frame->entropy_set = TRUE;

        g_byte_array_free(frame_data, TRUE);
    }

    return 0;
}

sdtp_commitment_status sdtp_commitment_check(SDTP_Commitment * s) {
    GByteArray * frame_data;
    gcry_md_hd_t hash_handle;
    guchar * md_result;
    sdtp_commitment_status result;
    GDateTime * now;

    frame_data = g_byte_array_new();

    sdtp_commitment_frame_serialize(s->frame, frame_data);

    gcry_md_open(&hash_handle, GCRY_MD_SHA256, 0);

    gcry_md_write(hash_handle, frame_data->data, frame_data->len);

    md_result = gcry_md_read(hash_handle, GCRY_MD_SHA256);

    if(!memcmp(md_result, s->hash_value, HASH_SIZE)) {
        now = g_date_time_new_now_utc();

        if(g_date_time_compare(now, s->frame->revelation) < 0)
            result = COMMITMENT_VALID;
        else
            result = COMMITMENT_EXPIRED;

        g_date_time_unref(now);
    }
    else
        result = COMMITMENT_INVALID;

    gcry_md_close(hash_handle);
    g_byte_array_free(frame_data, TRUE);

    return result;
}