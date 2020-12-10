#include "hcommit.h"
#include "crypto.h"
#include "irregint.h"
#include "debug.h"

void SDTP_commitment_create(SDTP_commitment ** commitment) {
    *commitment = g_new(SDTP_commitment, 1);

    if (*commitment == NULL) {
        g_abort();
    }

    (*commitment)->subject = g_string_new("<SUBJECT UNSET>");
    (*commitment)->message = g_string_new("<MESSAGE UNSET>");
    (*commitment)->payload = g_byte_array_new();
    (*commitment)->entropy = g_byte_array_new();
    (*commitment)->hashval = g_byte_array_new();

    (*commitment)->datamode = COMMITMENT_DATA_MODE_UNDEFINED;

    (*commitment)->_hash_uptodate = FALSE;
    (*commitment)->_revelation_set = FALSE;

    return;
}

void SDTP_commitment_delete(SDTP_commitment ** commitment) {
    g_string_free((*commitment)->subject, TRUE);
    g_string_free((*commitment)->message, TRUE);
    g_byte_array_free((*commitment)->payload, TRUE);
    g_byte_array_free((*commitment)->entropy, TRUE);
    g_byte_array_free((*commitment)->hashval, TRUE);

    if((*commitment)->_revelation_set) {
        g_date_time_unref((*commitment)->revelation);
    }

    g_free(*commitment);

    return;
}

void SDTP_commitment_subject_set(SDTP_commitment * commitment, gchar * subject) {
    if(strlen(subject) > MAX_SUBJECT_LENGTH) {
        return;
    }

    g_string_assign(commitment->subject, subject);
    commitment->_hash_uptodate = FALSE;

    return;
}

void SDTP_commitment_message_set(SDTP_commitment * commitment, gchar * message) {
    if(strlen(message) > MAX_MESSAGE_LENGTH) {
        return;
    }

    g_string_assign(commitment->message, message);
    commitment->datamode = COMMITMENT_DATA_MODE_TEXT;
    commitment->_hash_uptodate = FALSE;

    return;
}

void SDTP_commitment_payload_set(SDTP_commitment * commitment, guchar * data, gsize len) {
    if(len > MAX_PAYLOAD_LENGTH) {
        return;
    }

    g_byte_array_assign(commitment->payload, data, len);
    commitment->datamode = COMMITMENT_DATA_MODE_BINARY;
    commitment->_hash_uptodate = FALSE;
}

void SDTP_commitment_revelation_set(SDTP_commitment * commitment, gint64 time_utc) {
    GDateTime * current_utc;

    if (commitment->_revelation_set) {
        g_date_time_unref(commitment->revelation);
    } else {
        commitment->_revelation_set = TRUE;
    }

    current_utc = g_date_time_new_now_utc();
    commitment->revelation = g_date_time_new_from_unix_utc(time_utc);

    if(g_date_time_compare(commitment->revelation, current_utc) < 1) {
        g_date_time_unref(commitment->revelation);
        commitment->_revelation_set = FALSE;
    } else {
        commitment->_hash_uptodate = FALSE;
    }

    g_date_time_unref(current_utc);

    return;
}

void __internal_SDTP_commitment_entropy_set(SDTP_commitment * commitment) {
    gchar entropy[DEF_ENTROPY_LENGTH];
    
    if(commitment->entropy->len != DEF_ENTROPY_LENGTH) {
        SDTP_crypto_write_random_entropy(entropy, DEF_ENTROPY_LENGTH);
        g_byte_array_assign(commitment->entropy, entropy, DEF_ENTROPY_LENGTH);
        __internal_SDTP_commitment_hashval_calc(commitment);
    }

    return;
}

void __internal_SDTP_commitment_hashval_calc(SDTP_commitment * commitment) {
    gchar hash_value[HASH_LENGTH];
    GByteArray * body_reveal_to_hash;

    if(!commitment->_hash_uptodate) {
        body_reveal_to_hash = g_byte_array_new();
        __internal_SDTP_commitment_body_get(commitment, body_reveal_to_hash, COMMITMENT_OPERATION_MODE_REVEAL);
        SDTP_crypto_get_sha256_hash(hash_value, body_reveal_to_hash->data, body_reveal_to_hash->len);
        g_byte_array_assign(commitment->hashval, hash_value, HASH_LENGTH);
        g_byte_array_free(body_reveal_to_hash, TRUE);
        commitment->_hash_uptodate = TRUE;
    }
}

void __internal_SDTP_commitment_head_get(SDTP_commitment * commitment, GByteArray * head_dest, SDTP_commitment_operation_mode operation_mode, gboolean is_human_readable) {
    gboolean himem;
    register int i;
    guint8 to_head;  // Next byte written to header

    if(commitment->datamode == COMMITMENT_DATA_MODE_BINARY && commitment->payload->len > UINT24_MAX) {
        himem = TRUE;
    } else himem = FALSE;

    //gboolean flags[8] = {FALSE, FALSE, FALSE, himem, is_human_readable, commitment->_revelation_set, (operation_mode == COMMITMENT_OPERATION_MODE_REVEAL) ? FALSE : TRUE, (commitment->datamode == COMMITMENT_DATA_MODE_TEXT) ? FALSE : TRUE };

    from_2x_uint4_to_uint8(&to_head, 0, 0);
    g_byte_array_append(head_dest, &to_head, 1);

    from_8x_bool_to_uint8(&to_head, flags);
    g_byte_array_append(head_dest, &to_head, 1);

    to_head = 0;    // No offset (yet)
    g_byte_array_append(head_dest, &to_head, 1);

    debug_print_gbyte_array(head_dest, "head:");
    
}

void __internal_SDTP_commitment_body_get(SDTP_commitment * commitment, GByteArray * body_dest, SDTP_commitment_operation_mode operation_mode) {
    g_byte_array_empty(body_dest);

    gint64 time_utc;
    char time_48[UINT48_BYTES];
    gboolean is_himem;  // More than 16MiB data-mode size

    if (commitment->_revelation_set) {
        from_uint64_to_uint48(time_48, g_date_time_to_unix(commitment->revelation));
    }

    __internal_SDTP_commitment_entropy_set(commitment);

    if(operation_mode == COMMITMENT_OPERATION_MODE_COMMIT) {
        if(commitment->_revelation_set) {
            g_byte_array_append(body_dest, &time_48, UINT48_BYTES);
        }
        g_byte_array_append(body_dest, commitment->hashval->data, HASH_LENGTH);
        g_byte_array_append(body_dest, commitment->subject->str, commitment->subject->len);
    } else if(operation_mode == COMMITMENT_OPERATION_MODE_REVEAL) {
        g_byte_array_append(body_dest, commitment->entropy->data, DEF_ENTROPY_LENGTH);
        if(commitment->_revelation_set) {
            g_byte_array_append(body_dest, &time_48, UINT48_BYTES);
        }
        g_byte_array_append(body_dest, commitment->subject->str, commitment->subject->len + 1);
        if(commitment->datamode == COMMITMENT_DATA_MODE_TEXT) {
            g_byte_array_append(body_dest, commitment->message->str, commitment->message->len);
        } else if(commitment->datamode == COMMITMENT_DATA_MODE_BINARY) {
            if(commitment->payload->len <= UINT24_MAX) {
                is_himem = FALSE;
            } else is_himem = TRUE;

            char len_bytes[UINT48_BYTES];  // Only three needed if is_himem == FALSE
            memset(len_bytes, 0, UINT48_BYTES);

            if (!is_himem) {
                from_uint32_to_uint24(len_bytes, commitment->payload->len);
                g_byte_array_append(body_dest, len_bytes, UINT24_BYTES);
            } else {
                from_uint64_to_uint48(len_bytes, commitment->payload->len);
                g_byte_array_append(body_dest, len_bytes, UINT48_BYTES);
            }

            g_byte_array_append(body_dest, commitment->payload->data, commitment->payload->len);
        }
    }
}
