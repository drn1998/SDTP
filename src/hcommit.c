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
    (*commitment)->content.has_commit = FALSE;
    (*commitment)->content.has_reveal = FALSE;

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

    return;
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

void SDTP_commitment_serialize(SDTP_commitment * commitment, GByteArray * commit_dest, GByteArray * reveal_dest, gboolean is_human_readable) {
    // Check completeness!

    GByteArray * out_array;

    GByteArray * head_array;
    GByteArray * body_array;

    out_array = g_byte_array_new();
    head_array = g_byte_array_new();
    body_array = g_byte_array_new();

    __internal_SDTP_commitment_head_get(commitment, head_array, COMMITMENT_OPERATION_MODE_COMMIT, is_human_readable);
    __internal_SDTP_commitment_body_get(commitment, body_array, COMMITMENT_OPERATION_MODE_COMMIT);

    g_byte_array_append(out_array, head_array->data, head_array->len);
    g_byte_array_append(out_array, body_array->data, body_array->len);
    g_byte_array_assign(commit_dest, out_array->data, out_array->len);

    g_byte_array_empty(out_array);
    g_byte_array_empty(head_array);
    g_byte_array_empty(body_array);

    __internal_SDTP_commitment_head_get(commitment, head_array, COMMITMENT_OPERATION_MODE_REVEAL, is_human_readable);
    __internal_SDTP_commitment_body_get(commitment, body_array, COMMITMENT_OPERATION_MODE_REVEAL);

    g_byte_array_append(out_array, head_array->data, head_array->len);
    g_byte_array_append(out_array, body_array->data, body_array->len);
    g_byte_array_assign(reveal_dest, out_array->data, out_array->len);

    g_byte_array_free(out_array, TRUE);
    g_byte_array_free(head_array, TRUE);
    g_byte_array_free(body_array, TRUE);


    return;
}

void SDTP_commitment_deserialize(SDTP_commitment * commitment, GByteArray * commitment_src, SDTP_commitment_validity * validity) {
    GByteArray * head;
    GByteArray * body;

    GDateTime * current_utc;

    guint8 cmp_hash[DEF_HASHVAL_LENGTH];

    SDTP_commitment_operation_mode mode;
    gboolean human_readable;

    head = g_byte_array_new();
    body = g_byte_array_new();

    g_byte_array_assign(head, commitment_src->data, 3);
    g_byte_array_assign(body, commitment_src->data + 3, commitment_src->len - 3);   // Use third byte instead of magic number

    __internal_SDTP_commitment_head_setby(commitment, head, &mode, &human_readable);

    if(mode == COMMITMENT_OPERATION_MODE_COMMIT)
        commitment->content.has_commit = TRUE;
    else if (mode == COMMITMENT_OPERATION_MODE_REVEAL)
        commitment->content.has_reveal = TRUE;

    if(commitment->_revelation_set == TRUE && (commitment->content.has_commit != commitment->content.has_reveal))
        commitment->revelation = g_date_time_new_from_unix_utc(0);

    __internal_SDTP_commitment_body_setby(commitment, body, mode);

    if (commitment->content.has_commit && commitment->content.has_reveal) {
        memcpy(cmp_hash, commitment->hashval->data, DEF_HASHVAL_LENGTH);
        commitment->_hash_uptodate = FALSE;
        __internal_SDTP_commitment_hashval_calc(commitment);
        if(memcmp(commitment->hashval->data, cmp_hash, DEF_HASHVAL_LENGTH) == 0)
            *validity = COMMITMENT_VALID;
    }

    if(commitment->_revelation_set) {
        current_utc = g_date_time_new_now_utc();
        
        if(g_date_time_compare(commitment->revelation, current_utc) < 1)
            *validity = COMMITMENT_NOT_VALID_DATETIME;

        g_date_time_unref(current_utc);
    }

    g_byte_array_free(head, TRUE);
    g_byte_array_free(body, TRUE);
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

    return;
}

void __internal_SDTP_commitment_head_get(SDTP_commitment * commitment, GByteArray * head_dest, SDTP_commitment_operation_mode operation_mode, gboolean is_human_readable) {
    gboolean himem;
    register int i;
    guint8 to_head;  // Next byte written to header
    guint offset = 0;
    gboolean flags[8];

    g_byte_array_empty(head_dest);

    if(commitment->datamode == COMMITMENT_DATA_MODE_BINARY && commitment->payload->len > UINT24_MAX) {
        himem = TRUE;
    } else himem = FALSE;

    {
        // First three flags are always unset
        for (i = 0; i < 3; i++) {
            flags[offset] = FALSE;
            offset++;
        }

        flags[offset] = himem;
        offset++;

        flags[offset] = is_human_readable;
        offset++;

        flags[offset] = commitment->_revelation_set;
        offset++;

        if(operation_mode == COMMITMENT_OPERATION_MODE_COMMIT) {
            flags[offset] = FALSE;
        } else {
            flags[offset] = TRUE;
        } 
        offset++;

        if(commitment->datamode == COMMITMENT_DATA_MODE_BINARY) {
            flags[offset] = FALSE;
        } else {
            flags[offset] = TRUE;
        }
        offset++;

        offset = 0;
    }

    from_2x_uint4_to_uint8(&to_head, 0, 0);
    g_byte_array_append(head_dest, &to_head, 1);

    from_8x_bool_to_uint8(&to_head, flags);
    g_byte_array_append(head_dest, &to_head, 1);

    to_head = 3;    // Fourth byte is first of body
    g_byte_array_append(head_dest, &to_head, 1);
    
    return;
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

    return;
}

void __internal_SDTP_commitment_head_setby(SDTP_commitment * commitment, GByteArray * head_src, SDTP_commitment_operation_mode * operation_mode, gboolean * is_human_readable) {
    gboolean himem;
    register int i;
    guint8 to_head;  // Next byte written to header
    guint offset = 0;
    gboolean flags[8];

    if(head_src->data[offset] != 0)
        return;

    offset++;

    from_uint8_to_8x_bool(head_src->data[offset], flags);

    // Third byte relevant for split-join-fn's, not this one

    offset = 3; // Ignore reserved flags for now

    commitment->_is_himem = flags[offset];
    offset++;

    *is_human_readable = flags[offset];
    offset++;

    commitment->_revelation_set = flags[offset];
    offset++;

    if(!flags[offset]) {
        *operation_mode = COMMITMENT_OPERATION_MODE_COMMIT;
    } else {
        *operation_mode = COMMITMENT_OPERATION_MODE_REVEAL;
    } offset++;

    if(!flags[offset]) {
        commitment->datamode = COMMITMENT_DATA_MODE_BINARY;
    } else {
        commitment->datamode = COMMITMENT_DATA_MODE_TEXT;
    } offset++;

    offset = 0;

}

void __internal_SDTP_commitment_body_setby(SDTP_commitment * commitment, GByteArray * body_src, SDTP_commitment_operation_mode operation_mode) {
    guint offset = 0;
    guint nullbyte = 0x00;
    guint payload_size = 0;
    guchar reveal_time_binary[UINT48_BYTES];    // Rename as also used for uint24/uint48 of binary len
    guint64 unix_time;

    g_byte_array_append(body_src, &nullbyte, 1);

    if(operation_mode == COMMITMENT_OPERATION_MODE_COMMIT) {

        if (commitment->_revelation_set) {
            if(body_src->len < (UINT48_BYTES + DEF_HASHVAL_LENGTH))
                return; // Not minimum length
            
            memcpy(reveal_time_binary, body_src->data + offset, UINT48_BYTES);
            from_uint48_to_uint64(reveal_time_binary, &unix_time);
            SDTP_commitment_revelation_set(commitment, unix_time);
            offset += UINT48_BYTES;
        }

        g_byte_array_assign(commitment->hashval, body_src->data + offset, DEF_HASHVAL_LENGTH);
        offset += DEF_HASHVAL_LENGTH;

        g_string_assign(commitment->subject, body_src->data + offset);

        offset = 0;
    } else if (operation_mode == COMMITMENT_OPERATION_MODE_REVEAL) {
        g_byte_array_assign(commitment->entropy, body_src->data, DEF_ENTROPY_LENGTH);
        offset += DEF_ENTROPY_LENGTH;

        if (commitment->_revelation_set) {
            if(body_src->len < (UINT48_BYTES + DEF_ENTROPY_LENGTH + 2))
                return; // Not minimum length
            
            memcpy(reveal_time_binary, body_src->data + offset, UINT48_BYTES);
            from_uint48_to_uint64(reveal_time_binary, &unix_time);
            SDTP_commitment_revelation_set(commitment, unix_time);
            offset += UINT48_BYTES;
        }

        g_string_assign(commitment->subject, body_src->data + offset);
        offset += strlen(commitment->subject->str) + 1;

        if(commitment->datamode == COMMITMENT_DATA_MODE_TEXT) {
            g_string_assign(commitment->message, body_src->data + offset);
        } else if (commitment->datamode == COMMITMENT_DATA_MODE_BINARY) {
            memset(reveal_time_binary, 0, UINT48_BYTES);

            if(!commitment->_is_himem) {
                guint32 payload_32 = 0;
                memcpy(reveal_time_binary, body_src->data + offset, UINT24_BYTES);
                from_uint24_to_uint32(reveal_time_binary, &payload_32);
                payload_size = payload_32;
                offset += UINT24_BYTES;
            } else if (commitment->_is_himem) {
                guint64 payload_64 = 0;
                memcpy(reveal_time_binary, body_src->data + offset, UINT48_BYTES);
                from_uint48_to_uint64(reveal_time_binary, &payload_64);
                payload_size = payload_64;
                offset += UINT48_BYTES;
            }

            g_byte_array_assign(commitment->payload, body_src->data + offset, payload_size);
        }
    }
}
