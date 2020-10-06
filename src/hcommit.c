/* General Todo
 * Is there a glib-internal function to test if an object (especially strings) is set or not?
 * Rename SDTP_commitment_write to **_serialize?
 * Use glibcryptos implementation for SHA-256 and random entropy
 */

#include <glib-2.0/glib.h>
#include <stdio.h>
#include <string.h>

#include "hcommit.h"

int SDTP_commitment_create(commitment_s ** obj) {
    *obj = g_new(commitment_s, 1);

    if(*obj == NULL)
        abort();

    return 0;
}

int SDTP_commitment_delete(commitment_s ** obj) {
    g_free(*obj);

    return 0;
}

int SDTP_commitment_message_set(commitment_s * obj, GString * msg) {

    if(strlen(msg->str) > MAX_MESSAGE_LENGTH) {
        return -1;
    }

    g_string_assign(obj->commitment_message, msg->str);

    obj->commitment_datamode = COMMITMENT_TEXT_MESSAGE;
    obj->commitment_calculated_b = FALSE; // Hash is no longer valid

    return 0;
}

int SDTP_commitment_payload_set(commitment_s * obj, GByteArray * pyl) {
    if (pyl->len > MAX_PAYLOAD_LENGTH)
        return -1;

    g_byte_array_append(obj->commitment_payload, pyl->data, pyl->len);
    obj->commitment_datamode = COMMITMENT_DATA_PAYLOAD;
    obj->commitment_calculated_b = FALSE;  // Hash is no longer valid

    return 0;
}

int SDTP_commitment_subject_set(commitment_s * obj, GString * sub) {

    if(strlen(sub->str) > MAX_SUBJECT_LENGTH)
        return -1;
 
    g_string_assign(obj->commitment_subject, sub->str);

    obj->commitment_calculated_b = FALSE; // Hash is no longer valid

    return 0;
}

int SDTP_commitment_entropy_set(commitment_s * obj) {
    guint8 entropy[DEF_ENTROPY_LENGTH];
    FILE * entropy_f;

    entropy_f = fopen("/dev/urandom", "r");

    if(entropy_f == NULL) {
        puts("Error: Unable to open /dev/urandom. Check read permission.");
        return -1;
    }

    fread(entropy, DEF_ENTROPY_LENGTH, 1, entropy_f);

    fclose(entropy_f);

    g_byte_array_append(obj->commitment_entropy, entropy, sizeof(entropy));

    obj->commitment_calculated_b = FALSE;

    return 0;
}

int SDTP_commitment_body_get(commitment_s * obj, GByteArray * out, commitment_operation_mode_t mode) {
    guint64 time_binary;

    // TODO Check existence of entropy, subject etc. unless hidden from public API

    if (mode == OPERATION_MODE_REVEAL) {
        time_binary = GUINT64_TO_BE(g_date_time_to_unix(obj->commitment_revelation));

        g_byte_array_append(out, obj->commitment_entropy->data, obj->commitment_entropy->len);
        g_byte_array_append(out, &time_binary, sizeof(time_binary));
        g_byte_array_append(out, obj->commitment_subject->str, obj->commitment_subject->len + 1);   // Include NULL byte
        if (obj->commitment_datamode == COMMITMENT_TEXT_MESSAGE)
            g_byte_array_append(out, obj->commitment_message->str, obj->commitment_message->len + 1); // Required here? EOF
        else if (obj->commitment_datamode == COMMITMENT_DATA_PAYLOAD) {
            // Get three byte representation of length (16384 KiB)
            guint32 payload_coded_size; // 16 MiB
            guint8 packed[4];
            payload_coded_size = GUINT32_TO_BE(obj->commitment_payload->len);
            memcpy(packed, &payload_coded_size, 4);
            g_byte_array_append(out, packed + 1, 3);
            // Append length, then actual data
            g_byte_array_append(out, obj->commitment_payload->data, obj->commitment_payload->len);
        }
    } else if (mode == OPERATION_MODE_COMMIT) {
        g_byte_array_append(out, obj->commitment_hashval->data, obj->commitment_hashval->len);
    }

    return 0;
}

// TODO: Get rid of dmode, assume obj to have mode set using set_by_header
int SDTP_commitment_set_by_body(commitment_s * obj, GByteArray * out, commitment_operation_mode_t omode, commitment_datamode_t dmode) {
    guint offset = 0;

    if (omode == OPERATION_MODE_REVEAL) {

        guint64 time_binary;
        gsize len;

        if (out->len < DEF_ENTROPY_LENGTH + sizeof(guint64) + 1 + (dmode ? 1 : 3)) {
            puts("493");
            abort();
        }
        
        g_byte_array_append(obj->commitment_entropy, out->data, DEF_ENTROPY_LENGTH);
        offset += DEF_ENTROPY_LENGTH;

        // Unix-Time value, 64 bit, to GDateTime
        memcpy(&time_binary, out->data + offset, sizeof(guint64));
        time_binary = GINT64_FROM_BE(time_binary);
        offset += sizeof(guint64);
        
        len = strlen(out->data + offset);
        if (len > out->len - (offset +  (dmode ? 1 : 3)))
            abort();

        g_string_assign(obj->commitment_subject, out->data + offset);

        offset += len + 1;

        if (dmode == COMMITMENT_TEXT_MESSAGE) {
            len = strlen(out->data + offset);
            
            // TODO: Checks required?

            g_string_assign(obj->commitment_message, out->data + offset);

            offset = -1; // Done, no value reasonable
        }


    }

}

// TODO: Analogous to subject_set and message_set, modify to allow overwriting
int SDTP_commitment_schedule_set(commitment_s * obj, const gchar * datetime) {

    GDateTime * current_time;
    GTimeZone * UTC = g_time_zone_new("UTC");
    int return_value;

    obj->commitment_revelation = g_date_time_new_from_iso8601(datetime, UTC);
    current_time = g_date_time_new_now(UTC);

    if(g_date_time_compare(obj->commitment_revelation, current_time) < 1) {
        // puts("ERROR: Date lies in the past!");
        g_date_time_unref(obj->commitment_revelation);
        obj->commitment_revelation = g_date_time_new_from_iso8601("1970-01-01 00:00:00", UTC);
        obj->commitment_schedule_b = TRUE;  // It is set, albeit 1970-0
        return_value = -1;
    } else {
        obj->commitment_schedule_b = TRUE;
        return_value = 0;
    }

    g_date_time_unref(current_time);
    g_time_zone_unref(UTC);

    obj->commitment_calculated_b = FALSE;

    return return_value;
}

int SDTP_commitment_prepare(commitment_s * obj) {
    // TODO Security measure so it's called once?
    // Call prepare within create, clear within delete

    obj->commitment_entropy = g_byte_array_new();
    obj->commitment_hashval = g_byte_array_new();
    obj->commitment_payload = g_byte_array_new();

    obj->commitment_subject = g_string_new("");
    obj->commitment_message = g_string_new("");

    SDTP_commitment_schedule_set(obj, "1970-01-01 00:00:00"); // Ugly and ought tb changed

    // Initialize
    obj->commitment_schedule_b = FALSE;
    obj->commitment_calculated_b = FALSE;

    return 0;
}

int SDTP_commitment_clear(commitment_s * obj) {
    g_date_time_unref(obj->commitment_revelation);
    
    g_string_free(obj->commitment_subject, TRUE);
    g_string_free(obj->commitment_message, TRUE);

    g_byte_array_free(obj->commitment_entropy, TRUE);
    g_byte_array_free(obj->commitment_hashval, TRUE);
    g_byte_array_free(obj->commitment_payload, TRUE);

    return 0;
}

// TODO Add hexdump of entropy and hash value; decide between message or payload
int SDTP_commitment_printf(commitment_s * obj) {
    gchar * commitment_schedule_date_time;

    g_printf("Content of 'commitment_message':\t%s\n", obj->commitment_message->str);
    g_printf("Content of 'commitment_subject':\t%s\n", obj->commitment_subject->str);

    commitment_schedule_date_time = g_date_time_format_iso8601(obj->commitment_revelation);
    g_printf("Content of 'commitment_revelation':\t%s\n", commitment_schedule_date_time);
    g_free(commitment_schedule_date_time);

    return 0;
}