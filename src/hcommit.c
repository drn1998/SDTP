/* General Todo
 * Is there a glib-internal function to test if an object (especially strings) is set or not?
 * Rename SDTP_commitment_write to **_serialize?
 * Use glibcryptos implementation for SHA-256 and random entropy
 */

#include <glib-2.0/glib.h>
#include <stdio.h>

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
        return 67;
    }

    if (!obj->commitment_message_b)
        obj->commitment_message = g_string_new(msg->str);
    else
        g_string_assign(obj->commitment_message, msg->str);
    
    obj->commitment_message_b = TRUE;
    obj->commitment_payload_b = FALSE;

    obj->commitment_datamode = COMMITMENT_TEXT_MESSAGE;

    return 0;
}

int SDTP_commitment_subject_set(commitment_s * obj, GString * sub) {

    if(strlen(sub->str) > MAX_SUBJECT_LENGTH) {
        return 68;
    }
 
    obj->commitment_subject = g_string_new(sub->str);
    obj->commitment_subject_b = TRUE;

    return 0;
}

// int SDTP_commitment_payload_set(commitment_s * obj, )
int SDTP_commitment_content_unset(commitment_s * obj) {
    if (obj->commitment_subject_b && obj->commitment_message_b) {
        g_string_assign(obj->commitment_message, "");
        g_string_assign(obj->commitment_subject, "");

        return 0;
    } else {
        return 69;
    }
}

int SDTP_commitment_calculate(commitment_s * obj) {
    // TODO: Check if time, msg and subject is set already

    GByteArray * data_to_hash;

    data_to_hash = g_byte_array_new();

    guint8 hash[32];

    guint8 entropy[DEF_ENTROPY_LENGTH];
    FILE * entropy_f;
    #ifdef DEBUG
    FILE * hashout_f;

    hashout_f = fopen("hash", "w");
    #endif

    entropy_f = fopen("/dev/urandom", "r");

    if(entropy_f == NULL) {
        puts("Error: Unable to open /dev/urandom. Check read permission.");
    }

    fread(entropy, DEF_ENTROPY_LENGTH, 1, entropy_f);

    fclose(entropy_f);

    g_byte_array_append(obj->commitment_entropy, entropy, sizeof(entropy));

    SDTP_commitment_serialize(obj, data_to_hash);

    calc_sha_256(hash, data_to_hash->data, data_to_hash->len);

    g_byte_array_append(obj->commitment_hashval, hash, sizeof(hash));

    #ifdef DEBUG
    fwrite(obj->commitment_hashval->data, obj->commitment_hashval->len, 1, hashout_f);

    fclose(hashout_f);
    #endif

    g_byte_array_free(data_to_hash, TRUE);
    return 0;
}

/* Distinguish between commit and reveal out = reveal... OR let this be a mere
generator of the block to be hashed so it can later be performed with the reveal file
(and the commit file in the beginning) for comparison. */

int SDTP_commitment_serialize(commitment_s * obj, GByteArray * out) {
    gint64 rdate;   // CHECK Unsigned?

    rdate = GINT64_TO_BE(g_date_time_to_unix(obj->commitment_revelation));

    g_byte_array_append(out, obj->commitment_entropy->data, obj->commitment_entropy->len);
    g_byte_array_append(out, &rdate, sizeof(rdate));
    g_byte_array_append(out, obj->commitment_subject->str, strlen(obj->commitment_subject->str) + 1);
    g_byte_array_append(out, obj->commitment_message->str, strlen(obj->commitment_message->str) + 1);

    return 0;
}

int SDTP_commitment_deserialize(commitment_s * obj, GByteArray * in) {
    gint64 rdate = 0;
    guint32 entropy_o = 0;
    guint32 revelation_o = entropy_o + DEF_ENTROPY_LENGTH;
    guint32 subject_o = revelation_o + sizeof(rdate);
    guint32 message_o; // Undefined

    // assert that in-> len has minimum length

    g_byte_array_remove_range(obj->commitment_entropy, 0, obj->commitment_entropy->len);
    g_byte_array_append(obj->commitment_entropy, in, DEF_ENTROPY_LENGTH);

    memcpy(&rdate, in->data + revelation_o, 8);
    rdate = GINT64_FROM_BE(rdate);

    if (obj->commitment_schedule_b)
        g_date_time_unref(obj->commitment_revelation);

    obj->commitment_revelation = g_date_time_new_from_unix_utc(rdate);

    #ifdef DEBUG
    //printf("%lx", rdate);
    #endif

    if (obj->commitment_subject_b) {
        g_string_assign(obj->commitment_subject, in->data + subject_o);
    }

    message_o = subject_o + strlen(obj->commitment_subject->str) + 1;

    if (obj->commitment_message_b) {
        g_string_assign(obj->commitment_message, in->data + message_o);
    }

    return 0;
}

int SDTP_commitment_schedule_set(commitment_s * obj, const gchar * datetime) {

    GDateTime * current_time;
    GTimeZone * UTC = g_time_zone_new("UTC");
    int return_value;

    current_time = g_date_time_new_now(UTC);

    obj->commitment_revelation = g_date_time_new_from_iso8601(datetime, UTC);

    if(g_date_time_compare(obj->commitment_revelation, current_time) < 1) {
        puts("ERROR: Date lies in the past!");
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

    return return_value;
}

int SDTP_commitment_prepare(commitment_s * obj) {
    // TODO Security measure so it's called once?

    obj->commitment_entropy = g_byte_array_new();
    obj->commitment_hashval = g_byte_array_new();

    obj->commitment_message_b = FALSE;
    obj->commitment_payload_b = FALSE;
    obj->commitment_subject_b = FALSE;
    obj->commitment_schedule_b = FALSE;

    return 0;
}

int SDTP_commitment_clear(commitment_s * obj) {
    if(obj->commitment_schedule_b)
        g_date_time_unref(obj->commitment_revelation);
    if(obj->commitment_subject_b)
        g_string_free(obj->commitment_subject, TRUE);
    if(obj->commitment_message_b)
        g_string_free(obj->commitment_message, TRUE);

    g_byte_array_free(obj->commitment_entropy, TRUE);
    g_byte_array_free(obj->commitment_hashval, TRUE);

    return 0;
}

// TODO Add hexdump of entropy (and hash, later on)
int SDTP_commitment_printf(commitment_s * obj) {
    gchar * commitment_schedule_date_time;

    if(obj->commitment_message_b)
        g_printf("Content of 'commitment_message':\t%s\n", obj->commitment_message->str);
    if(obj->commitment_subject_b)
        g_printf("Content of 'commitment_subject':\t%s\n", obj->commitment_subject->str);
    if(obj->commitment_schedule_b) {
        commitment_schedule_date_time = g_date_time_format_iso8601(obj->commitment_revelation);
        g_printf("Content of 'commitment_revelation':\t%s\n", commitment_schedule_date_time);
        g_free(commitment_schedule_date_time);
    }

    return 0;
}