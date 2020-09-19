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
    puts("Warning: Hash generation unimplemented. Only assigning random entropy!");

    guint8 entropy[DEF_ENTROPY_LENGTH];
    FILE * entropy_f;

    entropy_f = fopen("/dev/urandom", "r");

    if(entropy_f == NULL) {
        puts("Error: Unable to open /dev/urandom. Check read permission.");
    }

    fread(entropy, DEF_ENTROPY_LENGTH, 1, entropy_f);

    fclose(entropy_f);

    g_byte_array_append(obj->commitment_entropy, entropy, sizeof(entropy));
}

/* Distinguish between commit and reveal out = reveal... OR let this be a mere
generator of the block to be hashed so it can later be performed with the reveal file
(and the commit file in the beginning) for comparison. */

int SDTP_commitment_write(commitment_s * obj, GByteArray * out) {
    gint64 rdate;

    rdate = GINT64_TO_BE(g_date_time_to_unix(obj->commitment_revelation));

    g_byte_array_append(out, obj->commitment_entropy->data, obj->commitment_entropy->len);
    g_byte_array_append(out, obj->commitment_subject->str, strlen(obj->commitment_subject->str) + 1);
    g_byte_array_append(out, obj->commitment_message->str, strlen(obj->commitment_message->str) + 1);
    g_byte_array_append(out, &rdate, sizeof(rdate));

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