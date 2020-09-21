#ifndef HCOMMIT_H
#define HCOMMIT_H

#include <glib-2.0/glib.h>
#include <stdio.h>

#define DEF_ENTROPY_LENGTH 12
#define MAX_SUBJECT_LENGTH 64
#define MAX_MESSAGE_LENGTH 1024

typedef enum commitment_datamode_t {
    COMMITMENT_TEXT_MESSAGE,
    COMMITMENT_DATA_PAYLOAD
} commitment_datamode_t;

typedef struct commitment_s {
    GString * commitment_message;
    GString * commitment_subject;
    GByteArray * commitment_payload;

    gboolean commitment_message_b;
    gboolean commitment_subject_b;
    gboolean commitment_payload_b;
    gboolean commitment_schedule_b;

    GByteArray * commitment_entropy;
    GByteArray * commitment_hashval;
    GDateTime * commitment_revelation;

    commitment_datamode_t commitment_datamode;

} commitment_s;

int SDTP_commitment_create(commitment_s ** obj);
int SDTP_commitment_delete(commitment_s ** obj);
int SDTP_commitment_message_set(commitment_s * obj, GString * msg);
int SDTP_commitment_subject_set(commitment_s * obj, GString * sub);
int SDTP_commitment_calculate(commitment_s * obj);
int SDTP_commitment_content_unset(commitment_s * obj);
int SDTP_commitment_serialize(commitment_s * obj, GByteArray * out);
int SDTP_commitment_deserialize(commitment_s * obj, GByteArray * in);
int SDTP_commitment_schedule_set(commitment_s * obj, const gchar * datetime);
int SDTP_commitment_prepare(commitment_s * obj);
int SDTP_commitment_clear(commitment_s * obj);
int SDTP_commitment_printf(commitment_s * obj);

#endif