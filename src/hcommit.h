#ifndef HCOMMIT_H
#define HCOMMIT_H

#include <glib-2.0/glib.h>
#include <stdio.h>

#define DEF_ENTROPY_LENGTH 12
#define MAX_SUBJECT_LENGTH 64
#define MAX_MESSAGE_LENGTH 1024
#define MAX_PAYLOAD_LENGTH 16777216

typedef enum commitment_datamode_t {
    COMMITMENT_TEXT_MESSAGE,
    COMMITMENT_DATA_PAYLOAD
} commitment_datamode_t; // Rename to DATAMODE_TEXT/DATA ?

typedef enum commitment_operation_mode_t {
    OPERATION_MODE_COMMIT,
    OPERATION_MODE_REVEAL
} commitment_operation_mode_t;

typedef struct commitment_s {
    GString * commitment_message;
    GString * commitment_subject;
    GByteArray * commitment_payload;

    gboolean commitment_schedule_b;
    gboolean commitment_calculated_b;

    GByteArray * commitment_entropy;
    GByteArray * commitment_hashval;
    GDateTime * commitment_revelation;

    commitment_datamode_t commitment_datamode;

} commitment_s; // Rename SDTP_Commitment?

int SDTP_commitment_create(commitment_s ** obj);
int SDTP_commitment_delete(commitment_s ** obj);
int SDTP_commitment_message_set(commitment_s * obj, GString * msg);
int SDTP_commitment_subject_set(commitment_s * obj, GString * sub);
int SDTP_commitment_payload_set(commitment_s * obj, GByteArray * pyl);
int SDTP_commitment_entropy_set(commitment_s * obj);
int SDTP_commitment_schedule_set(commitment_s * obj, const gchar * datetime);
int SDTP_commitment_prepare(commitment_s * obj);
int SDTP_commitment_clear(commitment_s * obj);
int SDTP_commitment_printf(commitment_s * obj);
int SDTP_commitment_hashval_calculate(commitment_s * obj);
int SDTP_commitment_validity_check(commitment_s * obj);
int SDTP_commitment_body_get(commitment_s * obj, GByteArray * out, commitment_operation_mode_t mode);
int SDTP_commitment_set_by_body(commitment_s * obj, GByteArray * out, commitment_operation_mode_t omode);

#endif