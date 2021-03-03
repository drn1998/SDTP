#ifndef HCOMMIT_H
#define HCOMMIT_H

#include <glib-2.0/glib.h>

#define MAX_SUBJECT_LENGTH 64
#define MAX_MESSAGE_LENGTH 1024
#define MAX_PAYLOAD_LENGTH 281474976710656
#define DEF_ENTROPY_LENGTH 12
#define DEF_HASHVAL_LENGTH 32

#define g_byte_array_empty(array); g_byte_array_remove_range(array,0,array->len);
#define g_byte_array_assign(array,data,length) {\
        g_byte_array_empty(array);\
        g_byte_array_append(array,data,length);\
    };

typedef enum SDTP_commitment_data_mode {
    COMMITMENT_DATA_MODE_UNDEFINED,
    COMMITMENT_DATA_MODE_TEXT,
    COMMITMENT_DATA_MODE_BINARY
} SDTP_commitment_data_mode;

typedef enum SDTP_commitment_operation_mode {
    COMMITMENT_OPERATION_MODE_COMMIT,
    COMMITMENT_OPERATION_MODE_REVEAL
} SDTP_commitment_operation_mode;

typedef enum SDTP_commitment_validity {
    COMMITMENT_NOT_VERIFIABLE,
    COMMITMENT_NOT_VALID,
    COMMITMENT_NOT_VALID_DATETIME,
    COMMITMENT_VALID
} SDTP_commitment_validity;

typedef struct SDTP_commitment_content {
    gboolean has_commit;
    gboolean has_reveal;
} SDTP_commitment_content;

typedef struct SDTP_commitment {
    GString * subject;
    GString * message;
    
    GByteArray * payload;
    GByteArray * entropy;
    GByteArray * hashval;

    GDateTime * revelation;

    SDTP_commitment_data_mode datamode;
    SDTP_commitment_content content;

    gboolean _hash_uptodate;
    gboolean _revelation_set;
    gboolean _is_himem; // Set using setby_header
} SDTP_commitment;

void SDTP_commitment_create(SDTP_commitment ** commitment);
void SDTP_commitment_delete(SDTP_commitment ** commitment);
void SDTP_commitment_subject_set(SDTP_commitment * commitment, gchar * subject);
void SDTP_commitment_message_set(SDTP_commitment * commitment, gchar * message);
void SDTP_commitment_payload_set(SDTP_commitment * commitment, guchar * data, gsize len);
void SDTP_commitment_revelation_set(SDTP_commitment * commitment, gint64 time_utc);

void SDTP_commitment_serialize(SDTP_commitment * commitment, GByteArray * commit_dest, GByteArray * reveal_dest, gboolean is_human_readable);
void SDTP_commitment_deserialize(SDTP_commitment * commitment, GByteArray * commitment_src, SDTP_commitment_validity * validity);

void __internal_SDTP_commitment_entropy_set(SDTP_commitment * commitment);
void __internal_SDTP_commitment_hashval_calc(SDTP_commitment * commitment);

void __internal_SDTP_commitment_head_get(SDTP_commitment * commitment, GByteArray * head_dest, SDTP_commitment_operation_mode operation_mode, gboolean is_human_readable);
void __internal_SDTP_commitment_head_setby(SDTP_commitment * commitment, GByteArray * head_src, SDTP_commitment_operation_mode * operation_mode, gboolean * is_human_readable);
void __internal_SDTP_commitment_body_get(SDTP_commitment * commitment, GByteArray * body_dest, SDTP_commitment_operation_mode operation_mode);
void __internal_SDTP_commitment_body_setby(SDTP_commitment * commitment, GByteArray * body_src, SDTP_commitment_operation_mode operation_mode);

#endif
