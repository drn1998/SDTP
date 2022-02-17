#ifndef HCOMMIT_H
#define HCOMMIT_H

#include "hcommit_frame.h"

#define HASH_SIZE 32

typedef enum {
    COMMITMENT_VALID,
    COMMITMENT_INVALID,
    COMMITMENT_EXPIRED,
    COMMITMENT_UNDEFINED
} sdtp_commitment_status;

typedef enum {
    PHASE_COMMIT = 0,
    PHASE_REVEAL = 1,
    PHASE_INVALID = 255
} sdtp_commitment_phase;

typedef struct {
    sdtp_commitment_frame * frame;
    guchar hash_value[HASH_SIZE];
} SDTP_Commitment;

SDTP_Commitment * sdtp_commitment_new();

void sdtp_commitment_free(SDTP_Commitment * s);

void sdtp_commitment_content_set(SDTP_Commitment * s, guchar * data, gsize len);

void sdtp_commitment_revelation_set(SDTP_Commitment * s, guint64 unix_utc);

void sdtp_commitment_calculate_hash(SDTP_Commitment * s);

int sdtp_commitment_serialize(SDTP_Commitment * s, GByteArray * commit, GByteArray * reveal);

int sdtp_commitment_deserialize(SDTP_Commitment * s, guchar * data, gsize len);

sdtp_commitment_status sdtp_commitment_check(SDTP_Commitment * s);

sdtp_commitment_phase sdtp_commitment_data_get_phase (guchar * data, gsize len);

#endif
