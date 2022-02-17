#ifndef HCOMMIT_FRAME_H
#define HCOMMIT_FRAME_H

#include <glib.h>

#define ENTROPY_SIZE 12

typedef struct {
    GDateTime * revelation;
    guchar entropy[ENTROPY_SIZE];
    gboolean entropy_set;
    GByteArray * data;
} sdtp_commitment_frame;

sdtp_commitment_frame * sdtp_commitment_frame_new();

void sdtp_commitment_frame_free(sdtp_commitment_frame * s);

void sdtp_commitment_frame_set_data(sdtp_commitment_frame * s, guchar * data, gsize len);

void sdtp_commitment_frame_set_revelation(sdtp_commitment_frame * s, guint64 unix_revelation);

int sdtp_commitment_frame_serialize(sdtp_commitment_frame * s, GByteArray * out);

int sdtp_commitment_frame_deserialize(sdtp_commitment_frame * s, guchar * in, gsize len);

#endif