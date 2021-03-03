#include "hcommit.h"
#include "debug.h"

/* ISSUES:
 * revelation_time is set by head_setby, which affects its memory management (two vars?, more elegant solution)
 * Otherwise, body/header serialization and deserialization is almost done
 * One issue might be to reset entropy after full generation, but have hash and reveal-data match
 * 85% ready is a reasonable estimate i'd say
 */

int main(int argc, char* argv[]) {
	SDTP_commitment * commitment, * commitment_two;
	GByteArray * bytes, * head;

	SDTP_commitment_operation_mode mode;
	gboolean is_human;

	bytes = g_byte_array_new();
	head = g_byte_array_new();

	SDTP_commitment_create(&commitment);
	SDTP_commitment_create(&commitment_two);

	SDTP_commitment_payload_set(commitment, "Binary example payload", 22);
	SDTP_commitment_subject_set(commitment, "Example");
	//SDTP_commitment_message_set(commitment, "This is an example commitment.");
	SDTP_commitment_revelation_set(commitment, 1769371683);
	SDTP_commitment_revelation_set(commitment_two, 4884938933);

	__internal_SDTP_commitment_body_get(commitment, bytes, COMMITMENT_OPERATION_MODE_REVEAL);
	debug_print_gbyte_array(bytes, "body:");
	mode = COMMITMENT_OPERATION_MODE_REVEAL;
	commitment_two->datamode = COMMITMENT_DATA_MODE_BINARY;
	commitment_two->_is_himem = FALSE;
	__internal_SDTP_commitment_body_setby(commitment_two, bytes, mode);

	debug_print_mem(commitment_two->payload->data, commitment_two->payload->len, "dat:");

	SDTP_commitment_delete(&commitment);
	SDTP_commitment_delete(&commitment_two);

	g_byte_array_free(bytes, TRUE);
	g_byte_array_free(head, TRUE);

	return 0;
}
