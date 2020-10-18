#include "src/hcommit.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"

int main(int argc, char* argv[]) {
    commitment_s * create_test;
    commitment_s * verify_test;

    GString * test_subject;
    GString * test_message;

    GByteArray * temporary_data;

    unsigned int success = 0;
    unsigned int failure = 0;

    int return_value = 0;

    // Commitment Preperation

    SDTP_commitment_create(&create_test);
    SDTP_commitment_prepare(create_test);

    SDTP_commitment_create(&verify_test);
    SDTP_commitment_prepare(verify_test);

    temporary_data = g_byte_array_new();

    test_subject = g_string_new("");
    test_message = g_string_new("");

    {   // Test assign empty string
        return_value = SDTP_commitment_message_set(create_test, test_message);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " Assigning empty string as message for commitment object.");
            success++;
        } else if (return_value == -1) {
            printf(KRED "FAILURE:" KNRM " Assinging empty string as message for commitment object has returned %i.", return_value);
            failure++;
        }
    }

    {   // Test assign ok string
        g_string_assign(test_message, "This is an ordinary test with a text message whichs length in bytes is below 1024. 👍");
        return_value = SDTP_commitment_message_set(create_test, test_message);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " Assigning ordinary string as message for commitment object.");
            success++;
        } else if (return_value == -1) {
            printf(KRED "FAILURE:" KNRM " Assinging ordinary string as message for commitment object has returned %i.\n", return_value);
            failure++;
        }
    }

    {   // Test assigned string equals retrieved one
        return_value = strcmp(test_message->str, create_test->commitment_message->str);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " String retrieved from commitment object equals given one.");
            success++;
        } else if (return_value == -1) {
            printf(KRED "FAILURE:" KNRM " When comparing retrieved and given string, strcmp has returned %i.\n", return_value);
            failure++;
        }
    }

    {   // Test assign too long string fails
        g_string_assign(test_message, "This is a text that is supposed to be too long for the function to work. Therefore, this "
        "test is SUPPOSED to fail because a limit on 1024 has been set intentionally. I will now add some emojis that aren't really "
        "neccessary but will inflate the size of the string more than normal US ASCII bytes. 👑🌼🐍 OK, as this is still not enough, "
        "let me quote something from Wikipedia, the free encyclopedia, about CD-RWs. It's in german, so we get some multibyte characters "
        "like Ä Ü Ö for free. Afterwards, I hope I've finally gotten to the limit of 1024 bytes. 💿 CD-RW ist eine wiederbeschreibbare "
        "Compact Disc; die Abkürzung steht für den englischen Ausdruck Compact Disc ReWritable.\n\nDie ersten CD-RW kamen 1997 auf den "
        "Markt – von Philips, Sony, Hewlett-Packard, Mitsubishi Chemical und Ricoh – und konnten nur 650 MB speichern. Ab 1998 ist auch "
        "eine größere Speicherkapazität von 700 MB möglich. Aufgrund vieler Einschränkungen, wie etwa Geschwindigkeit, Datensicherheit "
        "und Speicherkapazität ist CD-RW eine Nischenanwendung geblieben."); // 1055 bytes
        return_value = SDTP_commitment_message_set(create_test, test_message);

        if(return_value == -1) {
            puts(KGRN "SUCCESS:" KNRM " A string with more than 1024 bytes was rejected as the message for a commitment.");
            success++;
        } else if (return_value == 0) {
            puts(KRED "FAILURE:" KNRM " A string with more than 1024 bytes was wrongfully accepted as a commitments message.");
            failure++;
        }
    }

    {   // Test assign empty string
        return_value = SDTP_commitment_subject_set(create_test, test_subject);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " Assigning empty string as subject for commitment object.");
            success++;
        } else if (return_value == -1) {
            printf(KRED "FAILURE:" KNRM " Assinging empty string as subject for commitment object has returned %i.", return_value);
            failure++;
        }
    }

    {   // Test assign ok string
        g_string_assign(test_message, "Ordinary subject whichs length is below 64 bytes. 👍");
        return_value = SDTP_commitment_subject_set(create_test, test_subject);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " Assigning ordinary string as subject for commitment object.");
            success++;
        } else if (return_value == -1) {
            printf(KRED "FAILURE:" KNRM " Assinging ordinary string as subject for commitment object has returned %i.\n", return_value);
            failure++;
        }
    }

    {   // Test assigned string equals retrieved one
        return_value = strcmp(test_subject->str, create_test->commitment_subject->str);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " String retrieved from commitment object equals given one.");
            success++;
        } else if (return_value == -1) {
            printf(KRED "FAILURE:" KNRM " When comparing retrieved and given string, strcmp has returned %i.\n", return_value);
            failure++;
        }
    }

    {   // Test assign too long string fails
        g_string_assign(test_subject, "This subject intentionally has more than 64 bytes, so this is supposed to fail."); // 80 bytes
        return_value = SDTP_commitment_subject_set(create_test, test_subject);

        if(return_value == -1) {
            puts(KGRN "SUCCESS:" KNRM " A string with more than 64 bytes was rejected as the subject for a commitment.");
            success++;
        } else if (return_value == 0) {
            puts(KRED "FAILURE:" KNRM " A string with more than 64 bytes was wrongfully accepted as a commitments subject.");
            failure++;
        }
    }

    // FIXME: Test isn't run at all. Check why!
    {   // Test if previous string remained after failed change
        return_value = strcmp(test_subject->str, create_test->commitment_subject->str);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " String retrieved from commitment object equals given one.");
            success++;
        } else if (return_value == -1) {
            printf(KRED "FAILURE:" KNRM " When comparing retrieved and given string, strcmp has returned %i.\n", return_value);
            failure++;
        }
    }

    {   // Access to /dev/urandom possible?
        return_value = SDTP_commitment_entropy_set(create_test);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " Obtained entropy from /dev/urandom.");
            success++;
        } else if (return_value == -1) {
            puts(KRED "FAILURE:" KNRM " Unable to retrieve random entropy from /dev/urandom");
            failure++;
        }
    }

    {   // Length of entropy correct?
        if(create_test->commitment_entropy->len == DEF_ENTROPY_LENGTH) {
            printf(KGRN "SUCCESS:" KNRM " Entropy has intended length of %i byte(s).\n", DEF_ENTROPY_LENGTH);
            success++;
        } else {
            printf(KRED "FAILURE:" KNRM " Entropy length is %i byte(s).\n", create_test->commitment_entropy->len);
            failure++;
        }
    }

    // TODO: More testing about scheduled once implemented fully (and with optionality)
    SDTP_commitment_schedule_set(create_test, "2022-05-05 19:00:00");

    {   // NOT A TEST: Printing entropy data
        debug_print_mem(create_test->commitment_entropy->data, DEF_ENTROPY_LENGTH, "Entropy data");
    }

    {   // NOT A TEST: Commitment calculation
        SDTP_commitment_hashval_calculate(create_test);
    }

    {   // NOT A TEST: Printing hashval data
        debug_print_mem(create_test->commitment_hashval->data, SHA256_HASH_LENGTH, "Hash data");
    }

    {   // Hash verification of valid commitment
        return_value = SDTP_commitment_validity_check(create_test);

        if(return_value == 0) {
            puts(KGRN "SUCCESS:" KNRM " Consistent and correct commitment object was validated.");
            success++;
        } else if (return_value == -1) {
            puts(KRED "FAILURE:" KNRM " Consistent and correct commitment object considered bad.");
            failure++;
        }
    }

    {   // Hash verification of invalid commitment
        g_string_assign(test_message, "This is another test message.");
        SDTP_commitment_message_set(create_test, test_message);
        return_value = SDTP_commitment_validity_check(create_test);

        if(return_value != 0) {
            puts(KGRN "SUCCESS:" KNRM " Incorrect commitment object was not wrongfully validated.");
            success++;
        } else if (return_value == 0) {
            puts(KRED "FAILURE:" KNRM " Incorrect commitment object was considered valid.");
            failure++;
        }
    }

    {   // NOT A TEST: Commitment calculation to make it correct again
        SDTP_commitment_hashval_calculate(create_test);
    }

    {   // NOT A TEST: Get header and print it
        SDTP_commitment_header_get(create_test, temporary_data, OPERATION_MODE_COMMIT);
        debug_print_mem(temporary_data->data, temporary_data->len, "Header (commit)");
    }

    {   // Is header length 3 bytes?
        if(temporary_data->len == 3) {
            puts(KGRN "SUCCESS:" KNRM " Header length in commit mode equals 3.");
            success++;
        } else {
            puts(KRED "FAILURE:" KNRM " Header length in commit mode unequals 3.");
            failure++;
        }
    }

    g_byte_array_empty(temporary_data);

    {   // NOT A TEST: Get header and print it
        SDTP_commitment_header_get(create_test, temporary_data, OPERATION_MODE_REVEAL);
        debug_print_mem(temporary_data->data, temporary_data->len, "Header (reveal)");
    }

    {   // Is header length 3 bytes?
        if(temporary_data->len == 3) {
            puts(KGRN "SUCCESS:" KNRM " Header length in reveal mode equals 3.");
            success++;
        } else {
            puts(KRED "FAILURE:" KNRM " Header length in reveal mode unequals 3.");
            failure++;
        }
    }

    g_byte_array_empty(temporary_data);

    {   // NOT A TEST: Get body and print it
        SDTP_commitment_body_get(create_test, temporary_data, OPERATION_MODE_COMMIT);
        debug_print_mem(temporary_data->data, temporary_data->len, "Body (commit)");
        g_byte_array_empty(temporary_data);
    }

    {   // NOT A TEST: Get body and print it
        SDTP_commitment_body_get(create_test, temporary_data, OPERATION_MODE_REVEAL);
        debug_print_mem(temporary_data->data, temporary_data->len, "Body (reveal)");
        g_byte_array_empty(temporary_data);
    }

    g_byte_array_free(temporary_data, TRUE);

    g_string_free(test_message, TRUE);
    g_string_free(test_subject, TRUE);

    SDTP_commitment_clear(create_test);
    SDTP_commitment_delete(&create_test);

    SDTP_commitment_clear(verify_test);
    SDTP_commitment_delete(&verify_test);

    printf("\nSUMMARY: %i succeded, %i failed.\n", success, failure);
}