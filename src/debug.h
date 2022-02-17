#ifndef DEBUG_H
#define DEBUG_H

void debug_print_gbyte_array(GByteArray * to_print, char * identifier) {
    register unsigned int i;
    static unsigned int j = 0;
    GString * filename_with_number;

    filename_with_number = g_string_new(identifier);
    g_string_prepend(filename_with_number, "GBYTES_");
    g_string_append_printf(filename_with_number, "_%u", j);

    FILE * f;

    f = fopen(filename_with_number->str, "w");

    for (i = 0; i < to_print->len; i++) {
        fputc(to_print->data[i], f);
    }

    fclose(f);
    g_string_prepend(filename_with_number, "hexdump ");
    g_string_append(filename_with_number, " -C");
    printf("%s (%i bytes):\n\n", identifier, to_print->len);
    fflush(NULL);
    system(filename_with_number->str);
    g_string_free(filename_with_number, TRUE);
    j++;

    return;
}

void debug_print_mem(guchar * dat, size_t len, char * identifier) {
    register unsigned int i;
    static unsigned int j = 0;
    GString * filename_with_number;

    filename_with_number = g_string_new(identifier);
    g_string_prepend(filename_with_number, "RAWMEM_");
    g_string_append_printf(filename_with_number, "_%u", j);

    FILE * f;

    f = fopen(filename_with_number->str, "w");

    for (i = 0; i < len; i++) {
        fputc(dat[i], f);
    }

    fclose(f);
    g_string_prepend(filename_with_number, "hexdump ");
    g_string_append(filename_with_number, " -C");
    puts(identifier);
    system(filename_with_number->str);
    g_string_free(filename_with_number, TRUE);
    j++;

    return;
}

#endif
