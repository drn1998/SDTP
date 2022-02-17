#define g_byte_array_empty(array); g_byte_array_remove_range(array,0,array->len);
#define g_byte_array_assign(array,data,length) {\
        g_byte_array_empty(array);\
        g_byte_array_append(array,data,length);\
    };
