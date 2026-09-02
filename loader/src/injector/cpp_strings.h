#ifndef CPP_STRINGS_H
#define CPP_STRINGS_H

/* INFO: Read a C string pointer from a std::string object.
           The returned pointer is valid only as long as the std::string exists. */
const char *read_std_string(const void *std_string_ptr);

#endif /* CPP_STRINGS_H */
