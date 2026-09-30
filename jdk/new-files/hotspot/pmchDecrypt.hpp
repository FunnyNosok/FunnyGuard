#ifndef SHARE_CLASSFILE_PMCHDECRYPT_HPP
#define SHARE_CLASSFILE_PMCHDECRYPT_HPP

extern "C" bool pmch_try_decrypt(const char* class_name,
                                 const unsigned char* in, int in_len,
                                 unsigned char** out, int* out_len);

extern "C" void pmch_free(unsigned char* p);

#endif
