#ifndef __UTILS_H__
#define __UTILS_H__

#include <pro.h>
qstring ph_type_to_string(uint32 ph_type);
qstring dyntag_to_string(uint64 dyntag);
qstring attributes_to_string(uint32 attributes);
qstring flags_to_string(uint32 flags);
int decode_base64(const char *str, int *a2);

#endif
