#ifndef __UTILS_H__
#define __UTILS_H__

#include <pro.h>

qstring d_tag_to_string(uint32 d_tag);
qstring p_flags_to_string(uint32 p_flags);
qstring p_type_to_string(uint32 p_type);

qstring port_attributes_to_string(uint32 attributes);
qstring module_attributes_to_string(uint32 attributes);
int decode_base64(const char *str, int *a2);

#endif
