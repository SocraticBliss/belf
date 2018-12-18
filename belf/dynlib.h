#pragma once

#include <pro.h>
#include <unordered_map>

class DynLib
{
public:
	DynLib(const char *xml);
	
	void load_xml(const char *);
	void add_module(uint32 id, uint32 name_idx) { module_map[id] = name_idx; }

	bool is_obfuscated(const char *sym);
	unsigned int lookup(const char *obf);
	qstring deobfuscate(qstring obf);

private:
	struct dynlib_entry
	{
		qstring obf;
		qstring lib;
		qstring sym;
	};
	std::vector<dynlib_entry> entries;

	std::unordered_map<uint32, uint32> module_map;
};
