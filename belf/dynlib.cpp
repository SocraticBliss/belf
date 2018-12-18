#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

#include "TinyXML/tinyxml.h"

#include "dynlib.h"
#include "utils.h"

DynLib::DynLib(const char *xml)
{
	load_xml(xml);
}

void DynLib::load_xml(const char *db)
{
	TiXmlDocument xml;

	if (!xml.LoadFile(db))
		loader_failure("Failed to load database file (%s).", db);

	TiXmlElement *DynlibDatabase = xml.FirstChildElement();

	if (!DynlibDatabase || strcmp(DynlibDatabase->Value(), "DynlibDatabase"))
		loader_failure("Database requires the \"DynlibDatabase\" header.");

	TiXmlElement *e = DynlibDatabase->FirstChildElement();

	if (!e)
		loader_failure("Database has no entries in the \"DynlibDatabase\" header.");

	do {
		const char *obf = e->Attribute("obf");
		
		if (!obf)
			loader_failure("Entry needs to have an \"obf\" attribute.");
		
		const char *lib = e->Attribute("lib");
		
		if (!lib)
			loader_failure("Entry needs to have an \"lib\" attribute.");
		
		const char *sym = e->Attribute("sym");
		
		if (!sym)
			loader_failure("Entry needs to have an \"sym\" attribute.");

		dynlib_entry entry;
		entry.obf.sprnt(obf);
		entry.lib.sprnt(lib);
		entry.sym.sprnt(sym);
		entries.push_back(entry);
	} while (e = e->NextSiblingElement());
}

bool DynLib::is_obfuscated(const char *sym)
{
	const char *p;

	if (strlen(sym) >= 13)
		if ((p = strchr(sym, '#')) != NULL) // contains first #
			if ((p - sym) == 11) // obfuscated symbol is 11 chars
				if ((p = strchr(p + 1, '#')) != NULL) // contains second #
					return true;

	return false;
}

unsigned int DynLib::lookup(const char *obf)
{
	int module_id;
	const char *library_id;
	
	library_id = strchr(obf, '#');

	if (library_id == NULL)
	{
		msg("No Library ID in this symbol!\n");
		return -1;
	}

	library_id = strchr(library_id + 1, '#');

	if (library_id == NULL)
	{
		msg("No Module ID in this symbol!\n");
		return -1;
	}

	if (decode_base64(library_id + 1, &module_id))
	{
		msg("Invalid Module ID!\n");
		return -1;
	}

	if (module_map.find(module_id) != module_map.end())
		return module_map.at(module_id);

	return -1;
}

qstring DynLib::deobfuscate(qstring obf)
{
	for (const dynlib_entry& entry : entries)
	{
		if (obf.substr(0, 11) == entry.obf)
			return entry.sym;
	}

	return "";
}
