
#ifndef BELF_LOADER_CPP
#define BELF_LOADER_CPP

#include <vector>

#include <auto.hpp>
#include <entry.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <typeinf.hpp>

#include "dynlib.h"
#include "elfr_sce.h"
#include "utils.h"

idaman void ida_export add_test_feature(const char *feature);

static bool accept_handler(const reader_t &reader, reader_t::errcode_t code, ...)
{
	return true;
}

static bool load_handler(const reader_t &reader, reader_t::errcode_t code, ...)
{
	return true;
}

static bool is_ps4_elf(reader_t &reader)
{
	switch (reader.get_header().e_type) {
	case ET_SCE_EXEC:
	case ET_SCE_DYNEXEC:
	case ET_SCE_RELEXEC:
	case ET_SCE_STUBLIB:
	case ET_SCE_DYNAMIC:
		return true;
	}

	return false;
}

uint16 load_elf(reader_t *reader)
{
	reader->set_handler(load_handler);

	if (!reader->read_ident() || !reader->read_header())
		loader_failure("Failed reading ELF header!");

	if (reader->is_msb())
		inf.lflags |= LFLG_MSF;
	else
		inf.lflags &= ~LFLG_MSF;

	while (true)
	{
		inf.lflags |= LFLG_PC_FLAT;

		if (reader->get_header().e_machine == EM_PPC64
			|| reader->get_header().e_machine == EM_IA64
			|| reader->get_header().e_machine == EM_X86_64
			|| reader->get_header().e_machine == EM_AARCH64
			|| reader->get_header().e_machine == EM_ALPHA)
		{
			inf.lflags |= LFLG_PC_FLAT | LFLG_64BIT;
			inf.cc.cm &= ~2u;
			inf.cc.cm |= 1u;
		}

		const char *procname = "metapc";
		proc_def_t *pd = nullptr;
		int ret = ph.notify(processor_t::ev_loader_elf_machine,
							reader->get_linput(),
							reader->get_header().e_machine,
							&procname, &pd);
		
		if (!ret || ret == reader->get_header().e_machine)
			break;

		reader->get_header().e_machine = ret;
	}

	set_processor_type("metapc", SETPROC_LOADER);

	if (reader->is_msb())
		inf.lflags |= LFLG_MSF;
	else
		inf.lflags &= ~LFLG_MSF;

	if (reader->is_64())
	{
		inf.lflags |= LFLG_PC_FLAT | LFLG_64BIT;
		inf.cc.cm &= ~2u;
		inf.cc.cm |= 1u;
	}

	// TODO: Add PS4 support?

	if (reader->get_header().e_type == ET_DYN)
		inf.lflags |= LFLG_IS_DLL;

	return reader->get_header().e_machine;
}

bool __fastcall elf_set_compiler(__int16 machine, char flags, char osabi)
{
	const char *abiname = "";

	switch (machine) {
	case EM_PPC64:
	{
		if (osabi == ELFOSABI_CELLOSLV2)
		{
			abiname = "celloslv2";
			break;
		}

		if ((flags & 3) == 2)
		{
			abiname = "elfv2";
			add_test_feature("elfv2");
			break;
		}

		return false;
	}
	case EM_PPC: abiname = "sysv"; break;
	case EM_ARM:
	case EM_AARCH64: abiname = "eabi"; break;
	case EM_X86_64:
		if (osabi == ELFOSABI_NACL)
		{
			abiname = "nacl";
			false;
		}

		return false;
	}

	compiler_info_t cc;
	cc.id = 0;

	return set_compiler(cc, 4i64, abiname);
}

void createSegment(const char *name, uint32 flags, uchar bitness, uchar type, ea_t start, ea_t end)
{
	static sel_t g_sel = 0;
	segment_t s;
	memset(&s, 0, sizeof(segment_t));
	s.color = -1;
	s.align = 1;
	s.comb = scPub;
	s.perm = 0;

	if (flags & PF_R)
		s.perm |= SEGPERM_READ;
	if (flags & PF_W)
		s.perm |= SEGPERM_WRITE;
	if (flags & PF_X)
		s.perm |= SEGPERM_EXEC;

	s.bitness = bitness;
	s.sel = g_sel++;
	s.type = type;
	s.start_ea = start;
	s.end_ea = end;

	if (!add_segm_ex(&s, name, 0, ADDSEG_SPARSE))
		loader_failure("Could not create segment '%s' at %a..%a", name, s.start_ea, s.end_ea, s.start_ea);
}

void load_jmprel(reader_t &reader, elf_phdr_t &dyndata, dynamic_info_t::entry_t &jmprel_entry, elf_sym_t *&symtab, char *&strtab, DynLib &dynlib)
{
	elf_rela_t *jmprel = new elf_rela_t[jmprel_entry.size / sizeof(elf_rela_t)];
	
	reader.seek(dyndata.p_offset + jmprel_entry.addr);
	
	if (reader.safe_read(jmprel, jmprel_entry.size, false) != 0)
		loader_failure("Failed reading jmprel!");

	msg("dyninfo.symtab().size: 0x%llx\n", jmprel_entry.size);
	msg("sizeof(elf_rela_t):    0x%llx\n", sizeof(elf_rela_t));

	for (size_t i = 0; i < (jmprel_entry.size / sizeof(elf_rela_t)); i++)
	{
		int type = reader.rel_info_type(jmprel[i]);
		int idx = reader.rel_info_index(jmprel[i]);

		if (type != R_X86_64_JUMP_SLOT)
		{
			msg("Unexpected reloc type %i for jump slot %i\n", type, i);
			continue;
		}

		if (idx >= (jmprel_entry.size / sizeof(elf_sym_t)))
		{
			msg("Invalid symbol index %i for relocation %i\n", idx, i);
			continue;
		}

		if (symtab[idx].st_name >= jmprel_entry.size)
		{
			msg("Invalid symbol string offset %x of symbol %i for relocation %i\n", symtab[idx].st_name, idx, i);
			continue;
		}

		qstring name = &strtab[symtab[idx].st_name];
		const char* module_name = "";

		if (dynlib.isObfuscated(name.c_str()))
		{
			uint32 modidx = dynlib.lookup(name.c_str());
			if (modidx != -1)
				module_name = &strtab[modidx];

			qstring deobf_name = dynlib.deobfuscate(module_name, name);
			if (deobf_name != "")
				name = deobf_name;
		}

		qstring import_name;
		import_name.sprnt(FUNC_IMPORT_PREFIX "%s", name.c_str());
		force_name(jmprel[i].r_offset, import_name.c_str());

		netnode import_node;
		netnode_check(&import_node, module_name, 0, true); //"$ IDALDR node for ids loading $"
		netnode_supset(import_node, jmprel[i].r_offset, name.c_str(), 0, 339);
		import_module(module_name, 0, import_node, 0, "linux");
	}
	delete[] jmprel;
}

void load_symtab(dynamic_info_t::entry_t &symtab_entry, elf_sym_t *&symtab, char *&strtab, DynLib &dynlib)
{
	for (int i = 0; i < symtab_entry.size / sizeof(elf_sym_t); i++)
	{
		if (symtab[i].st_value == 0)
			continue;

		qstring name = &strtab[symtab[i].st_name];
		const char* module_name = "";

		if (dynlib.isObfuscated(name.c_str()))
		{
			uint32 modidx = dynlib.lookup(name.c_str());
			
			if (modidx != -1)
				module_name = &strtab[modidx];

			qstring deobf_name = dynlib.deobfuscate(module_name, name);
			
			if (deobf_name != "")
				name = deobf_name;
		}

		if (ELF_ST_TYPE(symtab[i].st_info) == STT_FUNC || ELF_ST_TYPE(symtab[i].st_info) == STT_GNU_IFUNC)
		{
			add_entry(symtab[i].st_value, symtab[i].st_value, name.c_str(), true);
		}
		else
		{
			force_name(symtab[i].st_value, name.c_str());
		}
	}
}

void load_rela(reader_t &reader, elf_phdr_t &dyndata, dynamic_info_t::entry_t &rela_entry)
{
	elf_rela_t *rela = new elf_rela_t[rela_entry.size / sizeof(elf_rela_t)];
	reader.seek(dyndata.p_offset + rela_entry.addr);
	
	if (reader.safe_read(rela, rela_entry.size, false) != 0)
		loader_failure("Failed reading rela!");

	for (int i = 0; i < (rela_entry.size / sizeof(elf_sym_t)); i++)
	{
		int type = reader.rel_info_type(rela[i]);
		int idx = reader.rel_info_index(rela[i]);

		if (type != R_X86_64_RELATIVE) {
			msg("Unexpected reloc type %i for rela %i at offset 0x%x\n", type, i, rela[i].r_offset);
			continue;
		}

		put_qword(rela[i].r_offset, rela[i].r_addend);
	}

	delete[] rela;
}


// IDA
int idaapi elf_accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename)
{
	reader_t reader(li);
	reader.set_handler(accept_handler);

	if (reader.read_ident() && reader.read_header() && reader.get_header().e_machine == EM_X86_64 && is_ps4_elf(reader))
	{
		fileformatname->sprnt("Balika011's ELF%s for %s (%s)",
			reader.is_64() ? "64" : "",
			reader.machine_name_str(),
			reader.file_type_str());
		processor->sprnt("metapc");

		return 1;
	}

	return 0;
}

void idaapi elf_load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
#ifdef _DEBUG
	debug = IDA_DEBUG_ALWAYS;
#endif
	char db[QMAXPATH];
	
	msg("\nLoading dynlib.xml database file...");
	if (getsysfile(db, QMAXPATH, "dynlib.xml", LDR_SUBDIR) == NULL)
		loader_failure("Could not find dynlib.xml database file!");
	msg("OK\n");
	
	DynLib dynlib(db);
	reader_t reader(li);
	uint16 machine = load_elf(&reader);

	elf_set_compiler(machine, reader.get_header().e_flags, reader.get_header().e_ident.osabi);
	inf.baseaddr = 0;
	inf.specsegs = reader.is_64() ? 8 : 4;

	msg("\n[BELF] Reading Program Headers...\n");
	if (reader.get_header().e_phoff)
		add_test_feature("pht");
	else
		loader_failure("Missing program headers!");

	if (reader.get_header().e_shoff)
		add_test_feature("sht");
	
	if (!reader.read_program_headers())
		loader_failure("Failed reading program headers!");

	set_imagebase(reader.pheaders.get_image_base());
	elf_phdr_t dyndata;

	for (int i = 0; i < reader.pheaders.size(); i++)
	{
		elf_phdr_t *phdr = reader.pheaders.get(i);
		const char *name = phdr->p_flags & PF_X ? "CODE" : "DATA";
		uchar type = phdr->p_flags & PF_X ? SEG_CODE : SEG_DATA;
		
		switch (phdr->p_type) {
		case PT_LOAD:
			createSegment(name, phdr->p_flags, reader.get_seg_bitness(), type, phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz);
			file2base(li, phdr->p_offset, phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz, FILEREG_PATCHABLE);
			break;
		case PT_SCE_RELRO:
			createSegment(".relro", phdr->p_flags, reader.get_seg_bitness(), SEG_XTRN, phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz);
			file2base(li, phdr->p_offset, phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz, FILEREG_PATCHABLE);
			break;
		case PT_GNU_EH_FRAME:
			createSegment(".eh_frame", phdr->p_flags, reader.get_seg_bitness(), SEG_DATA, phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz);
			file2base(li, phdr->p_offset, phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz, FILEREG_PATCHABLE);
			break;
		case PT_SCE_DYNLIBDATA:
			dyndata = *phdr;
			break;		
		}

		msg("%d %s:\n", i, ph_type_to_string(phdr->p_type).c_str());
		msg("  p_flags:  0x%llx \t %s\n", phdr->p_flags, flags_to_string(phdr->p_flags).c_str());
		msg("  p_offset: 0x%llx\n", phdr->p_offset);
		msg("  p_vaddr:  0x%llx\n", phdr->p_vaddr);
		msg("  p_paddr:  0x%llx\n", phdr->p_paddr);
		msg("  p_filesz: 0x%llx\n", phdr->p_filesz);
		msg("  p_memsz:  0x%llx\n", phdr->p_memsz);
		msg("  p_align:  0x%llx\n", phdr->p_align);
	}

	inf.start_ip = get_imagebase() + reader.get_header().e_entry;
	inf.start_cs = getseg(inf.start_ip)->sel;
	msg("\nEntry Address: 0x%llx \n", reader.get_header().e_entry);

	msg("\n[BELF] Reading Dynamic Tags...\n");
	reader_t::dyninfo_tags_t dyninfo_tags;
	dynamic_info_t dyninfo;
	
	if (!reader.read_dynamic_info_tags(&dyninfo_tags, reader.pheaders.get_dynamic_linking_tables_info()) ||
		!reader.parse_dynamic_info(&dyninfo, dyninfo_tags))
		loader_failure("Failed reading dyninfo!");

	if (dyninfo.strtab().addr + dyninfo.strtab().size > dyndata.p_filesz)
		loader_failure("strtab is out of dyndata!");

	char *strtab = new char[dyninfo.strtab().size];
	reader.seek(dyndata.p_offset + dyninfo.strtab().addr);
	
	if (reader.safe_read(strtab, dyninfo.strtab().size, false) != 0)
		loader_failure("Failed reading strtab!");

	elf_sym_t *symtab = new elf_sym_t[dyninfo.symtab().size / sizeof(elf_sym_t)];
	reader.seek(dyndata.p_offset + dyninfo.symtab().addr);
	
	if (reader.safe_read(symtab, dyninfo.symtab().size, false) != 0)
		loader_failure("Failed reading symtab!");

	for (elf_dyn_t *dyn = dyninfo_tags.begin(); dyn != dyninfo_tags.end(); ++dyn)
	{
		uint64 data = dyn->d_un;
		uint64 tag = dyn->d_tag;
		uint32 id = data >> 48;
		uint32 nameidx = data & 0xFFFFFFFF;
		uint32 attridx = data & 0xF;

		switch (tag) {
		case DT_SCE_HASH:
		case DT_SCE_STRTAB:
		case DT_SCE_SYMTAB:
		case DT_SCE_PLTGOT:
		case DT_SCE_JMPREL:
		case DT_SCE_RELA:
		case DT_INIT_ARRAY:
		case DT_FINI_ARRAY:
		case DT_PREINIT_ARRAY:
		case DT_SCE_FINGERPRINT:
			msg("%s \t 0x%08llx\n", dyntag_to_string(tag).c_str(), data);
			break;
		case DT_SCE_HASHSZ:
		case DT_SCE_STRSZ:
		case DT_SCE_SYMTABSZ:
		case DT_SCE_PLTRELSZ:
		case DT_SCE_RELASZ:
		case DT_SCE_RELAENT:
		case DT_INIT_ARRAYSZ:
		case DT_FINI_ARRAYSZ:
		case DT_PREINIT_ARRAYSZ:
		case DT_SCE_SYMENT:
			msg("%s \t %d\n", dyntag_to_string(tag).c_str(), data);
			break;
		case DT_INIT:
			msg("DT_INIT \t\t 0x%08llx\n", data);
			add_entry(reader.get_load_bias() + data,
				reader.get_load_bias() + data,
				".init_proc", true);
			break;
		case DT_FINI:
			msg("DT_FINI \t\t 0x%08llx\n", data);
			add_entry(reader.get_load_bias() + data,
				reader.get_load_bias() + data,
				".term_proc", true);
			break;
		case DT_SCE_PLTREL: 
			msg("DT_SCE_PLTREL \t %d \t       %s\n", 
				data, dyntag_to_string(data).c_str());
			break;
		case DT_DEBUG:
		case DT_FLAGS:
			msg("%s \t\t 0x%08llx\n", dyntag_to_string(tag).c_str(), data);
			break;
		case DT_SONAME:
		case DT_NEEDED:
			msg("%s \t\t 0x%08llx       %s\n",
				dyntag_to_string(tag).c_str(), data, &strtab[nameidx]);
			break;
		case DT_SCE_NEEDED_MODULE:
		case DT_SCE_MODULE_INFO:
			msg("%s \t 0x%013llx  MID:%x  Name:%s\n",
				dyntag_to_string(tag).c_str(), data, id, &strtab[nameidx]);
			dynlib.addModule(id, nameidx);
			break;
		case DT_SCE_IMPORT_LIB:
		case DT_SCE_EXPORT_LIB:
			msg("%s \t 0x%013llx  LID:%x  Name:%s\n",
				dyntag_to_string(tag).c_str(), data, id, &strtab[nameidx]);
			break;
		case DT_SCE_IMPORT_LIB_ATTR:
		case DT_SCE_EXPORT_LIB_ATTR:
			msg("%s  0x%013llx  LID:%x  Attribute:%s\n",
				dyntag_to_string(tag).c_str(), data, id, attributes_to_string(attridx).c_str());
			break;		
		case DT_SCE_ORIGINAL_FILENAME:
			msg("%s 0x%08llx      %s\n", 
				dyntag_to_string(tag).c_str(), data, &strtab[nameidx]);
			break;
		case DT_SCE_MODULE_ATTR:
			msg("%s \t 0x%08llx       %s\n",
				dyntag_to_string(tag).c_str(), data, attributes_to_string(attridx).c_str());
			break;
		case DT_NULL: msg("DT_NULL \t\t -\n");
			break;
		}
	}

	msg("\n[BELF] Loading jmprel...\n");
	load_jmprel(reader, dyndata, dyninfo.jmprel(), symtab, strtab, dynlib);

	msg("\n[BELF] Loading symtab...\n");
	load_symtab(dyninfo.symtab(), symtab, strtab, dynlib);

	msg("\n[BELF] Loading rela...\n");
	load_rela(reader, dyndata, dyninfo.rela());

	delete[] symtab;
	delete[] strtab;
	msg("\n[BELF] Done!\n");

#ifdef _DEBUG
	debug = 0;
#endif
}

int idaapi elf_save_file(FILE *fp, const char *fileformatname)
{
	return 0;
}

extern "C" __declspec(dllexport) loader_t LDSC =
{
	IDP_INTERFACE_VERSION,
	0,
	elf_accept_file,
	elf_load_file,
	elf_save_file,
	nullptr,
	nullptr
};

#endif // BELF_LOADER_CPP
