#include <vector>

#include <auto.hpp>
#include <entry.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <struct.hpp>
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
	case ET_EXEC: // PS4Kernel
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

bool __fastcall elf_set_compiler(uint16 machine, char flags, char osabi)
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


// Creating Segment
void create_segment(const char *name, uint32 flags, uchar bitness, uchar type, ea_t start, ea_t end)
{
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

	static sel_t g_sel = 0;
	s.sel = g_sel++;

	s.bitness = bitness;
	s.type = type;
	s.start_ea = start;
	s.end_ea = end;

	if (!add_segm_ex(&s, name, 0, ADDSEG_SPARSE))
		loader_failure("Could not create segment '%s' at %a..%a", name, s.start_ea, s.end_ea, s.start_ea);
}


// Loading Sections
void load_relaplt(reader_t &reader, elf_phdr_t &dyndata, dynamic_info_t::entry_t &jmprel_entry, elf_sym_t *&symtab, char *&strtab, DynLib &dynlib)
{
	elf_rela_t *jmprel = new elf_rela_t[jmprel_entry.size / sizeof(elf_rela_t)];

	reader.seek(dyndata.p_offset + jmprel_entry.addr);

	if (reader.safe_read(jmprel, jmprel_entry.size, false) != 0)
		loader_failure("Failed reading .rela.plt section!");

	// Elf64_Rela Structure
	uint64 struc_size = sizeof(elf_rela_t);

	struc_t *sptr_rela = get_struc(add_struc(BADADDR, "Elf64_Rela", 0));
	add_struc_member(sptr_rela, "r_offset", 0x0, qword_flag(), NULL, 0x8);
	add_struc_member(sptr_rela, "r_info", 0x8, qword_flag(), NULL, 0x8);
	add_struc_member(sptr_rela, "r_addend", 0x10, qword_flag(), NULL, 0x8);
	
	// .rela.plt section
	for (int i = 0; i < (jmprel_entry.size / struc_size); i++)
	{
		int type = reader.rel_info_type(jmprel[i]);
		int idx = reader.rel_info_index(jmprel[i]);

		if (type != R_X86_64_JUMP_SLOT)
		{
			msg("Unexpected relocation type (%i) for jump slot (%i)\n", type, i);
			continue;
		}

		/* I really dunno why commenting these out causes things to work correctly, if someone does, let me know!
		if (idx >= (jmprel_entry.size / sizeof(elf_sym_t)))
		{
			msg("Invalid symbol index %i for relocation %i at offset 0x%x\n", idx, i, jmprel[i].r_offset);
			//msg("*** %012llx %012llx Symbol index %i for relocation %i\n", jmprel[i].r_offset, jmprel[i].r_info, idx, i);
			continue;
		}
		else
		{
			msg("Symbol index %i for relocation %i at offset 0x%x\n", idx, i, jmprel[i].r_offset);
			//msg("%012llx %012llx Symbol index %i for relocation %i\n", jmprel[i].r_offset, jmprel[i].r_info, idx, i);
		}
		if (symtab[idx].st_name >= jmprel_entry.size)
		{
			msg("Invalid symbol string offset %x of symbol %i for relocation %i\n", symtab[idx].st_name, idx, i);
			continue;
		}
		*/

		qstring func_name = &strtab[symtab[idx].st_name];
		qstring module_name;

		if (dynlib.is_obfuscated(func_name.c_str()))
		{
			uint32 module_idx = dynlib.lookup(func_name.c_str());

			if (module_idx != -1)
				module_name = &strtab[module_idx];

			qstring obf_name;
			obf_name.sprnt("%s:%s", func_name.c_str(), module_name.c_str()); // substr(0, 11) if you want to remove #A#C etc.
			set_cmt(jmprel[i].r_offset, obf_name.c_str(), true);

			qstring deobf_name = dynlib.deobfuscate(func_name);

			if (deobf_name != "")
				func_name = deobf_name;
		}

		qstring import_name;
		import_name.sprnt(FUNC_IMPORT_PREFIX "%s", func_name.c_str());
		force_name(jmprel[i].r_offset, import_name.c_str());

		netnode import_node;
		netnode_check(&import_node, module_name.c_str(), 0, true); // "$ IDALDR node for ids loading $"
		netnode_supset(import_node, jmprel[i].r_offset, func_name.c_str(), 0, 339);
		import_module(module_name.c_str(), 0, import_node, 0, "linux");
		
		//msg(".rela.plt %i: 0x%x \t %s \t %s\n", i, jmprel[i].r_offset, rela_type_to_string(type).c_str(), func_name.c_str());

		create_struct((jmprel_entry.addr + (i * struc_size)), struc_size, sptr_rela->id);
	}

	delete[] jmprel;
}

void load_symtab(dynamic_info_t::entry_t &symtab_entry, elf_sym_t *&symtab, char *&strtab, DynLib &dynlib)
{
	// Elf64_Sym Structure
	uint64 struc_size = sizeof(elf_sym_t);

	struc_t *sptr_sym = get_struc(add_struc(BADADDR, "Elf64_Sym", 0));
	add_struc_member(sptr_sym, "st_name", 0x0, dword_flag(), NULL, 0x4);
	add_struc_member(sptr_sym, "st_info", 0x4, byte_flag(), NULL, 0x1);
	add_struc_member(sptr_sym, "st_other", 0x5, byte_flag(), NULL, 0x1);
	add_struc_member(sptr_sym, "st_shndx", 0x6, word_flag(), NULL, 0x2);
	add_struc_member(sptr_sym, "st_value", 0x8, qword_flag(), NULL, 0x8);
	add_struc_member(sptr_sym, "st_size", 0x10, qword_flag(), NULL, 0x8);

	// .symtab section
	for (int i = 0; i < (symtab_entry.size / struc_size); i++)
	{
		if (symtab[i].st_value == 0)
			continue;

		qstring func_name = &strtab[symtab[i].st_name];
		qstring module_name;

		if (dynlib.is_obfuscated(func_name.c_str()))
		{
			uint32 module_idx = dynlib.lookup(func_name.c_str());

			if (module_idx != -1)
				module_name = &strtab[module_idx];

			qstring obf_name;
			obf_name.sprnt("%s", func_name.c_str()); // substr(0, 11) if you want to remove #A#C etc.
			set_cmt(symtab[i].st_value, obf_name.c_str(), true);

			qstring deobf_name = dynlib.deobfuscate(func_name);

			if (deobf_name != "")
				func_name = deobf_name;
		}

		if (ELF_ST_TYPE(symtab[i].st_info) == STT_FUNC || ELF_ST_TYPE(symtab[i].st_info) == STT_GNU_IFUNC)
		{
			add_entry(symtab[i].st_value, symtab[i].st_value, func_name.c_str(), true);
		}
		else
		{
			force_name(symtab[i].st_value, func_name.c_str());
		}

		//msg(".symtab %i: 0x%x \t %s\n", i, symtab[i].st_value, func_name.c_str());

		create_struct((symtab_entry.addr + (i * struc_size)), struc_size, sptr_sym->id);
	}
}

void load_strtab(reader_t &reader, elf_phdr_t &dyndata, dynamic_info_t::entry_t &strtab_entry)
{
	elf_sym_t *str = new elf_sym_t[strtab_entry.size / sizeof(elf_sym_t)];
	
	reader.seek(dyndata.p_offset + strtab_entry.addr);

	if (reader.safe_read(str, (strtab_entry.size / sizeof(elf_sym_t)), false) != 0)
		loader_failure("Failed reading .strtab section!");

	// Elf64_Sym Structure
	uint64 struc_size = sizeof(elf_sym_t);

	struc_t *sptr_sym = get_struc(add_struc(BADADDR, "Elf64_Sym", 0));
	add_struc_member(sptr_sym, "st_name", 0x0, dword_flag(), NULL, 0x4);
	add_struc_member(sptr_sym, "st_info", 0x4, byte_flag(), NULL, 0x1);
	add_struc_member(sptr_sym, "st_other", 0x5, byte_flag(), NULL, 0x1);
	add_struc_member(sptr_sym, "st_shndx", 0x6, word_flag(), NULL, 0x2);
	add_struc_member(sptr_sym, "st_value", 0x8, qword_flag(), NULL, 0x8);
	add_struc_member(sptr_sym, "st_size", 0x10, qword_flag(), NULL, 0x8);

	// .strtab section
	for (int i = 0; i < (strtab_entry.size / struc_size); i++)
	{
		if (str[i].st_value == 0)
			continue;
		
		//msg(".strtab %i: value: 0x%x\n", i, str[i].st_value);

		create_struct((strtab_entry.addr + (i * struc_size)), struc_size, sptr_sym->id);
	}
}

void load_reladyn(reader_t &reader, elf_phdr_t &dyndata, dynamic_info_t::entry_t &rela_entry)
{
	elf_rela_t *rela = new elf_rela_t[rela_entry.size / sizeof(elf_rela_t)];

	reader.seek(dyndata.p_offset + rela_entry.addr);

	if (reader.safe_read(rela, rela_entry.size, false) != 0)
		loader_failure("Failed reading .rela.dyn section!");

	// Elf64_Dyn Structure
	struc_t *sptr_dyn = get_struc(add_struc(BADADDR, "Elf64_Dyn", 0));
	add_struc_member(sptr_dyn, "d_tag", 0x0, qword_flag(), NULL, 0x8);
	add_struc_member(sptr_dyn, "d_un", 0x8, qword_flag(), NULL, 0x8);

	// .rela.dyn section
	for (int i = 0; i < (rela_entry.size / sizeof(elf_sym_t)); i++)
	{
		if (rela[i].r_offset == 0)
			continue;
		
		int type = reader.rel_info_type(rela[i]);

		if (type < R_X86_64_NONE || type > R_X86_64_RELATIVE64)
		{
			msg("Unexpected relocation type (%i) for rela (%i) at offset (0x%x)\n", type, i, rela[i].r_offset);
			continue;
		}

		put_qword(rela[i].r_offset, rela[i].r_addend);

		//msg(".rela.dyn %i: 0x%x \t %s \t 0x%x\n", i, rela[i].r_offset, rela_type_to_string(type).c_str(), rela[i].r_addend);

		//create_struct((rela_entry.addr + (i * sizeof(elf_dyn_t))), sizeof(elf_dyn_t), sptr_dyn->id);
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
			reader.file_type_str() == "Executable" ? "PS4 Kernel" : reader.file_type_str());
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

	elf_set_compiler(load_elf(&reader), reader.get_header().e_flags, reader.get_header().e_ident.osabi);
	
	if (reader.get_header().e_phoff)
		add_test_feature("pht");

	if (reader.get_header().e_shoff)
		add_test_feature("sht");

	if (!reader.get_header().e_phoff)
		loader_failure("Missing program headers");

	if (!reader.read_program_headers())
		loader_failure("Failed reading program headers");

	// Program Base/Entry Address
	msg("\n[BELF] Entry Address: 0x%llx\n", reader.get_header().e_entry);
	set_imagebase(reader.get_header().e_entry);
	
	// Program Headers
	elf_phdr_t dyndata;
	bool has_dynamic = false;

	msg("\n[BELF] Processing Program Headers...\n");
	for (int i = 0; i < reader.pheaders.size(); i++)
	{
		elf_phdr_t *phdr = reader.pheaders.get(i);

		switch (phdr->p_type) {
		case PT_LOAD:
			create_segment(phdr->p_flags & PF_X ? ".text" : ".data", phdr->p_flags, reader.get_seg_bitness(), phdr->p_flags & PF_X ? SEG_CODE : SEG_DATA, phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz);
			file2base(li, phdr->p_offset, phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz, FILEREG_PATCHABLE);
			break;
		case PT_SCE_RELRO:
			create_segment(".data.rel.ro", phdr->p_flags, reader.get_seg_bitness(), SEG_XTRN, phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz);
			file2base(li, phdr->p_offset, phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz, FILEREG_PATCHABLE);
			break;
		case PT_GNU_EH_FRAME:
			create_segment(".eh_frame", phdr->p_flags, reader.get_seg_bitness(), SEG_DATA, phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz);
			file2base(li, phdr->p_offset, phdr->p_vaddr, phdr->p_vaddr + phdr->p_filesz, FILEREG_PATCHABLE);
			break;
		case PT_SCE_DYNLIBDATA:
			dyndata = *phdr;
			break;
		case PT_DYNAMIC:
			has_dynamic = true;
		}

		msg("%d %s:\n", i, p_type_to_string(phdr->p_type).c_str());
		msg("  p_flags:  0x%llx \t %s\n", phdr->p_flags, p_flags_to_string(phdr->p_flags).c_str());
		msg("  p_offset: 0x%llx\n", phdr->p_offset);
		msg("  p_vaddr:  0x%llx\n", phdr->p_vaddr);
		msg("  p_paddr:  0x%llx\n", phdr->p_paddr);
		msg("  p_filesz: 0x%llx\n", phdr->p_filesz);
		msg("  p_memsz:  0x%llx\n", phdr->p_memsz);
		msg("  p_align:  0x%llx\n", phdr->p_align);
	}

	if (has_dynamic)
	{
		// DYNAMIC segment
		msg("\n[BELF] Processing DYNAMIC segment...\n");
		reader_t::dyninfo_tags_t dynamic_tags;
		dynamic_info_t dynamic;
		bool outside = false;

		if (!reader.read_dynamic_info_tags(&dynamic_tags, reader.pheaders.get_dynamic_linking_tables_info()) ||
			!reader.parse_dynamic_info(&dynamic, dynamic_tags))
			loader_failure("Failed reading DYNAMIC segment!");

		// .strtab section
		char *strtab = new char[dynamic.strtab().size];

		reader.seek(dyndata.p_offset + dynamic.strtab().addr);
		reader.safe_read(strtab, dynamic.strtab().size, false);

		// .symtab section
		elf_sym_t *symtab = new elf_sym_t[dynamic.symtab().size / sizeof(elf_sym_t)];

		reader.seek(dyndata.p_offset + dynamic.symtab().addr);
		reader.safe_read(symtab, dynamic.symtab().size, false);

		if ((dynamic.strtab().addr + dynamic.strtab().size) > dyndata.p_filesz)
			outside = true;

		// tags
		for (elf_dyn_t *dyn = dynamic_tags.begin(); dyn != dynamic_tags.end(); ++dyn)
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
				msg("%s \t 0x%08llx\n", d_tag_to_string(tag).c_str(), data);
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
				msg("%s \t %d\n", d_tag_to_string(tag).c_str(), data);
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
				msg("DT_SCE_PLTREL \t %d \t       %s\n", data, d_tag_to_string(data).c_str());
				break;
			case DT_DEBUG:
			case DT_FLAGS:
				msg("%s \t\t 0x%08llx\n", d_tag_to_string(tag).c_str(), data);
				break;
			case DT_SONAME:
			case DT_NEEDED:
				msg("%s \t\t 0x%08llx       %s\n", d_tag_to_string(tag).c_str(), data, &strtab[nameidx]);
				break;
			case DT_SCE_NEEDED_MODULE:
			case DT_SCE_MODULE_INFO:
				msg("%s \t 0x%013llx  MID:%x  Name:%s\n", d_tag_to_string(tag).c_str(), data, id, outside ? "[Error: not in dynamic data]" : (const char *)&strtab[nameidx]);
				dynlib.add_module(id, nameidx);
				break;
			case DT_SCE_IMPORT_LIB:
			case DT_SCE_EXPORT_LIB:
				msg("%s \t 0x%013llx  LID:%x  Name:%s\n", d_tag_to_string(tag).c_str(), data, id, &strtab[nameidx]);
				break;
			case DT_SCE_IMPORT_LIB_ATTR:
			case DT_SCE_EXPORT_LIB_ATTR:
				msg("%s  0x%013llx  LID:%x  Attribute:%s\n",
					d_tag_to_string(tag).c_str(), data, id, port_attributes_to_string(attridx).c_str());
				break;
			case DT_SCE_ORIGINAL_FILENAME:
				msg("%s 0x%08llx      %s\n", d_tag_to_string(tag).c_str(), data, outside ? "[Error: not in dynamic data]" : (const char *)&strtab[nameidx]);
				break;
			case DT_SCE_MODULE_ATTR:
				msg("%s \t 0x%08llx       %s\n", d_tag_to_string(tag).c_str(), data, module_attributes_to_string(attridx).c_str());
				break;
			case DT_TEXTREL:
			case DT_NULL:
				msg("%s \t\t -\n", d_tag_to_string(tag).c_str());
				break;
			}
		}

		if (outside)
		{
			// If outside the DYNAMIC segment...

			// Elf64_Rela Structure
			uint64 struc_size = sizeof(elf_rela_t);

			struc_t *sptr_rela = get_struc(add_struc(BADADDR, "Elf64_Rela", 0));
			add_struc_member(sptr_rela, "r_offset", 0x0, qword_flag(), NULL, 0x8);
			add_struc_member(sptr_rela, "r_info", 0x8, qword_flag(), NULL, 0x8);
			add_struc_member(sptr_rela, "r_addend", 0x10, qword_flag(), NULL, 0x8);

			// .rela.plt section
			msg("\n[BELF] Processing %i imported functions...\n", dynamic.jmprel().size / struc_size);

			for (int i = 0; i < (dynamic.rela().size / struc_size); i++)
				create_struct((dynamic.rela().addr + (i * struc_size)), struc_size, sptr_rela->id);

			// Elf64_Sym Structure
			struc_size = sizeof(elf_sym_t);

			struc_t *sptr_sym = get_struc(add_struc(BADADDR, "Elf64_Sym", 0));
			add_struc_member(sptr_sym, "st_name", 0x0, dword_flag(), NULL, 0x4);
			add_struc_member(sptr_sym, "st_info", 0x4, byte_flag(), NULL, 0x1);
			add_struc_member(sptr_sym, "st_other", 0x5, byte_flag(), NULL, 0x1);
			add_struc_member(sptr_sym, "st_shndx", 0x6, word_flag(), NULL, 0x2);
			add_struc_member(sptr_sym, "st_value", 0x8, qword_flag(), NULL, 0x8);
			add_struc_member(sptr_sym, "st_size", 0x10, qword_flag(), NULL, 0x8);

			// .symtab section
			msg("\n[BELF] Processing %i symbol table entries...\n", dynamic.symtab().size / struc_size);

			for (int i = 0; i < (dynamic.symtab().size / struc_size); i++)
				create_struct((dynamic.symtab().addr + (i * struc_size)), struc_size, sptr_sym->id);
			/*
			// .strtab section
			msg("\n[BELF] Processing %i string table entries...\n", dynamic.strtab().size);

			for (int i = 0; i < (dynamic.strtab().size / struc_size); i++)
				create_struct((dynamic.strtab().addr + (i * struc_size)), struc_size, sptr_sym->id);
			*/
			// Elf64_Dyn Structure
			struc_t *sptr_dyn = get_struc(add_struc(BADADDR, "Elf64_Dyn", 0));
			add_struc_member(sptr_dyn, "d_tag", 0x0, qword_flag(), NULL, 0x8);
			add_struc_member(sptr_dyn, "d_un", 0x8, qword_flag(), NULL, 0x8);
			/*
			// .rela.dyn section
			msg("\n[BELF] Processing %i relocation table entries...\n", dynamic.rela().size / struc_size);
			
			for (int i = 0; i < (dynamic.rela().size / struc_size); i++)
				create_struct((dynamic.rela().addr + (i * struc_size)), struc_size, sptr_dyn->id);
			*/
		}
		else
		{
			// .rela.plt section
			msg("\n[BELF] Processing %i imported functions...\n", dynamic.jmprel().size / sizeof(elf_rela_t));
			load_relaplt(reader, dyndata, dynamic.jmprel(), symtab, strtab, dynlib);

			// .symtab section
			msg("\n[BELF] Processing %i symbol table entries...\n", dynamic.symtab().size / sizeof(elf_sym_t));
			load_symtab(dynamic.symtab(), symtab, strtab, dynlib);
			/*
			// .strtab section
			msg("\n[BELF] Processing %i string table entries...\n", dynamic.strtab().size / sizeof(elf_sym_t));
			load_strtab(reader, dyndata, dynamic.strtab());
			*/
			// .rela.dyn section
			msg("\n[BELF] Processing %i relocation table entries...\n", (dynamic.rela().size / sizeof(elf_sym_t)));
			load_reladyn(reader, dyndata, dynamic.rela());
		}

		delete[] symtab;
		delete[] strtab;
	}
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
