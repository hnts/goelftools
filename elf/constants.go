package elf

const ELF_MAGIC = "\x7FELF"

const (
	MAGIC_SIZE    uint8 = 4
	EI_CLASS      uint8 = 4
	EI_DATA       uint8 = 5
	EI_VERSION    uint8 = 6
	EI_OSABI      uint8 = 7
	EI_ABIVERSION uint8 = 8
	EI_PADDING    uint8 = 9
)

type Type uint16

const (
	ET_NONE   Type = 0
	ET_REL    Type = 1
	ET_EXEC   Type = 2
	ET_DYN    Type = 3
	ET_CORE   Type = 4
	ET_NUM    Type = 5
	ET_LPROC  Type = 0xff00
	ET_HIPROC Type = 0xffff
)

type Machine uint16

const (
	EM_NONE    Machine = 0
	EM_386     Machine = 3
	EM_486     Machine = 6
	EM_860     Machine = 7
	EM_MIPS    Machine = 8
	EM_PPC     Machine = 20
	EM_PPC64   Machine = 21
	EM_ARM     Machine = 40
	EM_IA_64   Machine = 50
	EM_X86_64  Machine = 62
	EM_AARCH64 Machine = 183
)

type SectionHeaderType uint32

const (
	SHT_NULL          SectionHeaderType = 0
	SHT_PROGBITS      SectionHeaderType = 1
	SHT_SYMTAB        SectionHeaderType = 2
	SHT_STRTAB        SectionHeaderType = 3
	SHT_RELA          SectionHeaderType = 4
	SHT_HASH          SectionHeaderType = 5
	SHT_DYNAMIC       SectionHeaderType = 6
	SHT_NOTE          SectionHeaderType = 7
	SHT_NOBITS        SectionHeaderType = 8
	SHT_REL           SectionHeaderType = 9
	SHT_SHLIB         SectionHeaderType = 10
	SHT_DYNSYM        SectionHeaderType = 11
	SHT_INIT_ARRAY    SectionHeaderType = 14
	SHT_FINI_ARRAY    SectionHeaderType = 15
	SHT_PREINIT_ARRAY SectionHeaderType = 16
	SHT_GROUP         SectionHeaderType = 17
	SHT_SYMTAB_SHNDX  SectionHeaderType = 18
	SHT_LOOS          SectionHeaderType = 0x60000000
	SHT_HIOS          SectionHeaderType = 0x6fffffff
	SHT_LOPROC        SectionHeaderType = 0x70000000
	SHT_HIPROC        SectionHeaderType = 0x7fffffff
	SHT_LOUSER        SectionHeaderType = 0x80000000
	SHT_HIUSER        SectionHeaderType = 0xffffffff
)

type SectionFlag uint64

const (
	SHF_WRITE            SectionFlag = 0x1
	SHF_ALLOC            SectionFlag = 0x2
	SHF_EXECINSTR        SectionFlag = 0x4
	SHF_MERGE            SectionFlag = 0x10
	SHF_STRINGS          SectionFlag = 0x20
	SHF_INFO_LINK        SectionFlag = 0x40
	SHF_LINK_ORDER       SectionFlag = 0x80
	SHF_OS_NONCONFORMING SectionFlag = 0x100
	SHF_GROUP            SectionFlag = 0x200
	SHF_TLS              SectionFlag = 0x400
	SHF_COMPRESSED       SectionFlag = 0x800
	SHF_MASKOS           SectionFlag = 0x0ff00000
	SHF_MASKPROC         SectionFlag = 0xf0000000
	SHF_ORDERED          SectionFlag = 0x40000000
	SHF_EXCLUDE          SectionFlag = 0x80000000
)

type ProgramHeaderType uint32

const (
	PT_NULL         ProgramHeaderType = 0
	PT_LOAD         ProgramHeaderType = 1
	PT_DYNAMIC      ProgramHeaderType = 2
	PT_INTERP       ProgramHeaderType = 3
	PT_NOTE         ProgramHeaderType = 4
	PT_SHLIB        ProgramHeaderType = 5
	PT_PHDR         ProgramHeaderType = 6
	PT_TLS          ProgramHeaderType = 7
	PT_NUM          ProgramHeaderType = 8
	PT_LOOS         ProgramHeaderType = 0x60000000
	PT_GNU_EH_FRAME ProgramHeaderType = 0x6474e550
	PT_GNU_STACK    ProgramHeaderType = 0x6474e551
	PT_GNU_RELRO    ProgramHeaderType = 0x6474e552
	PT_HIOS         ProgramHeaderType = 0x6fffffff
	PT_LOPROC       ProgramHeaderType = 0x70000000
	PT_HIPROC       ProgramHeaderType = 0x7fffffff
)

type ProgramFlag uint32

const (
	PF_X        ProgramFlag = 1
	PF_W        ProgramFlag = 2
	PF_R        ProgramFlag = 4
	PF_MASKOS   ProgramFlag = 0x0ff00000
	PF_MASKPROC ProgramFlag = 0xf0000000
)
