package elf_test

import (
	"encoding/binary"
	"os"
	"reflect"
	"testing"

	"github.com/hnts/goelftools/elf"
)

type testFiles struct {
	fileName   string
	header     *elf.ELFHeader
	endianness binary.ByteOrder
	sections   []elf.Section
	segments   []elf.Segment
}

var tests = []testFiles{
	{
		"../testdata/elf_linux_amd64",
		&elf.ELFHeader{
			[16]uint8{0x7f, 0x45, 0x4c, 0x46, 0x2, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			0x2, 0x3e, 0x1, 0x465860, 0x40, 0x1c8, 0x0, 0x40, 0x38, 0x7, 0x40, 0x17, 0x3},
		binary.LittleEndian,
		[]elf.Section{
			{Name: "", Header: elf.SectionHeader{Name: 0x0, Type: 0x0, Flags: 0x0, Addr: 0x0, Offset: 0x0, Size: 0x0, Link: 0x0, Info: 0x0, Addralign: 0x0, EntSize: 0x0}},
			{Name: ".text", Header: elf.SectionHeader{Name: 0x1, Type: 0x1, Flags: 0x6, Addr: 0x401000, Offset: 0x1000, Size: 0x967ea, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".rodata", Header: elf.SectionHeader{Name: 0x6a, Type: 0x1, Flags: 0x2, Addr: 0x498000, Offset: 0x98000, Size: 0x43be4, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".shstrtab", Header: elf.SectionHeader{Name: 0x170, Type: 0x3, Flags: 0x0, Addr: 0x0, Offset: 0xdbc00, Size: 0x17a, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".typelink", Header: elf.SectionHeader{Name: 0x72, Type: 0x1, Flags: 0x2, Addr: 0x4dbd80, Offset: 0xdbd80, Size: 0x72c, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".itablink", Header: elf.SectionHeader{Name: 0x7c, Type: 0x1, Flags: 0x2, Addr: 0x4dc4c0, Offset: 0xdc4c0, Size: 0x50, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".gosymtab", Header: elf.SectionHeader{Name: 0x86, Type: 0x1, Flags: 0x2, Addr: 0x4dc510, Offset: 0xdc510, Size: 0x0, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".gopclntab", Header: elf.SectionHeader{Name: 0x90, Type: 0x1, Flags: 0x2, Addr: 0x4dc520, Offset: 0xdc520, Size: 0x58c20, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".go.buildinfo", Header: elf.SectionHeader{Name: 0x42, Type: 0x1, Flags: 0x3, Addr: 0x536000, Offset: 0x136000, Size: 0x20, Link: 0x0, Info: 0x0, Addralign: 0x10, EntSize: 0x0}},
			{Name: ".noptrdata", Header: elf.SectionHeader{Name: 0x7, Type: 0x1, Flags: 0x3, Addr: 0x536020, Offset: 0x136020, Size: 0xe2c4, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".data", Header: elf.SectionHeader{Name: 0x12, Type: 0x1, Flags: 0x3, Addr: 0x544300, Offset: 0x144300, Size: 0x7790, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".bss", Header: elf.SectionHeader{Name: 0x18, Type: 0x8, Flags: 0x3, Addr: 0x54baa0, Offset: 0x14baa0, Size: 0x2d750, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".noptrbss", Header: elf.SectionHeader{Name: 0x1d, Type: 0x8, Flags: 0x3, Addr: 0x579200, Offset: 0x179200, Size: 0x5310, Link: 0x0, Info: 0x0, Addralign: 0x20, EntSize: 0x0}},
			{Name: ".zdebug_abbrev", Header: elf.SectionHeader{Name: 0xb9, Type: 0x1, Flags: 0x0, Addr: 0x57f000, Offset: 0x14c000, Size: 0x119, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".zdebug_line", Header: elf.SectionHeader{Name: 0x11f, Type: 0x1, Flags: 0x0, Addr: 0x57f119, Offset: 0x14c119, Size: 0x1c4f9, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".zdebug_frame", Header: elf.SectionHeader{Name: 0xd5, Type: 0x1, Flags: 0x0, Addr: 0x59b612, Offset: 0x168612, Size: 0x5b4e, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".debug_gdb_scripts", Header: elf.SectionHeader{Name: 0x12c, Type: 0x1, Flags: 0x0, Addr: 0x5a1160, Offset: 0x16e160, Size: 0x3e, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".zdebug_info", Header: elf.SectionHeader{Name: 0xef, Type: 0x1, Flags: 0x0, Addr: 0x5a119e, Offset: 0x16e19e, Size: 0x33328, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".zdebug_loc", Header: elf.SectionHeader{Name: 0x107, Type: 0x1, Flags: 0x0, Addr: 0x5d44c6, Offset: 0x1a14c6, Size: 0x177bc, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".zdebug_ranges", Header: elf.SectionHeader{Name: 0x161, Type: 0x1, Flags: 0x0, Addr: 0x5ebc82, Offset: 0x1b8c82, Size: 0x91a5, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
			{Name: ".note.go.buildid", Header: elf.SectionHeader{Name: 0x50, Type: 0x7, Flags: 0x2, Addr: 0x400f9c, Offset: 0xf9c, Size: 0x64, Link: 0x0, Info: 0x0, Addralign: 0x4, EntSize: 0x0}},
			{Name: ".symtab", Header: elf.SectionHeader{Name: 0x9b, Type: 0x2, Flags: 0x0, Addr: 0x0, Offset: 0x1c1e28, Size: 0xcb88, Link: 0x16, Info: 0x7c, Addralign: 0x8, EntSize: 0x18}},
			{Name: ".strtab", Header: elf.SectionHeader{Name: 0xa3, Type: 0x3, Flags: 0x0, Addr: 0x0, Offset: 0x1ce9b0, Size: 0xb7b7, Link: 0x0, Info: 0x0, Addralign: 0x1, EntSize: 0x0}},
		},
		[]elf.Segment{
			{Header: elf.ProgramHeader{Type: 0x6, Flags: 0x4, Offset: 0x40, Vaddr: 0x400040, Paddr: 0x400040, Filesz: 0x188, Memsz: 0x188, Align: 0x1000}},
			{Header: elf.ProgramHeader{Type: 0x4, Flags: 0x4, Offset: 0xf9c, Vaddr: 0x400f9c, Paddr: 0x400f9c, Filesz: 0x64, Memsz: 0x64, Align: 0x4}},
			{Header: elf.ProgramHeader{Type: 0x1, Flags: 0x5, Offset: 0x0, Vaddr: 0x400000, Paddr: 0x400000, Filesz: 0x977ea, Memsz: 0x977ea, Align: 0x1000}},
			{Header: elf.ProgramHeader{Type: 0x1, Flags: 0x4, Offset: 0x98000, Vaddr: 0x498000, Paddr: 0x498000, Filesz: 0x9d140, Memsz: 0x9d140, Align: 0x1000}},
			{Header: elf.ProgramHeader{Type: 0x1, Flags: 0x6, Offset: 0x136000, Vaddr: 0x536000, Paddr: 0x536000, Filesz: 0x15aa0, Memsz: 0x48510, Align: 0x1000}},
			{Header: elf.ProgramHeader{Type: 0x6474e551, Flags: 0x6, Offset: 0x0, Vaddr: 0x0, Paddr: 0x0, Filesz: 0x0, Memsz: 0x0, Align: 0x8}},
			{Header: elf.ProgramHeader{Type: 0x65041580, Flags: 0x2a00, Offset: 0x0, Vaddr: 0x0, Paddr: 0x0, Filesz: 0x0, Memsz: 0x0, Align: 0x8}},
		},
	},
}

func TestNew(t *testing.T) {
	for _, tt := range tests {
		b, err := os.ReadFile(tt.fileName)
		if err != nil {
			t.Fatalf("failed to read %s: %s", tt.fileName, err)
		}

		e, err := elf.New(b)
		if err != nil {
			t.Fatalf("[%s] expected no error: %s", tt.fileName, err)
		}

		if !reflect.DeepEqual(tt.header, e.Header) {
			t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, e.Header, tt.header)
		}

		if !reflect.DeepEqual(tt.endianness, e.Endianness) {
			t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, e.Endianness, tt.endianness)
		}

		if len(tt.sections) != len(e.Sections) {
			t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, len(e.Sections), len(tt.sections))
		}

		for i, ts := range tt.sections {
			s := e.Sections[i]
			if s != nil {
				if ts.Name != s.Name {
					t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, s.Name, ts.Name)
				}

				if !reflect.DeepEqual(ts.Header, s.Header) {
					t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, s.Header, ts.Header)
				}
			} else {
				t.Errorf("%s: e.Sections[%d] should not be nil.", tt.fileName, i)
			}

		}

		if len(tt.sections) != len(e.Sections) {
			t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, len(e.Sections), len(tt.sections))
		}

		for i, ts := range tt.segments {
			s := e.Segments[i]
			if s != nil {
				if !reflect.DeepEqual(ts.Header, s.Header) {
					t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, s.Header, ts.Header)
				}
			} else {
				t.Errorf("%s: e.Segments[%d] should not be nil.", tt.fileName, i)
			}

		}
	}
}

func TestSectionByName(t *testing.T) {
	for _, tt := range tests {
		b, err := os.ReadFile(tt.fileName)
		if err != nil {
			t.Fatal(err)
		}

		e, err := elf.New(b)
		if err != nil {
			t.Fatal(err)
		}

		for _, ts := range tt.sections {
			s := e.SectionByName(ts.Name)
			if s != nil {
				if ts.Name != s.Name {
					t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, s.Name, ts.Name)
				}

				if !reflect.DeepEqual(ts.Header, s.Header) {
					t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, s.Header, ts.Header)
				}
			} else {
				t.Errorf("%s: returned value of `e.SectionByName(%s)` should not be nil.", tt.fileName, ts.Name)
			}
		}

		s := e.SectionByName("foooobar")
		if s != nil {
			t.Errorf("%s: returned value of `e.SectionByName(\"foooobar\")` should be nil. \n\thave %#v\n", tt.fileName, s)
		}
	}
}

func TestSectionAt(t *testing.T) {
	for _, tt := range tests {
		b, err := os.ReadFile(tt.fileName)
		if err != nil {
			t.Fatal(err)
		}

		e, err := elf.New(b)
		if err != nil {
			t.Fatal(err)
		}

		for i, ts := range tt.sections {
			s := e.SectionAt(uint16(i))
			if s != nil {
				if ts.Name != s.Name {
					t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, s.Name, ts.Name)
				}

				if !reflect.DeepEqual(ts.Header, s.Header) {
					t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, s.Header, ts.Header)
				}
			} else {
				t.Errorf("%s: returned value of `e.SectionByName(%s)` should not be nil.", tt.fileName, ts.Name)
			}
		}

		idx := len(e.Sections)
		s := e.SectionAt(uint16(idx))
		if s != nil {
			t.Errorf("%s: returned value of `e.SectionAt(uint16(%d))` should be nil. \n\thave %#v\n", tt.fileName, idx, s)
		}
	}
}

// validELF64 builds a minimal but well-formed little-endian 64-bit ELF
// containing a NULL section and a .shstrtab section, with the string table
// placed at the end of the file so tests can truncate the terminating null.
func validELF64() []byte {
	const (
		ehsize  = 64
		shentsz = 64
		shnum   = 2
	)
	strtab := []byte("\x00.shstrtab\x00")
	shoff := uint64(ehsize)
	strOff := shoff + shentsz*shnum
	total := strOff + uint64(len(strtab))

	raw := make([]byte, total)

	copy(raw[0:4], []byte(elf.ELF_MAGIC))
	raw[4] = 2 // EI_CLASS = ELFCLASS64
	raw[5] = 1 // EI_DATA = little endian
	raw[6] = 1 // EI_VERSION

	le := binary.LittleEndian
	le.PutUint16(raw[16:], 2)       // e_type = ET_EXEC
	le.PutUint16(raw[18:], 0x3e)    // e_machine = x86-64
	le.PutUint32(raw[20:], 1)       // e_version
	le.PutUint64(raw[40:], shoff)   // e_shoff
	le.PutUint16(raw[52:], ehsize)  // e_ehsize
	le.PutUint16(raw[58:], shentsz) // e_shentsize
	le.PutUint16(raw[60:], shnum)   // e_shnum
	le.PutUint16(raw[62:], 1)       // e_shstrndx

	copy(raw[strOff:], strtab)

	// section 1: .shstrtab (section 0 stays all-zero / NULL)
	sh1 := shoff + shentsz
	le.PutUint32(raw[sh1+0:], 1)                    // sh_name -> ".shstrtab"
	le.PutUint32(raw[sh1+4:], 3)                    // sh_type = SHT_STRTAB
	le.PutUint64(raw[sh1+24:], strOff)              // sh_offset
	le.PutUint64(raw[sh1+32:], uint64(len(strtab))) // sh_size

	return raw
}

// validELF64WithSegment builds a minimal 64-bit ELF with no sections and a
// single PT_LOAD program header, used to exercise segment parsing.
func validELF64WithSegment() []byte {
	const (
		ehsize  = 64
		phentsz = 56
		phnum   = 1
	)
	phoff := uint64(ehsize)
	total := phoff + phentsz*phnum

	raw := make([]byte, total)

	copy(raw[0:4], []byte(elf.ELF_MAGIC))
	raw[4] = 2
	raw[5] = 1
	raw[6] = 1

	le := binary.LittleEndian
	le.PutUint16(raw[16:], 2)
	le.PutUint16(raw[18:], 0x3e)
	le.PutUint32(raw[20:], 1)
	le.PutUint64(raw[32:], phoff)   // e_phoff
	le.PutUint16(raw[52:], ehsize)  // e_ehsize
	le.PutUint16(raw[54:], phentsz) // e_phentsize
	le.PutUint16(raw[56:], phnum)   // e_phnum

	// program header 0: PT_LOAD covering the start of the file
	le.PutUint32(raw[phoff+0:], 1)       // p_type = PT_LOAD
	le.PutUint64(raw[phoff+8:], 0)       // p_offset
	le.PutUint64(raw[phoff+32:], ehsize) // p_filesz

	return raw
}

// validELF32 builds a minimal well-formed little-endian 32-bit ELF, used to
// exercise the 32-bit conversion paths.
func validELF32() []byte {
	const (
		ehsize  = 52
		shentsz = 40
		shnum   = 2
	)
	strtab := []byte("\x00.shstrtab\x00")
	strOff := uint64(ehsize)
	shoff := strOff + uint64(len(strtab))
	total := shoff + shentsz*shnum

	raw := make([]byte, total)

	copy(raw[0:4], []byte(elf.ELF_MAGIC))
	raw[4] = 1 // EI_CLASS = ELFCLASS32
	raw[5] = 1 // EI_DATA = little endian
	raw[6] = 1 // EI_VERSION

	le := binary.LittleEndian
	le.PutUint16(raw[16:], 2)             // e_type
	le.PutUint16(raw[18:], 3)             // e_machine = EM_386
	le.PutUint32(raw[20:], 1)             // e_version
	le.PutUint32(raw[32:], uint32(shoff)) // e_shoff
	le.PutUint16(raw[40:], ehsize)        // e_ehsize
	le.PutUint16(raw[46:], shentsz)       // e_shentsize
	le.PutUint16(raw[48:], shnum)         // e_shnum
	le.PutUint16(raw[50:], 1)             // e_shstrndx

	copy(raw[strOff:], strtab)

	sh1 := shoff + shentsz
	le.PutUint32(raw[sh1+0:], 1)                    // sh_name
	le.PutUint32(raw[sh1+4:], 3)                    // sh_type = SHT_STRTAB
	le.PutUint32(raw[sh1+16:], uint32(strOff))      // sh_offset
	le.PutUint32(raw[sh1+20:], uint32(len(strtab))) // sh_size

	return raw
}

func TestNewValidSynthetic(t *testing.T) {
	cases := map[string][]byte{
		"elf64":            validELF64(),
		"elf64WithSegment": validELF64WithSegment(),
		"elf32":            validELF32(),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := elf.New(raw); err != nil {
				t.Fatalf("expected valid ELF to parse, got error: %s", err)
			}
		})
	}
}

func TestNewMalformed(t *testing.T) {
	le := binary.LittleEndian

	cases := []struct {
		name  string
		build func() []byte
	}{
		{
			name: "shstrndx out of range",
			build: func() []byte {
				raw := validELF64()
				le.PutUint16(raw[60:], 2) // e_shnum
				le.PutUint16(raw[62:], 5) // e_shstrndx >= shnum
				return raw
			},
		},
		{
			name: "shstrndx is SHN_XINDEX",
			build: func() []byte {
				raw := validELF64()
				le.PutUint16(raw[62:], 0xffff) // e_shstrndx = SHN_XINDEX
				return raw
			},
		},
		{
			name: "section name offset out of bounds",
			build: func() []byte {
				raw := validELF64()
				sh1 := uint64(64 + 64)          // section header 1
				le.PutUint32(raw[sh1+0:], 1000) // sh_name far beyond file
				return raw
			},
		},
		{
			name: "section name not null terminated",
			build: func() []byte {
				raw := validELF64()
				return raw[:len(raw)-1] // drop the terminating null
			},
		},
		{
			name: "terminating null lies outside the string table",
			build: func() []byte {
				// The file still contains a trailing null, but the
				// declared string table size excludes it, so the name
				// must be reported as unterminated within the table.
				raw := validELF64()
				sh1 := uint64(64 + 64)
				le.PutUint64(raw[sh1+32:], uint64(len("\x00.shstrtab"))) // sh_size excludes final null
				return raw
			},
		},
		{
			name: "section body out of bounds",
			build: func() []byte {
				raw := validELF64()
				sh1 := uint64(64 + 64)
				le.PutUint64(raw[sh1+32:], 0xffffffff) // sh_size huge
				return raw
			},
		},
		{
			name: "section entry size too small",
			build: func() []byte {
				raw := validELF64()
				le.PutUint16(raw[58:], 1) // e_shentsize < struct size
				return raw
			},
		},
		{
			name: "segment body out of bounds",
			build: func() []byte {
				raw := validELF64WithSegment()
				le.PutUint64(raw[64+32:], 0xffffffff) // p_filesz huge
				return raw
			},
		},
		{
			name: "program entry size too small",
			build: func() []byte {
				raw := validELF64WithSegment()
				le.PutUint16(raw[54:], 1) // e_phentsize < struct size
				return raw
			},
		},
		{
			name: "truncated before ident",
			build: func() []byte {
				return []byte(elf.ELF_MAGIC) // only 4 bytes
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("New panicked instead of returning an error: %v", r)
				}
			}()

			if _, err := elf.New(tc.build()); err == nil {
				t.Fatalf("expected error for malformed ELF, got nil")
			}
		})
	}
}

func TestSegmentAt(t *testing.T) {
	for _, tt := range tests {
		b, err := os.ReadFile(tt.fileName)
		if err != nil {
			t.Fatal(err)
		}

		e, err := elf.New(b)
		if err != nil {
			t.Fatal(err)
		}

		for i, ts := range tt.segments {
			s := e.SegmentAt(uint16(i))
			if s != nil {
				if !reflect.DeepEqual(ts.Header, s.Header) {
					t.Errorf("%s:\n\thave %#v\n\twant %#v\n", tt.fileName, s.Header, ts.Header)
				}
			} else {
				t.Errorf("%s: e.Segments[%d] should not be nil.", tt.fileName, i)
			}
		}

		idx := len(e.Segments)
		s := e.SegmentAt(uint16(idx))
		if s != nil {
			t.Errorf("%s: returned value of `e.SegmentAt(uint16(%d))` should be nil. \n\thave %#v\n", tt.fileName, idx, s)
		}
	}
}
