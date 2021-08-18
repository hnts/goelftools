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
