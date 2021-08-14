package elf

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/xerrors"
)

type ELFHeader struct {
	Ident     [16]byte
	Type      Type
	Machine   Machine
	Version   uint32
	Entry     uint64
	Phoff     uint64
	Shoff     uint64
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type elfHeader32 struct {
	Ident     [16]byte
	Type      uint16
	Machine   uint16
	Version   uint32
	Entry     uint32
	Phoff     uint32
	Shoff     uint32
	Flags     uint32
	Ehsize    uint16
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type ELFFile struct {
	Header     *ELFHeader
	Sections   []*Section
	Segments   []*Segment
	Endianness binary.ByteOrder
	Raw        []byte
}

type SectionHeader struct {
	Name      uint32
	Type      SectionHeaderType
	Flags     SectionFlag
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	EntSize   uint64
}

type sectionHeader32 struct {
	Name      uint32
	Type      uint32
	Flags     uint32
	Addr      uint32
	Offset    uint32
	Size      uint32
	Link      uint32
	Info      uint32
	Addralign uint32
	Entsize   uint32
}

type Section struct {
	Header SectionHeader
	Name   string
	Raw    []byte
}

type ProgramHeader struct {
	Type   ProgramHeaderType
	Flags  ProgramFlag
	Offset uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

type programHeader32 struct {
	Type   uint32
	Flags  uint32
	Offset uint32
	Vaddr  uint32
	Paddr  uint32
	Filesz uint32
	Memsz  uint32
	Align  uint32
}

type Segment struct {
	Header ProgramHeader
	Raw    []byte
}

func New(raw []byte) (*ELFFile, error) {
	if len(raw) < int(MAGIC_SIZE) {
		return nil, xerrors.Errorf("insufficient elf format size: %d", len(raw))
	}

	if !bytes.Equal(raw[:MAGIC_SIZE], []byte(ELF_MAGIC)) {
		return nil, xerrors.Errorf("invalid magic number: %s", raw[:MAGIC_SIZE])
	}

	var endianness binary.ByteOrder
	if raw[EI_DATA] != 1 {
		if raw[EI_DATA] != 2 {
			return nil, xerrors.Errorf("invalid endianness: %d", raw[EI_DATA])
		}
		endianness = binary.BigEndian
	} else {
		endianness = binary.LittleEndian
	}

	if raw[EI_CLASS] != 1 && raw[EI_CLASS] != 2 {
		return nil, xerrors.Errorf("invalid elf class: %d", raw[EI_CLASS])
	}

	var header ELFHeader
	r := bytes.NewReader(raw)
	if raw[EI_CLASS] == 1 {
		header32 := new(elfHeader32)
		err := binary.Read(r, endianness, header32)
		if err != nil {
			return nil, xerrors.Errorf("failed to read elf header: %w", err)
		}
		header = convertToELFHeader(header32)
	} else {
		err := binary.Read(r, endianness, &header)
		if err != nil {
			return nil, xerrors.Errorf("failed to read elf header: %w", err)
		}
	}

	e := &ELFFile{
		Header:     &header,
		Endianness: endianness,
		Raw:        raw,
	}

	if header.Shnum == 0 {
		e.Sections = make([]*Section, 0)
	} else {
		if uint64(len(e.Raw)) <= header.Shoff {
			return nil, xerrors.Errorf("invalid section header offset: %d", header.Shoff)
		}

		shs := make([]SectionHeader, header.Shnum)
		r = bytes.NewReader(e.Raw[header.Shoff:])
		if e.Header.Ident[EI_CLASS] == 1 {
			sh32s := make([]sectionHeader32, header.Shnum)
			err := binary.Read(r, endianness, sh32s)
			if err != nil {
				return nil, xerrors.Errorf("failed to read section header: %w", err)
			}

			for i := 0; i < len(sh32s); i++ {
				shs[i] = convertToSectionHeader(&sh32s[i])
			}
		} else {
			err := binary.Read(r, endianness, shs)
			if err != nil {
				return nil, xerrors.Errorf("failed to read section header: %w", err)
			}
		}

		e.Sections = make([]*Section, header.Shnum)
		stroffset := shs[header.Shstrndx].Offset
		for i := 0; i < len(shs); i++ {
			index := stroffset + uint64(shs[i].Name)
			if uint64(len(e.Raw)) <= index {
				return nil, xerrors.Errorf("invalid section string index: %d", index)
			}

			for e.Raw[index] != 0 {
				index++
			}

			n := string(e.Raw[stroffset+uint64(shs[i].Name) : index])
			sr := e.Raw[shs[i].Offset : shs[i].Offset+shs[i].Size]
			s := Section{
				Header: shs[i],
				Name:   n,
				Raw:    sr,
			}
			e.Sections[i] = &s
		}
	}

	if header.Phnum == 0 {
		e.Segments = make([]*Segment, 0)
	} else {
		if header.Phoff >= uint64(len(e.Raw)) {
			return nil, xerrors.Errorf("invalid program header offset: %d", header.Phoff)
		}

		phs := make([]ProgramHeader, header.Phnum)
		r = bytes.NewReader(e.Raw[header.Phoff:])
		if e.Header.Ident[EI_CLASS] == 1 {
			ph32s := make([]programHeader32, header.Phnum)
			err := binary.Read(r, endianness, ph32s)
			if err != nil {
				return nil, xerrors.Errorf("failed to read program header: %w", err)
			}

			for i := 0; i < len(ph32s); i++ {
				phs[i] = convertToProgramHeader(&ph32s[i])
			}
		} else {
			err := binary.Read(r, endianness, phs)
			if err != nil {
				return nil, xerrors.Errorf("failed to read program header: %w", err)
			}
		}

		e.Segments = make([]*Segment, header.Phnum)
		for i := 0; i < len(phs); i++ {
			sgr := e.Raw[phs[i].Offset : phs[i].Offset+phs[i].Filesz]
			sg := Segment{
				Header: phs[i],
				Raw:    sgr,
			}
			e.Segments[i] = &sg
		}
	}

	return e, nil
}

// SectionByName get a section by name.
func (e *ELFFile) SectionByName(name string) *Section {
	for _, s := range e.Sections {
		if s.Name == name {
			return s
		}
	}

	return nil
}

// SectionsByFlag get sections by flag.
func (e *ELFFile) SectionsByFlag(sf SectionFlag) []*Section {
	var ss []*Section
	for _, s := range e.Sections {
		if s.Header.Flags == sf {
			ss = append(ss, s)
		}
	}

	return ss
}

// SectionsByType get sections by type.
func (e *ELFFile) SectionsByType(sht SectionHeaderType) []*Section {
	var ss []*Section
	for _, s := range e.Sections {
		if s.Header.Type == sht {
			ss = append(ss, s)
		}
	}

	return ss
}

// SectionAt get a setcion by index.
func (e *ELFFile) SectionAt(n uint16) *Section {
	ss := e.Sections
	if n > uint16(len(ss)) {
		return nil
	}

	return ss[n]
}

// SegmentsByFlag get segments by flag.
func (e *ELFFile) SegmentsByFlag(pf ProgramFlag) []*Segment {
	var sgs []*Segment
	for _, sg := range e.Segments {
		if sg.Header.Flags == pf {
			sgs = append(sgs, sg)
		}
	}

	return sgs
}

// SegmentsByType get segments by type.
func (e *ELFFile) SegmentsByType(pt ProgramHeaderType) []*Segment {
	var sgs []*Segment
	for _, sg := range e.Segments {
		if sg.Header.Type == pt {
			sgs = append(sgs, sg)
		}
	}

	return sgs
}

// SegmentAt get a segment by index.
func (e *ELFFile) SegmentAt(n uint16) *Segment {
	sgs := e.Segments
	if n > uint16(len(sgs)) {
		return nil
	}

	return sgs[n]
}

func convertToELFHeader(header32 *elfHeader32) ELFHeader {
	return ELFHeader{
		Ident:     header32.Ident,
		Type:      Type(header32.Type),
		Machine:   Machine(header32.Machine),
		Version:   header32.Version,
		Entry:     uint64(header32.Entry),
		Phoff:     uint64(header32.Phoff),
		Shoff:     uint64(header32.Shoff),
		Flags:     header32.Flags,
		Ehsize:    header32.Ehsize,
		Phentsize: header32.Phentsize,
		Phnum:     header32.Phnum,
		Shentsize: header32.Shentsize,
		Shnum:     header32.Shnum,
		Shstrndx:  header32.Shstrndx,
	}
}

func convertToSectionHeader(header32 *sectionHeader32) SectionHeader {
	return SectionHeader{
		Name:      header32.Name,
		Type:      SectionHeaderType(header32.Type),
		Flags:     SectionFlag(header32.Flags),
		Addr:      uint64(header32.Addr),
		Offset:    uint64(header32.Offset),
		Size:      uint64(header32.Size),
		Link:      header32.Link,
		Info:      header32.Info,
		Addralign: uint64(header32.Addralign),
		EntSize:   uint64(header32.Entsize),
	}
}

func convertToProgramHeader(header32 *programHeader32) ProgramHeader {
	return ProgramHeader{
		Type:   ProgramHeaderType(header32.Type),
		Flags:  ProgramFlag(header32.Flags),
		Offset: uint64(header32.Offset),
		Vaddr:  uint64(header32.Vaddr),
		Paddr:  uint64(header32.Paddr),
		Filesz: uint64(header32.Filesz),
		Memsz:  uint64(header32.Memsz),
		Align:  uint64(header32.Align),
	}
}
