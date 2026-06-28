package elf

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

// File represents a parsed ELF file, including its header, sections,
// segments, detected endianness, and the raw underlying bytes.
type File struct {
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
	Offset uint32
	Vaddr  uint32
	Paddr  uint32
	Filesz uint32
	Memsz  uint32
	Flags  uint32
	Align  uint32
}

type Segment struct {
	Header ProgramHeader
	Raw    []byte
}

var (
	sizeSectionHeader32 = uint64(binary.Size(sectionHeader32{}))
	sizeSectionHeader64 = uint64(binary.Size(SectionHeader{}))
	sizeProgramHeader32 = uint64(binary.Size(programHeader32{}))
	sizeProgramHeader64 = uint64(binary.Size(ProgramHeader{}))
)

// safeSlice returns raw[offset:offset+size] only when the range is fully
// contained in raw, guarding against integer overflow and out-of-bounds
// access caused by malformed ELF files.
func safeSlice(raw []byte, offset, size uint64) ([]byte, error) {
	end := offset + size
	if end < offset {
		return nil, fmt.Errorf("range [%d:%d+%d] overflows", offset, offset, size)
	}
	if offset > uint64(len(raw)) || end > uint64(len(raw)) {
		return nil, fmt.Errorf("range [%d:%d] out of bounds (len %d)", offset, end, len(raw))
	}

	return raw[offset:end], nil
}

// sectionName resolves a null-terminated name at nameOffset inside the
// section header string table, bounded by the string table itself rather than
// the whole file. A NUL that only appears in data following the table is not
// accepted as a terminator.
func sectionName(strtab []byte, nameOffset uint32) (string, error) {
	if uint64(nameOffset) >= uint64(len(strtab)) {
		return "", fmt.Errorf("invalid section name offset: %d (string table size %d)", nameOffset, len(strtab))
	}

	rel := bytes.IndexByte(strtab[nameOffset:], 0)
	if rel < 0 {
		return "", fmt.Errorf("section name at offset %d is not null-terminated within the string table", nameOffset)
	}

	return string(strtab[nameOffset : uint64(nameOffset)+uint64(rel)]), nil
}

func parseSectionHeaders(raw []byte, endianness binary.ByteOrder, is32 bool, shoff uint64, shnum, shentsize uint16) ([]SectionHeader, error) {
	structSize := sizeSectionHeader64
	if is32 {
		structSize = sizeSectionHeader32
	}
	if uint64(shentsize) < structSize {
		return nil, fmt.Errorf("invalid section header entry size: %d", shentsize)
	}

	shs := make([]SectionHeader, shnum)
	for i := 0; i < int(shnum); i++ {
		entryOffset := shoff + uint64(i)*uint64(shentsize)
		buf, err := safeSlice(raw, entryOffset, structSize)
		if err != nil {
			return nil, fmt.Errorf("failed to read section header %d: %w", i, err)
		}

		r := bytes.NewReader(buf)
		if is32 {
			var sh32 sectionHeader32
			if err := binary.Read(r, endianness, &sh32); err != nil {
				return nil, fmt.Errorf("failed to read section header %d: %w", i, err)
			}
			shs[i] = convertToSectionHeader(&sh32)
		} else {
			var sh SectionHeader
			if err := binary.Read(r, endianness, &sh); err != nil {
				return nil, fmt.Errorf("failed to read section header %d: %w", i, err)
			}
			shs[i] = sh
		}
	}

	return shs, nil
}

func parseProgramHeaders(raw []byte, endianness binary.ByteOrder, is32 bool, phoff uint64, phnum, phentsize uint16) ([]ProgramHeader, error) {
	structSize := sizeProgramHeader64
	if is32 {
		structSize = sizeProgramHeader32
	}
	if uint64(phentsize) < structSize {
		return nil, fmt.Errorf("invalid program header entry size: %d", phentsize)
	}

	phs := make([]ProgramHeader, phnum)
	for i := 0; i < int(phnum); i++ {
		entryOffset := phoff + uint64(i)*uint64(phentsize)
		buf, err := safeSlice(raw, entryOffset, structSize)
		if err != nil {
			return nil, fmt.Errorf("failed to read program header %d: %w", i, err)
		}

		r := bytes.NewReader(buf)
		if is32 {
			var ph32 programHeader32
			if err := binary.Read(r, endianness, &ph32); err != nil {
				return nil, fmt.Errorf("failed to read program header %d: %w", i, err)
			}
			phs[i] = convertToProgramHeader(&ph32)
		} else {
			var ph ProgramHeader
			if err := binary.Read(r, endianness, &ph); err != nil {
				return nil, fmt.Errorf("failed to read program header %d: %w", i, err)
			}
			phs[i] = ph
		}
	}

	return phs, nil
}

func New(raw []byte) (*File, error) {
	if len(raw) < int(MAGIC_SIZE) {
		return nil, fmt.Errorf("insufficient elf format size: %d", len(raw))
	}

	if !bytes.Equal(raw[:MAGIC_SIZE], []byte(ELF_MAGIC)) {
		return nil, fmt.Errorf("invalid magic number: %s", raw[:MAGIC_SIZE])
	}

	if len(raw) <= int(EI_DATA) {
		return nil, fmt.Errorf("insufficient elf format size: %d", len(raw))
	}

	var endianness binary.ByteOrder
	switch raw[EI_DATA] {
	case 1:
		endianness = binary.LittleEndian
	case 2:
		endianness = binary.BigEndian
	default:
		return nil, fmt.Errorf("invalid endianness: %d", raw[EI_DATA])
	}

	if raw[EI_CLASS] != 1 && raw[EI_CLASS] != 2 {
		return nil, fmt.Errorf("invalid elf class: %d", raw[EI_CLASS])
	}
	is32 := raw[EI_CLASS] == 1

	var header ELFHeader
	r := bytes.NewReader(raw)
	if is32 {
		header32 := new(elfHeader32)
		if err := binary.Read(r, endianness, header32); err != nil {
			return nil, fmt.Errorf("failed to read elf header: %w", err)
		}
		header = convertToELFHeader(header32)
	} else {
		if err := binary.Read(r, endianness, &header); err != nil {
			return nil, fmt.Errorf("failed to read elf header: %w", err)
		}
	}

	e := &File{
		Header:     &header,
		Endianness: endianness,
		Raw:        raw,
	}

	if header.Shnum == 0 {
		e.Sections = make([]*Section, 0)
	} else {
		shs, err := parseSectionHeaders(raw, endianness, is32, header.Shoff, header.Shnum, header.Shentsize)
		if err != nil {
			return nil, err
		}

		if header.Shstrndx == SHN_XINDEX {
			return nil, fmt.Errorf("unsupported extended section header string table index (SHN_XINDEX)")
		}
		if header.Shstrndx >= header.Shnum {
			return nil, fmt.Errorf("invalid section header string table index: %d", header.Shstrndx)
		}
		strtabHeader := shs[header.Shstrndx]
		strtab, err := safeSlice(raw, strtabHeader.Offset, strtabHeader.Size)
		if err != nil {
			return nil, fmt.Errorf("invalid section header string table: %w", err)
		}

		e.Sections = make([]*Section, header.Shnum)
		for i := 0; i < len(shs); i++ {
			name, err := sectionName(strtab, shs[i].Name)
			if err != nil {
				return nil, err
			}

			var sr []byte
			if shs[i].Type != SHT_NOBITS {
				sr, err = safeSlice(raw, shs[i].Offset, shs[i].Size)
				if err != nil {
					return nil, fmt.Errorf("invalid section %d (%s) body: %w", i, name, err)
				}
			} else {
				sr = make([]byte, 0)
			}

			e.Sections[i] = &Section{
				Header: shs[i],
				Name:   name,
				Raw:    sr,
			}
		}
	}

	if header.Phnum == 0 {
		e.Segments = make([]*Segment, 0)
	} else {
		phs, err := parseProgramHeaders(raw, endianness, is32, header.Phoff, header.Phnum, header.Phentsize)
		if err != nil {
			return nil, err
		}

		e.Segments = make([]*Segment, header.Phnum)
		for i := 0; i < len(phs); i++ {
			sgr, err := safeSlice(raw, phs[i].Offset, phs[i].Filesz)
			if err != nil {
				return nil, fmt.Errorf("invalid segment %d body: %w", i, err)
			}

			e.Segments[i] = &Segment{
				Header: phs[i],
				Raw:    sgr,
			}
		}
	}

	return e, nil
}

// SectionByName get a section by name.
func (e *File) SectionByName(name string) *Section {
	for _, s := range e.Sections {
		if s.Name == name {
			return s
		}
	}

	return nil
}

// SectionsByType get sections by type.
func (e *File) SectionsByType(sht SectionHeaderType) []*Section {
	var ss []*Section
	for _, s := range e.Sections {
		if s.Header.Type == sht {
			ss = append(ss, s)
		}
	}

	return ss
}

// SectionAt get a setcion by index.
func (e *File) SectionAt(n uint16) *Section {
	ss := e.Sections
	if n >= uint16(len(ss)) {
		return nil
	}

	return ss[n]
}

// SegmentsByType get segments by type.
func (e *File) SegmentsByType(pt ProgramHeaderType) []*Segment {
	var sgs []*Segment
	for _, sg := range e.Segments {
		if sg.Header.Type == pt {
			sgs = append(sgs, sg)
		}
	}

	return sgs
}

// SegmentAt get a segment by index.
func (e *File) SegmentAt(n uint16) *Segment {
	sgs := e.Segments
	if n >= uint16(len(sgs)) {
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
