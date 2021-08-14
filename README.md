# goelftools

goelftools is library written in Go for parsing ELF file.

This library is inspired by [pyelftools](https://github.com/eliben/pyelftools) and [rbelftools](https://github.com/david942j/rbelftools).

# Motivation
The motivation to develop this library from scratch is a comprehensive understanding of ELF file structure.

# Usage
View section names.
```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hnts/goelftools/elf"
)

func main() {
	file := "testdata/elf_linux_amd64"
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("failed to read %s: %s", file, err)
	}

	e, err := elf.New(b)
	if err != nil {
		log.Fatalf("failed to new elf file struct: %s", err)
	}

	ss := e.Sections
	for _, s := range ss {
		fmt.Println(s.Name)
	}
}
```

```bash
$ go run section_name.go | head -n10

.text
.rodata
.shstrtab
.typelink
.itablink
.gosymtab
.gopclntab
.go.buildinfo
.noptrdata
```

View assembly by using [goelftools](https://github.com/hnts/goelftools) and [gapstone](https://github.com/knightsc/gapstone).

Please note that the below code will not work without the [capstone](https://www.capstone-engine.org/download.html) library installed.

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hnts/goelftools/elf"
	"github.com/knightsc/gapstone"
)

func main() {
	file := "testdata/elf_linux_amd64"
	b, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("failed to read %s: %s", file, err)
	}

	e, err := elf.New(b)
	if err != nil {
		log.Fatalf("failed to new elf file struct: %s", err)
	}

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_64,
	)

	if err == nil {
		defer engine.Close()
		s := e.SectionByName(".text")
		if s == nil {
			log.Fatal(".text in not found")
		}

		insns, err := engine.Disasm(
			[]byte(s.Raw),
			0x10000,
			0,
		)

		if err == nil {
			for _, insn := range insns {
				fmt.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
			}
			return
		}
		log.Fatalf("Disassembly error: %v", err)
	}
	log.Fatalf("Failed to initialize engine: %v", err)
}
```

```
$ go run disas.go | head -n10
0x10000:        mov             rcx, qword ptr fs:[0xfffffffffffffff8]
0x10009:        cmp             rsp, qword ptr [rcx + 0x10]
0x1000d:        jbe             0x10047
0x1000f:        sub             rsp, 0x18
0x10013:        mov             qword ptr [rsp + 0x10], rbp
0x10018:        lea             rbp, [rsp + 0x10]
0x1001d:        nop             dword ptr [rax]
0x10020:        call            0x107a0
0x10025:        mov             rax, qword ptr [rsp + 0x20]
0x1002a:        mov             qword ptr [rsp], rax
```

# Precautions
goelftools is under development.

If you want to parse ELF file in earnest by using Go, I recommend that you use [debug/elf](https://github.com/golang/go/tree/master/src/debug/elf) library.