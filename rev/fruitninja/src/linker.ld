MEMORY {
    rom (rx) : ORIGIN = 0x10000000,   LENGTH = 0x0004000
    ram (rw) : ORIGIN = 0x00000000,   LENGTH = 0x2000000
}

SECTIONS {
    .text    : {
        KEEP(*(.entry))
        *(.text.*)
    } > rom
    .initram : {
        *(.initram)
        *(.rodata)
        *(.rodata.*)
        *(.data)
        *(.data.*)
        *(.bss)
        *(.bss.*)
    } > ram
}