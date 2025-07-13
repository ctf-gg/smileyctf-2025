MEMORY {
    rom (rx) : ORIGIN = 0x010000000, LENGTH = 0x400000
    ram (rw) : ORIGIN = 0x000000000, LENGTH = 0x400000
}

SECTIONS {
    .text    : {
        KEEP(*(.entry))
        *(.text.*)
    } > rom
    .initram : {
        *(.rodata)
        *(.rodata.*)
        *(.data)
        *(.data.*)
        *(.bss)
        *(.bss.*)
    } > ram
}