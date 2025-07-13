package Opcode;
    typedef enum logic [6:0] {
        RegImm = 7'b00_100_11,
        RegReg = 7'b01_100_11,
        Load   = 7'b00_000_11,
        Store  = 7'b01_000_11,
        Branch = 7'b11_000_11,
        Jal    = 7'b11_011_11,
        Jalr   = 7'b11_001_11,
        Lui    = 7'b01_101_11,
        Auipc  = 7'b00_101_11
    } Opcode;
endpackage

package Op;
    typedef enum {
        Add,
        Sub,
        USub,
        Xor,
        Or,
        And,
        Shl,
        Shr,
        Asr,
        Slt,
        USlt
    } Operation;
endpackage

package Mem;
    // must be power of 2 aligned
    logic [31:0] framebuffer = 'h1000000;
endpackage

package Common;
    typedef struct packed {
        logic [6:0] funct7;
        logic [4:0] rs2;
        logic [4:0] rs1;
        logic [2:0] funct3;
        logic [4:0] rd;
        logic [6:0] opcode;
    } RType;

    typedef struct packed {
        logic [11:0] imm;
        logic [4:0]  rs1;
        logic [2:0]  funct3;
        logic [4:0]  rd;
        logic [6:0]  opcode;
    } IType;

    typedef struct packed {
        logic [6:0] immhi;
        logic [4:0] rs2;
        logic [4:0] rs1;
        logic [2:0] funct3;
        logic [4:0] immlo;
        logic [6:0] opcode;
    } SType;

    typedef struct packed {
        logic imm4;
        logic [5:0] imm2;
        logic [4:0] rs2;
        logic [4:0] rs1;
        logic [2:0] funct3;
        logic [3:0] imm1;
        logic imm3;
        logic [6:0] opcode;
    } BType;

    typedef struct packed {
        logic [19:0] imm;
        logic [4:0]  rd;
        logic [6:0]  opcode;
    } UType;

    typedef struct packed {
        logic imm4;
        logic [9:0] imm1;
        logic imm2;
        logic [7:0] imm3;
        logic [4:0] rd;
        logic [6:0] opcode;
    } JType;

    typedef union packed {
        RType r;
        IType i;
        SType s;
        BType b;
        UType u;
        JType j;
    } Insn;

    typedef enum {
        Register,
        Immediate,
        ProgramCounter
    } Selector;

    typedef struct {
        logic zero;
        logic carry;
    } Flags;

    typedef enum {
        Zero,
        NotZero,
        Carry,
        NotCarry,
        Never,
        Always
    } Condition;

    typedef enum {
        LoadByte,
        LoadHalf,
        LoadWord,
        ULoadByte,
        ULoadHalf,
        StoreByte,
        StoreHalf,
        StoreWord
    } MemType;

    typedef struct {
        logic [31:0] pc;
        Insn insn;

        logic [4:0]   rs1;
        logic [4:0]   rs2;
        logic [31:0]  reg1;
        logic [31:0]  reg2;
        Op::Operation op;
        logic [31:0]  imm;

        Selector asel;
        Selector bsel;
        logic pcsel;

        Flags flags;
        Condition cond;

        logic [31:0] jimm;
        logic [31:0] branch;

        logic   memr;
        logic   memw;
        MemType memt;

        logic wback;
        logic [4:0] wreg;
        logic [32:0] wdata;
    } Signals;

`ifdef SIMULATION

    `define err(ARGS) \
    $error("%s", $sformatf ARGS )

    `define log(ARGS) \
    $display("%s", $sformatf ARGS )

`else

    `define err(ARGS)
    `define log(ARGS)

`endif

endpackage
