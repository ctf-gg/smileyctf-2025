import Common::*;

module Register (
    input logic          clk,
    input logic          rst,
    input logic          stall,
    input Signals        i_buffer,
    input logic          i_wback,
    input logic   [ 4:0] i_wreg,
    input logic   [31:0] i_wdata,

    output Signals        o_signals,
    output logic   [31:0] o_debug
);

    logic [31:0] registers[31:0];
    assign o_debug = registers[10];

    Signals i_current;
    Signals i_signals;
    assign i_signals = stall ? i_current : i_buffer;

    Insn insn;
    assign insn = i_signals.insn;

    always_ff @(posedge clk) begin
        if (rst) begin
            for (int i = 0; i < 32; i++) begin
                registers[i] <= 0;
            end
        end else begin
            if (i_wback) begin
                if (i_wreg == 0) begin
                    registers[i_wreg] <= 0;
                end else begin
                    // if (i_wreg == 1) begin
                    //     $display("regs[%2d] = 0x%0x", i_wreg, i_wdata);
                    // end
                    registers[i_wreg] <= i_wdata;
                end
            end
        end
    end

    logic [31:0] reg1;
    logic [31:0] reg2;
    always_comb begin
        if (i_wreg != 0 && i_wback == 1 && insn.r.rs1 == i_wreg) begin
            reg1 = i_wdata;
        end else begin
            reg1 = registers[insn.r.rs1];
        end

        if (i_wreg != 0 && i_wback == 1 && insn.r.rs2 == i_wreg) begin
            reg2 = i_wdata;
        end else begin
            reg2 = registers[insn.r.rs2];
        end
    end

    always_ff @(posedge clk) begin
        if (!stall) begin
            i_current <= i_buffer;
        end

        if (rst) begin
            o_signals.reg1 <= 0;
            o_signals.reg2 <= 0;
        end else begin
            // if (insn != 'h13) begin
            //     $display("rs1 = %d", insn.r.rs1);
            //     $display("registers[rs1] = %x", registers[insn.r.rs1]);
            // end

            // `log(("reg insn = %08x", insn));
            case (insn.r.opcode)
                Opcode::RegReg: begin
                    o_signals.reg1 <= reg1;
                    o_signals.reg2 <= reg2;
                end
                Opcode::RegImm: begin
                    // if (insn.i.rd != 0) begin
                    //     //     `log(("reg insn = %08x", insn));
                    //     `log(("wdata = %08x", i_wdata));
                    //     `log(("wreg = %0d", i_wreg));
                    //     `log(("reg[wreg] = %08x", registers[i_wreg]));
                    // end
                    // `log(("rd = %0d, rs1 = %0d", insn.i.rd, insn.i.rs1));
                    o_signals.reg1 <= reg1;
                    o_signals.reg2 <= 0;
                end
                Opcode::Branch: begin
                    o_signals.reg1 <= reg1;
                    o_signals.reg2 <= reg2;
                end
                Opcode::Jalr: begin
                    // `log(("\tjalr rs = %d", insn.i.rs1));
                    // `log(("\trs      = %08x", registers[insn.i.rs1]));
                    o_signals.reg1 <= reg1;
                    o_signals.reg2 <= 0;
                end
                Opcode::Load: begin
                    o_signals.reg1 <= reg1;
                    o_signals.reg2 <= 0;
                end
                Opcode::Store: begin
                    o_signals.reg1 <= reg1;
                    o_signals.reg2 <= reg2;
                end
                default: begin
                    o_signals.reg1 <= 0;
                    o_signals.reg2 <= 0;
                end
            endcase
        end

        // if (o_signals.rs1 != 0 || o_signals.rs2 != 0) begin
        //     `log(("rs1 = %02x, rs2 = %02x", o_signals.rs1, o_signals.rs2));
        // end
    end

endmodule
