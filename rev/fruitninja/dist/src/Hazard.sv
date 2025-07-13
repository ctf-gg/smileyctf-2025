import Common::*;

module Hazard (
    input  logic   clk,
    input  logic   rst,
    input  Signals i_buffer,
    input  Signals decode_signals,
    input  Signals alu_signals,
    input  Signals mem_signals,
    input  Signals wb_signals,
    output logic   o_stall,
    output logic   o_flush
);

    Signals i_current;
    Signals i_signals;
    assign i_signals = o_stall ? i_current : i_buffer;

    Insn insn;
    assign insn = i_signals.insn;

    logic [4:0] rs1;
    logic [4:0] rs2;
    logic branch;

    always_comb begin
        case (insn.r.opcode)
            Opcode::RegReg: begin
                rs1 = insn.r.rs1;
                rs2 = insn.r.rs2;
            end
            Opcode::RegImm, Opcode::Jalr, Opcode::Load: begin
                rs1 = insn.i.rs1;
                rs2 = 0;
            end
            Opcode::Branch: begin
                rs1 = insn.b.rs1;
                rs2 = insn.b.rs2;
            end
            Opcode::Store: begin
                rs1 = insn.s.rs1;
                rs2 = insn.s.rs2;
            end
            Opcode::Jal, Opcode::Auipc, Opcode::Lui: begin
                rs1 = 0;
                rs2 = 0;
            end
            default: begin
                rs1 = 0;
                rs2 = 0;
            end
        endcase

        case (insn.r.opcode)
            Opcode::Jal, Opcode::Jalr, Opcode::Branch: begin
                branch = 1;
            end
            default: begin
                branch = 0;
            end
        endcase
    end

    always_ff @(posedge clk) begin
        if (rst) begin
            o_stall <= 0;
            o_flush <= 0;
        end else begin
            // $display("pc = %0x", i_signals.pc);

            if (!o_stall) begin
                i_current <= i_buffer;
            end

            if (
                (
                    decode_signals.wback &&
                    (decode_signals.wreg != 0) &&
                    (rs1 == decode_signals.wreg || rs2 == decode_signals.wreg)
                )
                || (
                    alu_signals.wback &&
                    (alu_signals.wreg != 0) &&
                    (rs1 == alu_signals.wreg || rs2 == alu_signals.wreg)
                )
                || (
                    mem_signals.wback &&
                    (mem_signals.wreg != 0) &&
                    (rs1 == mem_signals.wreg || rs2 == mem_signals.wreg)
                )
                || (decode_signals.cond != Never)
                || (alu_signals.cond != Never)
                || (mem_signals.cond != Never)
                || (wb_signals.cond != Never && wb_signals.pcsel == 0)
                ) begin
                // $display("decode signals.cond = %0d", decode_signals.cond);
                // $display("alu    signals.cond = %0d", alu_signals.cond);
                // $display("mem    signals.cond = %0d", mem_signals.cond);
                // $display("rs1 = %0d, rs2 = %0d", rs1, rs2);
                // $display("stalling with insn = %0x", insn);
                o_stall <= 1;
            end else begin
                o_stall <= 0;
            end

            if ((decode_signals.cond != Never)
                || (alu_signals.cond != Never)
                || (mem_signals.cond != Never)
            ) begin
                o_flush <= 1;
            end else begin
                o_flush <= 0;
            end
        end
    end

endmodule
