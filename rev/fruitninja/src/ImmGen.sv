import Common::*;

module ImmGen (
    input  logic   clk,
    input  logic   rst,
    input  logic   stall,
    input  Signals i_buffer,
    output Signals o_signals
);

    Signals i_current;
    Signals i_signals;
    assign i_signals = stall ? i_current : i_buffer;

    Insn insn;
    assign insn = i_signals.insn;

    always_ff @(posedge clk) begin
        if (rst) begin
            o_signals.imm  <= 0;
            o_signals.jimm <= 0;
        end else begin
            if (!stall) begin
                i_current <= i_buffer;
            end

            case (insn.r.opcode)
                Opcode::RegImm: begin
                    case (insn.i.funct3)
                        'h1:     o_signals.imm <= 32'(insn.i.imm[4:0]);
                        'h5:     o_signals.imm <= 32'(insn.i.imm[4:0]);
                        default: o_signals.imm <= 32'(signed'(insn.i.imm));
                    endcase
                    // if (insn != 'h13) begin
                    //     $display("imm = %d", insn.i.imm);
                    // end
                end
                Opcode::Jal, Opcode::Jalr: begin
                    o_signals.imm <= 32'd4;
                end
                Opcode::Load: begin
                    o_signals.imm <= 32'(signed'(insn.i.imm));
                end
                Opcode::Store: begin
                    o_signals.imm <= 32'(signed'({insn.s.immhi, insn.s.immlo}));
                end
                Opcode::Lui, Opcode::Auipc: begin
                    o_signals.imm <= {insn.u.imm, 12'd0};
                end
                default: begin
                    o_signals.imm <= 0;
                end
            endcase

            case (insn.r.opcode)
                Opcode::Jalr: begin
                    o_signals.jimm <= 32'(signed'(insn.i.imm));
                end
                Opcode::Branch: begin
                    o_signals.jimm <= 32'(signed'({
                        insn.b.imm4, insn.b.imm3, insn.b.imm2, insn.b.imm1, 1'b0
                    }));
                end
                Opcode::Jal: begin
                    o_signals.jimm <= 32'(signed'({
                        insn.j.imm4, insn.j.imm3, insn.j.imm2, insn.j.imm1, 1'b0
                    }));
                end
                default: begin
                    o_signals.jimm <= 0;
                end
            endcase
        end
    end

endmodule
