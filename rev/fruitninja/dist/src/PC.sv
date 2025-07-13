import Common::*;

module PC (
    input  logic   clk,
    input  logic   rst,
    input  logic   stall,
    input  Signals i_signals,
    output Signals o_signals
);

    logic [31:0] mem[0:4096-1];
    initial $readmemh("rom_file.mem", mem);

    logic [31:0] pc = 0;
    logic started = 0;

    always @(posedge clk) begin
        if (rst) begin
            pc <= 0;
            o_signals.pc <= 0;
            o_signals.insn <= 'h13;
        end else begin
            if (i_signals.pcsel) begin
                // $display("accepting pc = %0x", i_signals.pc);
                o_signals.pc <= i_signals.pc;
                o_signals.insn <= mem[i_signals.pc>>2];
                pc <= i_signals.pc + 4;
            end else begin
                if (stall) begin

                end else begin
                    o_signals.pc <= pc;
                    o_signals.insn <= mem[pc>>2];
                    pc <= pc + 4;
                end
            end

            // $display("stall = %0d, pc = %0x", stall, pc);
        end
    end

endmodule
