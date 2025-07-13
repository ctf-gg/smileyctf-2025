import Common::*;

module WriteBack (
    input logic   clk,
    input logic   rst,
    input Signals i_signals,

    output Signals o_signals
);

    logic pcsel;

    always_comb begin
        case (i_signals.cond)
            Zero:     pcsel = (i_signals.flags.zero == 1);
            NotZero:  pcsel = (i_signals.flags.zero == 0);
            Carry:    pcsel = (i_signals.flags.carry == 1);
            NotCarry: pcsel = (i_signals.flags.carry == 0);
            Always:   pcsel = 1;
            default:  pcsel = 0;
        endcase
    end

    always_ff @(posedge clk) begin
        if (rst) begin
            o_signals.pcsel <= 0;
            o_signals.pc    <= 0;
            o_signals.cond  <= Never;
            o_signals.wback <= 0;
            o_signals.wreg  <= 0;
            o_signals.wdata <= 0;
        end else begin
            // if (i_signals.cond != Never) begin
            //     $display("cond = %0d", i_signals.cond);
            //     $display("wb pcsel = %0d", pcsel);
            //     $display("wb branch = %0x", i_signals.branch);
            // end
            o_signals.pcsel <= pcsel;
            o_signals.pc    <= i_signals.branch;
            o_signals.cond  <= i_signals.cond;
            o_signals.wback <= i_signals.wback;
            o_signals.wreg  <= i_signals.wreg;
            o_signals.wdata <= i_signals.wdata;
        end
    end

endmodule
