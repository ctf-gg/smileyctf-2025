import Common::*;

module CPU (
    input logic i_clk,
    input logic i_rst,
    input logic [14:0] i_switches,
    input logic [4:0] i_buttons,
    output logic [3:0] gpio,

    output logic [11:0] leds,
    output logic o_clk,

    output logic vga_hsync,
    output logic vga_vsync,
    output logic [3:0] vga_r,
    output logic [3:0] vga_g,
    output logic [3:0] vga_b,
    output logic o_stall,

    output logic o_hypervisor_call
);

`ifdef SIMULATION
    logic clk;
    assign clk = i_clk;
`else

    logic clk = 0;
    always @(posedge i_clk) begin
        clk <= !clk;
    end
`endif

    logic rst = 1;
    always @(posedge clk) begin
        rst <= i_rst;
    end

    // constant 10 khz timer
    // depends on the external 100 mhz clock and not the internal cpu clock
    logic [31:0] timer = 0;
    int timer_counter = 0;
    always @(posedge i_clk) begin
        if (timer_counter == 10 * 1000 - 1) begin
            timer_counter <= 0;
            timer <= timer + 1;
        end else begin
            timer_counter <= timer_counter + 1;
        end
    end

    logic [31:0] debug;
    assign leds[10:0] = debug[10:0];

    logic stall;
    logic flush;

    assign o_stall = stall;

    Signals fetch_signals;

    Signals intermediate_decode_signals_regs;
    Signals intermediate_decode_signals_con;
    Signals intermediate_decode_signals_imm_gen;

    Signals decode_signals;
    Signals alu_signals;
    Signals mem_signals;
    Signals wb_signals;

    PC pc_i (
        .clk(clk),
        .rst(rst),
        .stall(stall),
        .i_signals(wb_signals),
        .o_signals(fetch_signals)
    );

    /* verilator lint_off MULTIDRIVEN */

    Register regs_i (
        .clk(clk),
        .rst(rst),
        .stall(stall),
        .i_buffer(fetch_signals),
        .i_wback(wb_signals.wback),
        .i_wreg(wb_signals.wreg),
        .i_wdata(wb_signals.wdata[31:0]),
        .o_signals(intermediate_decode_signals_regs),
        .o_debug(debug)
    );

    Control con_i (
        .clk(clk),
        .rst(rst),
        .stall(stall),
        .flush(flush),
        .i_buffer(fetch_signals),
        .o_signals(intermediate_decode_signals_con)
    );

    ImmGen imm_gen_i (
        .clk(clk),
        .rst(rst),
        .stall(stall),
        .i_buffer(fetch_signals),
        .o_signals(intermediate_decode_signals_imm_gen)
    );

    Hazard hazard_i (
        .clk(clk),
        .rst(rst),
        .o_stall(stall),
        .o_flush(flush),
        .i_buffer(fetch_signals),
        .decode_signals(decode_signals),
        .alu_signals(alu_signals),
        .mem_signals(mem_signals),
        .wb_signals(wb_signals)
    );

    assign decode_signals.pc    = intermediate_decode_signals_con.pc;
    assign decode_signals.reg1  = intermediate_decode_signals_regs.reg1;
    assign decode_signals.reg2  = intermediate_decode_signals_regs.reg2;
    assign decode_signals.op    = intermediate_decode_signals_con.op;
    assign decode_signals.imm   = intermediate_decode_signals_imm_gen.imm;
    assign decode_signals.asel  = intermediate_decode_signals_con.asel;
    assign decode_signals.bsel  = intermediate_decode_signals_con.bsel;
    assign decode_signals.pcsel = intermediate_decode_signals_con.pcsel;
    assign decode_signals.cond  = stall ? Never : intermediate_decode_signals_con.cond;
    assign decode_signals.jimm  = intermediate_decode_signals_imm_gen.jimm;
    assign decode_signals.memr  = stall ? 0 : intermediate_decode_signals_con.memr;
    assign decode_signals.memw  = stall ? 0 : intermediate_decode_signals_con.memw;
    assign decode_signals.memt  = intermediate_decode_signals_con.memt;
    assign decode_signals.wback = stall ? 0 : intermediate_decode_signals_con.wback;
    assign decode_signals.wreg  = intermediate_decode_signals_con.wreg;

    ALU alu_i (
        .clk(clk),
        .rst(rst),
        .i_signals(decode_signals),
        .o_signals(alu_signals)
    );

    RAM ram_i (
        .clk(clk),
        .rst(rst),
        .i_switches(i_switches),
        .i_buttons(i_buttons),
        .i_timer(timer),
        .gpio(gpio),
        .o_hypervisor_call(o_hypervisor_call),
        .i_signals(alu_signals),
        .o_signals(mem_signals)
    );

    WriteBack write_back_i (
        .clk(clk),
        .rst(rst),
        .i_signals(mem_signals),
        .o_signals(wb_signals)
    );

endmodule
