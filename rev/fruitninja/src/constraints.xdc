set_property -dict {LOC W5  IOSTANDARD LVCMOS18} [get_ports {i_clk}]
set_property -dict {LOC U16 IOSTANDARD LVCMOS18} [get_ports {o_clk}]
set_property -dict {LOC V17 IOSTANDARD LVCMOS18} [get_ports {i_rst}]
set_property -dict {LOC W18 IOSTANDARD LVCMOS18} [get_ports {leds[0]}]
set_property -dict {LOC U15 IOSTANDARD LVCMOS18} [get_ports {leds[1]}]
set_property -dict {LOC U14 IOSTANDARD LVCMOS18} [get_ports {leds[2]}]
set_property -dict {LOC V14 IOSTANDARD LVCMOS18} [get_ports {leds[3]}]
set_property -dict {LOC V13 IOSTANDARD LVCMOS18} [get_ports {leds[4]}]
set_property -dict {LOC V3  IOSTANDARD LVCMOS18} [get_ports {leds[5]}]
set_property -dict {LOC W3  IOSTANDARD LVCMOS18} [get_ports {leds[6]}]
set_property -dict {LOC U3  IOSTANDARD LVCMOS18} [get_ports {leds[7]}]
set_property -dict {LOC P3  IOSTANDARD LVCMOS18} [get_ports {leds[8]}]
set_property -dict {LOC N3  IOSTANDARD LVCMOS18} [get_ports {leds[9]}]
set_property -dict {LOC P1  IOSTANDARD LVCMOS18} [get_ports {leds[10]}]
set_property -dict {LOC L1  IOSTANDARD LVCMOS18} [get_ports {leds[11]}]

# hsync = P19
# vsync = R19
# red   = G19, H19, J19, N19
# green = J17, H17, G17, D17
# blue  = N18, L18, K18, J18

set_property -dict {LOC P19 IOSTANDARD LVCMOS18} [get_ports {vga_hsync}]
set_property -dict {LOC R19 IOSTANDARD LVCMOS18} [get_ports {vga_vsync}]

set_property -dict {LOC G19 IOSTANDARD LVCMOS18} [get_ports {vga_r[0]}]
set_property -dict {LOC H19 IOSTANDARD LVCMOS18} [get_ports {vga_r[1]}]
set_property -dict {LOC J19 IOSTANDARD LVCMOS18} [get_ports {vga_r[2]}]
set_property -dict {LOC N19 IOSTANDARD LVCMOS18} [get_ports {vga_r[3]}]

set_property -dict {LOC J17 IOSTANDARD LVCMOS18} [get_ports {vga_g[0]}]
set_property -dict {LOC H17 IOSTANDARD LVCMOS18} [get_ports {vga_g[1]}]
set_property -dict {LOC G17 IOSTANDARD LVCMOS18} [get_ports {vga_g[2]}]
set_property -dict {LOC D17 IOSTANDARD LVCMOS18} [get_ports {vga_g[3]}]

set_property -dict {LOC N18 IOSTANDARD LVCMOS18} [get_ports {vga_b[0]}]
set_property -dict {LOC L18 IOSTANDARD LVCMOS18} [get_ports {vga_b[1]}]
set_property -dict {LOC K18 IOSTANDARD LVCMOS18} [get_ports {vga_b[2]}]
set_property -dict {LOC J18 IOSTANDARD LVCMOS18} [get_ports {vga_b[3]}]

set_property -dict {LOC E19 IOSTANDARD LVCMOS18} [get_ports {o_stall}]

# set_property -dict {LOC V17 IOSTANDARD LVCMOS18} [get_ports {i_switches[15]}]
set_property -dict {LOC V16 IOSTANDARD LVCMOS18} [get_ports {i_switches[14]}]
set_property -dict {LOC W16 IOSTANDARD LVCMOS18} [get_ports {i_switches[13]}]
set_property -dict {LOC W17 IOSTANDARD LVCMOS18} [get_ports {i_switches[12]}]
set_property -dict {LOC W15 IOSTANDARD LVCMOS18} [get_ports {i_switches[11]}]
set_property -dict {LOC V15 IOSTANDARD LVCMOS18} [get_ports {i_switches[10]}]
set_property -dict {LOC W14 IOSTANDARD LVCMOS18} [get_ports {i_switches[9]}]
set_property -dict {LOC W13 IOSTANDARD LVCMOS18} [get_ports {i_switches[8]}]
set_property -dict {LOC V2  IOSTANDARD LVCMOS18} [get_ports {i_switches[7]}]
set_property -dict {LOC T3  IOSTANDARD LVCMOS18} [get_ports {i_switches[6]}]
set_property -dict {LOC T2  IOSTANDARD LVCMOS18} [get_ports {i_switches[5]}]
set_property -dict {LOC R3  IOSTANDARD LVCMOS18} [get_ports {i_switches[4]}]
set_property -dict {LOC W2  IOSTANDARD LVCMOS18} [get_ports {i_switches[3]}]
set_property -dict {LOC U1  IOSTANDARD LVCMOS18} [get_ports {i_switches[2]}]
set_property -dict {LOC T1  IOSTANDARD LVCMOS18} [get_ports {i_switches[1]}]
set_property -dict {LOC R2  IOSTANDARD LVCMOS18} [get_ports {i_switches[0]}]

set_property -dict {LOC W19 IOSTANDARD LVCMOS18} [get_ports {i_buttons[0]}]
set_property -dict {LOC T18 IOSTANDARD LVCMOS18} [get_ports {i_buttons[1]}]
set_property -dict {LOC T17 IOSTANDARD LVCMOS18} [get_ports {i_buttons[2]}]
set_property -dict {LOC U17 IOSTANDARD LVCMOS18} [get_ports {i_buttons[3]}]
set_property -dict {LOC U18 IOSTANDARD LVCMOS18} [get_ports {i_buttons[4]}]

set_property -dict {LOC B16 IOSTANDARD LVCMOS18} [get_ports {gpio[0]}]
set_property -dict {LOC B15 IOSTANDARD LVCMOS18} [get_ports {gpio[1]}]
set_property -dict {LOC A16 IOSTANDARD LVCMOS18} [get_ports {gpio[2]}]
set_property -dict {LOC A14 IOSTANDARD LVCMOS18} [get_ports {gpio[3]}]