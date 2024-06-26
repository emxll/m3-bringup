
.globl _start
.type _start, @function
_start:

adrp x2, exception_vector_el2

msr VBAR_EL2, x2
msr VBAR_EL1, x2

# set up stack and pray for no overflow
adrp x2, stack_top
add x2, x2, :lo12:stack_top

mov sp, x2

start_with_stack:

# save context
adrp x2, kernel_data
add x2, x2, :lo12:kernel_data

stp lr, x0, [x2]

mov x0, x1
bl set_output_buffer


adr x0, string_banner
bl puts


bl main


hook_exit:

# restore context
adrp x2, kernel_data
add x2, x2, :lo12:kernel_data

ldp lr, x0, [x2]

# unsetup stack
movz x1, #0
mov sp, x1

br lr

string_banner:
.asciz "output generated by hook:\n"






.align 12, 0
exception_vector_el2:
/* Same EL, SP 0 */
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
/* Same EL, Same SP */
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
/* Lower EL, Aarch64 */
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
/* Lower EL, Aarch32 */
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align	7
b		exception_handler_el2
.align 12, 0




.align 2
exception_handler_el2:

adr x0, string_exception_banner_el2
bl puts

b hook_exit


string_exception_banner_el2:
.asciz "\nexception taken to el: 2\n"






# general main function
# no args

.align 2
main:

str lr, [sp, #-0x10]!

bl frame_buffer_adventures
bl video_dump
bl sys_dump
bl el_dump
bl sp_dump

adr x0, string_before_error
bl puts

# crash here
# movz x0, #0
# ldr x0, [x0]

# hvc #0

adr x0, string_after_error
bl puts


ldr lr, [sp], #0x10

br lr

string_before_error:
.asciz "printing something before any exceptions occured\n"

string_after_error:
.asciz "printing something after a bad load\n"






.align 2
frame_buffer_adventures:

stp lr, x0, [sp, #-0x10]!
stp x1, x2, [sp, #-0x10]!


adrp x2, kernel_data
add x2, x2, :lo12:kernel_data

ldr x1, [x2, #8]
ldr x1, [x1, #0x28]

mov x2, #0x10000

movz x0, #0
sub x0, x0, #1

frame_buffer_adventures_loop:
str x0, [x1], #8

sub x2, x2, #1
cbnz x2, frame_buffer_adventures_loop


ldp x1, x2, [sp], #0x10
ldp lr, x0, [sp], #0x10

br lr






# dump video info
# no args

.align 2
video_dump:

stp lr, x0, [sp, #-0x10]!
stp x1, x2, [sp, #-0x10]!

# load boot info
adrp x2, kernel_data
add x2, x2, :lo12:kernel_data

ldr x1, [x2, #8]

adr x0, string_boot_info
bl puts

mov x0, x1
bl hex_num

# Boot_Video
add x1, x1, #0x28

adr x0, string_v_baseAddr
bl puts

ldr x0, [x1]
bl hex_num

adr x0, string_v_display
bl puts

ldr x0, [x1, #0x8]
bl hex_num

adr x0, string_v_rowBytes
bl puts

ldr x0, [x1, #0x10]
bl hex_num

adr x0, string_v_width
bl puts

ldr x0, [x1, #0x18]
bl hex_num

adr x0, string_v_height
bl puts

ldr x0, [x1, #0x20]
bl hex_num

adr x0, string_v_depth
bl puts

ldr x0, [x1, #0x28]
bl hex_num

mov x0, 0x0a
bl putc

ldp x1, x2, [sp], #0x10
ldp lr, x0, [sp], #0x10

br lr

string_boot_info:
.asciz "boot_info: "

string_v_baseAddr:
.asciz "\nv_baseAddr: "

string_v_display:
.asciz "\nv_display: "

string_v_rowBytes:
.asciz "\nv_rowBytes: "

string_v_width:
.asciz "\nv_width: "

string_v_height:
.asciz "\nv_height: "

string_v_depth:
.asciz "\nv_depth: "






# dump system info
# no args

.align 2
sys_dump:

stp lr, x0, [sp, #-0x10]!

adr x0, string_SCTLR_EL2
bl puts

mrs x0, SCTLR_EL2
bl hex_num

adr x0, string_SCTLR_EL1
bl puts

mrs x0, SCTLR_EL1
bl hex_num

mov x0, 0x0a
bl putc

ldp lr, x0, [sp], #0x10

br lr

string_SCTLR_EL2:
.asciz "SCTLR_EL2: "

string_SCTLR_EL1:
.asciz "\nSCTLR_EL1: "





# dump exception level info
# no args

.align 2
el_dump:

stp lr, x0, [sp, #-0x10]!

adr x0, string_CurrentEL
bl puts

mrs x0, CurrentEL
bl hex_num

adr x0, string_VBAR_EL1
bl puts

mrs x0, VBAR_EL1
bl hex_num

adr x0, string_VBAR_EL2
bl puts

mrs x0, VBAR_EL2
bl hex_num

mov x0, 0x0a
bl putc

ldp lr, x0, [sp], #0x10

br lr

string_CurrentEL:
.asciz "CurrentEL: "

string_VBAR_EL1:
.asciz "\nVBAR_EL1: "

string_VBAR_EL2:
.asciz "\nVBAR_EL2: "






# dump stack pointer info
# no args

.align 2
sp_dump:

stp lr, x0, [sp, #-0x10]!

adr x0, string_SPSel
bl puts

mrs x0, SPSel
bl hex_num

adr x0, string_SP_EL0
bl puts

mrs x0, SP_EL0
bl hex_num

adr x0, string_SP_EL1
bl puts

mrs x0, SP_EL1
bl hex_num

adr x0, string_sp
bl puts

mov x0, sp
bl hex_num

mov x0, 0x0a
bl putc

ldp lr, x0, [sp], #0x10

br lr

string_SPSel:
.asciz "SPSel: "

string_SP_EL0:
.asciz "\nSP_EL0: "

string_SP_EL1:
.asciz "\nSP_EL1: "

string_sp:
.asciz "\nsp: "






# args: 
# x0 (q): number to print as hex

.align 2
hex_num:

stp lr, x1, [sp, #-0x10]!
stp x2, x3, [sp, #-0x10]!
str x4, [sp, #-0x10]!

# value
mov x4, x0

# counter
movz x2, 0x10

adrp x3, hex_alphabet
add x3, x3, :lo12:hex_alphabet

hex_num_loop:

# bits to shift value by
sub x1, x2, #1
lsl x1, x1, #2

# shift value and mask
lsr x1, x4, x1
and x1, x1, #0xf

# load character and print
ldrb w0, [x3, x1]

bl putc

subs x2, x2, #1
cbnz x2, hex_num_loop

ldr x4, [sp], #0x10
ldp x2, x3, [sp], #0x10
ldp lr, x1, [sp], #0x10

br lr


hex_alphabet:
.ascii "0123456789abcdef"



# args:
# x0 (q): pointer to string
puts:

stp lr, x1, [sp, #-0x10]!

mov x1, x0

puts_loop:

# load byte
ldrb w0, [x1], #1
and x0, x0, #0xff

# exit if null byte
cbz x0, puts_exit

# print otherwise
bl putc

b puts_loop


puts_exit:
ldp lr, x1, [sp], #0x10

br lr






# args: 
# x0 (b): char to write
putc:

stp x1, x2, [sp, #-0x10]!

adrp x1, output_buffer
add x1, x1, :lo12:output_buffer

ldr x2, [x1]
# debug:
# mov x2, x26

strb w0, [x2], #1


str x2, [x1]
# debug:
# mov x26, x2

ldp x1, x2, [sp], #0x10

br lr





set_output_buffer:

str x1, [sp, #-0x10]!

adrp x1, output_buffer
add x1, x1, :lo12:output_buffer

str x0, [x1]

ldr x1, [sp], #0x10

br lr





.align 3

output_buffer:
.quad 0



.align 4
kernel_data:
.quad 0
.quad 0



.align 4
stack_bottom:

# 8 pages
.rept   0x1000
.quad   0
.endr

stack_top: