#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

# scancodes: https://www.win.tue.nl/~aeb/linux/kbd/scancodes.html

# https://wiki.osdev.org/USB_Human_Interface_Devices
# Bit	Bit Length	Description
# 0	1	Left Ctrl.
# 1	1	Left Shift.
# 2	1	Left Alt.
# 3	1	Left GUI (Windows/Super key.)
# 4	1	Right Ctrl.
# 5	1	Right Shift.
# 6	1	Right Alt.
# 7	1	Right GUI (Windows/Super key.)

LEFT_CTRL = 0x1
LEFT_SHIFT = 0x02
LEFT_ALT = 0x04
LEFT_WIN = 0x08
RIGHT_CTRL = 0x10
RIGHT_SHIFT = 0x20
ALT_GRAPHIC = 0x40
RIGHT_WIN = 0x80

BEPO = {
    0x04:['a', 'A', 'æ'],
    0x05:['k', 'K', '~'], #TODO next char
    0x06:['x', 'X', '}'],
    0x07:['i', 'I', '¨'], #TODO next char
    0x08:['p', 'P', '&'],
    0x09:['e', 'E', '€'],
    0x0A:[',', ';', ''],
    0x0B:['c', 'C', ''],
    0x0C:['d', 'D', ''],
    0x0D:['t', 'T', ''],
    0x0E:['s', 'S', ''],
    0x0F:['r', 'R', ''],
    0x10:['q', 'Q', ''],
    0x11:[',', '?', ''],
    0x12:['l', 'L', ''],
    0x13:['j', 'J', ''],
    0x14:['b', 'B', '|'],
    0x15:['o', 'O', 'œ'],
    0x16:['u', 'U', 'ù'],
    0x17:['è', 'È', ''],
    0x18:['v', 'V', ''],
    0x19:['.', ':', '…'],
    0x1A:['é', 'É', ''],
    0x1B:['y', 'Y', '{'],
    0x1C:['!', '^', ''],
    0x1D:['à', 'À', '\\'],
    0x1E:['"', '1', '_'],
    0x1F:['«', '2', '<'],
    0x20:['»', '3', '>'],
    0x21:['(', '4', '['],
    0x22:[')', '5', ']'],
    0x23:['@', '6', '^'],
    0x24:['+', '7', ''], 
    0x25:['-', '8', ''],
    0x26:['/', '9', ''],
    0x27:['*', '0', ''],
    0x28:['\n','\n', ''],
    0x29:['␛','␛', ''],
    0x2a:['\b', '\b', '\b'],
    0x2b:['\t', '\t', ''],
    0x2C:[' ', ' ', ''],
    0x2D:['=', '°', ''],#TODO next char
    0x2E:['%', '`', ''],#TODO next char
    0x2F:['z', 'Z', ''],
    0x30:['w', 'W', ''],
    0x32:['ç','Ç', ''],
    0x33:['n', 'N', ''],
    0x34:['m', 'M', ''],
    0x36:['g', 'G', ''],
    0x37:['h', 'H', ''],
    0x38:['f', 'F', ''],
    0x39:['⇪','⇪','⇪'], #CAPS LOCK
    0x4f:[u'→',u'→',u'→'],
    0x50:[u'←',u'←',u'←'],
    0x51:[u'↓',u'↓',u'↓'],
    0x52:[u'↑',u'↑',u'↑']
}

AZERTY = {
    0x04:['q', 'Q', ''],
    0x05:['b', 'B', ''],
    0x06:['c', 'C', ''],
    0x07:['d', 'D', ''],
    0x08:['e', 'E', '€'],
    0x09:['f', 'F', ''],
    0x0A:['g', 'G', ''],
    0x0B:['h', 'H', ''],
    0x0C:['i', 'I', ''],
    0x0D:['j', 'J', ''],
    0x0E:['k', 'K', ''],
    0x0F:['l', 'L', ''],
    0x10:[',', '?', ''],
    0x11:['n', 'N', ''],
    0x12:['o', 'O', ''],
    0x13:['p', 'P', ''],
    0x14:['a', 'A', ''],
    0x15:['r', 'R', ''],
    0x16:['s', 'S', ''],
    0x17:['t', 'T', ''],
    0x18:['u', 'U', ''],
    0x19:['v', 'V', ''],
    0x1A:['z', 'Z', ''],
    0x1B:['x', 'X', ''],
    0x1C:['y', 'Y', ''],
    0x1D:['w', 'W', ''],
    0x1E:['&', '1', ''],
    0x1F:['é', '2', '~'], # TODO tilde next letter
    0x20:['"', '3', '#'],
    0x21:['\'', '4', '{'],
    0x22:['(', '5', '['],
    0x23:['-', '6', '|'],
    0x24:['è', '7', '`'], #TODO backtick next letter
    0x25:['_', '8', '\\'],
    0x26:['ç', '9', '^'],
    0x27:['à', '0', '@'],
    0x28:['\n','\n', ''],
    0x29:['␛','␛', ''],
    0x2a:['\b', '\b', '\b'],
    0x2b:['\t','\t', ''],
    0x2C:[' ', ' ', ''],
    0x2D:[')', '°', ']'],
    0x2E:['=', '+', '}'],
    0x2F:['^', '¨', ''], #TODO next char
    0x30:['$', '£', '¤'],
    0x32:['*','µ', ''],
    0x33:['m', 'M', ''],
    0x34:['ù', '%', ''],
    0x36:[';', '.', ''],
    0x37:[':', '/', ''],
    0x38:['!', '§', ''],
    0x39:['⇪','⇪','⇪'], #CAPS LOCK
    0x4f:[u'→',u'→',u'→'],
    0x50:[u'←',u'←',u'←'],
    0x51:[u'↓',u'↓',u'↓'],
    0x52:[u'↑',u'↑',u'↑']
}

QWERTY = {
    0x04:['a', 'A', ''],
    0x05:['b', 'B', ''],
    0x06:['c', 'C', ''],
    0x07:['d', 'D', ''],
    0x08:['e', 'E', ''],
    0x09:['f', 'F', ''],
    0x0A:['g', 'G', ''],
    0x0B:['h', 'H', ''],
    0x0C:['i', 'I', ''],
    0x0D:['j', 'J', ''],
    0x0E:['k', 'K', ''],
    0x0F:['l', 'L', ''],
    0x10:['m', 'M', ''],
    0x11:['n', 'N', ''],
    0x12:['o', 'O', ''],
    0x13:['p', 'P', ''],
    0x14:['q', 'Q', ''],
    0x15:['r', 'R', ''],
    0x16:['s', 'S', ''],
    0x17:['t', 'T', ''],
    0x18:['u', 'U', ''],
    0x19:['v', 'V', ''],
    0x1A:['w', 'W', ''],
    0x1B:['x', 'X', ''],
    0x1C:['y', 'Y', ''],
    0x1D:['z', 'Z', ''],
    0x1E:['1', '!', ''],
    0x1F:['2', '@', ''],
    0x20:['3', '#', ''],
    0x21:['4', '$', ''],
    0x22:['5', '%', ''],
    0x23:['6', '^', ''],
    0x24:['7', '&', ''],
    0x25:['8', '*', ''],
    0x26:['9', '(', ''],
    0x27:['0', ')', ''],
    0x28:['\n','\n', ''],
    0x29:['␛','␛',''],
    0x2a:['\b', '\b','\b'], #⌫
    0x2b:['\t','\t',''],
    0x2C:[' ', ' ',''],
    0x2D:['-', '_',''],
    0x2E:['=', '+',''],
    0x2F:['[', '{',''],
    0x30:[']', '}',''],
    # 0x31 ANSI kbd \ & |
    0x31:[']', '}',''],
    # 0x32: non US ANSI kbd # & ~
    0x32:['#','~',''],
    0x33:[';', ':',''],
    0x34:['\'', '"',''],
    0x36:[',', '<',''],
    0x37:['.', '>',''],
    0x38:['/', '?',''],
    0x39:['⇪','⇪','⇪'], #CAPS LOCK
    0x4f:[u'→',u'→',u'→'],
    0x50:[u'←',u'←',u'←'],
    0x51:[u'↓',u'↓',u'↓'],
    0x52:[u'↑',u'↑',u'↑']
}

# USB frame keycodes
# as found in the specifications @
# https://usb.org/sites/default/files/hut1_3_0.pdf Chapter 10
US_ANSI_KEYCODES = {
    0x04:['a', 'A'],
    0x05:['b', 'B'],
    0x06:['c', 'C'],
    0x07:['d', 'D'],
    0x08:['e', 'E'],
    0x09:['f', 'F'],
    0x0A:['g', 'G'],
    0x0B:['h', 'H'],
    0x0C:['i', 'I'],
    0x0D:['j', 'J'],
    0x0E:['k', 'K'],
    0x0F:['l', 'L'],
    0x10:['m', 'M'],
    0x11:['n', 'N'],
    0x12:['o', 'O'],
    0x13:['p', 'P'],
    0x14:['q', 'Q'],
    0x15:['r', 'R'],
    0x16:['s', 'S'],
    0x17:['t', 'T'],
    0x18:['u', 'U'],
    0x19:['v', 'V'],
    0x1A:['w', 'W'],
    0x1B:['x', 'X'],
    0x1C:['y', 'Y'],
    0x1D:['z', 'Z'],
    0x1E:['1', '!'],
    0x1F:['2', '@'],
    0x20:['3', '#'],
    0x21:['4', '$'],
    0x22:['5', '%'],
    0x23:['6', '^'],
    0x24:['7', '&'],
    0x25:['8', '*'],
    0x26:['9', '('],
    0x27:['0', ')'],
    0x28:['\n','\n'],
    0x29:['␛','␛'],
    0x2a:['\b', '\b'], #⌫
    0x2b:['\t','\t'],
    0x2C:[' ', ' '],
    0x2D:['-', '_'],
    0x2E:['=', '+'],
    0x2F:['[', '{'],
    0x30:[']', '}'],
    # 0x31 ANSI kbd \ & |
    0x31:[']', '}'],
    # 0x32: non US ANSI kbd # & ~
    0x32:['#','~'],
    0x33:[';', ':'],
    0x34:['\'', '"'],
    0x36:[',', '<'],
    0x37:['.', '>'],
    0x38:['/', '?'],
    0x39:['⇪','⇪'],
    0x4f:[u'→',u'→'],
    0x50:[u'←',u'←'],
    0x51:[u'↓',u'↓'],
    0x52:[u'↑',u'↑']

    #TODO map keypad and other keys ?
}

#tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata > strokes.txt
with open('strokes.txt', 'r') as f:
    datas = f.readlines()

decoded = ""
for data in [bytearray.fromhex(k) for k in datas]:
    mod = data[0]
    shift = mod & LEFT_SHIFT or mod & RIGHT_SHIFT
    ctrl = mod & RIGHT_CTRL or mod & LEFT_CTRL
    alt = mod & LEFT_ALT
    altgr = mod & ALT_GRAPHIC
    win = mod & LEFT_WIN or mod & RIGHT_WIN

    s = []
    if (shift):
        s.append("shift")
    if (ctrl):
        s.append("ctrl")
    if (alt):
        s.append("alt")
    if (altgr):
        s.append('altgr')
    if (win):
        s.append("win")
    if len(s):
        print("mod " + bin(mod) + ":" + '|'.join(s))
    
    keycode = data[2]

    for keycode in data[2:]:
        if keycode == 0:
            continue
        print(hex(keycode))
        if not keycode in BEPO:
            print("Not found: " + hex(keycode))
            continue

        if shift:
            i = 1
        elif altgr:
            i = 2
        else:
            i = 0

        key = BEPO[keycode][i]
        decoded += key
        print(key)
        #sys.stdout.write(AZERTY[keycode][i])

print(decoded)
