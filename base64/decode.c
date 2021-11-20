/*
 * MIT License
 *
 * Copyright (c) 2021 Zaman (7amaaan@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "base64.h"

#include <stdint.h>

// @formatter:off
/* BASE 64 decode map (0xFF for unused character, 0xFE for Pad ('=')) */
static const uint8_t b64demap[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /*  NUL  SOH  STX  ETX  EOT  ENQ  ACK  BEL  */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /*  BS   HT   LF   VT   FF   CR   SO   SI   */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /*  DLE  DC1  DC2  DC3  DC4  NAK  SYN  ETB  */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /*  CAN  EM   SUB  ESC  FS   GS   RS   US   */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /*  SP   !    "    #    $    %    &    '    */
        0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F, /*  (    )    *    +    ,    -    .    /    */
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, /*  0    1    2    3    4    5    6    7    */
        0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, /*  8    9    :    ;    <    =    >    ?    */
        0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /*  @    A    B    C    D    E    F    G    */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, /*  H    I    J    K    L    M    N    O    */
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, /*  P    Q    R    S    T    U    V    W    */
        0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /*  X    Y    Z    [    \    ]    ^    _    */
        0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, /*  `    a    b    c    d    e    f    g    */
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, /*  h    i    j    k    l    m    n    o    */
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, /*  p    q    r    s    t    u    v    w    */
        0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /*  x    y    z    {    |    }    ~    DEL  */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* the rest is unused */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};
// @formatter:on


size_t b64_decode(const char *cipher, const size_t len, void *plain)
{
    uint8_t *raw = plain;
    if (len == 0 || ((len & 3) > 0)) {
        /* Invalid base64 cipher */
        raw[0] = 0;
        return 0;
    }
    const uint8_t *str = (void*)cipher;
    size_t left = len;
    uint8_t byte[4];
    while (left > 4) {
        byte[0] = b64demap[str[0]];
        byte[1] = b64demap[str[1]];
        byte[2] = b64demap[str[2]];
        byte[3] = b64demap[str[3]];
        if ((byte[0] > 0xFD) || (byte[1] > 0xFD) || (byte[2] > 0xFD) || (byte[3] > 0xFD)) {
            /* Invalid byte in cipher */
            return 0;
        }
        raw[0] = (byte[0] << 2) + (byte[1] >> 4);
        raw[1] = (byte[1] << 4) + (byte[2] >> 2);
        raw[2] = (byte[2] << 6) + (byte[3] >> 0);
        str += 4;
        raw += 3;
        left -= 4;
    }
    /* last four */
    byte[0] = b64demap[str[0]];
    byte[1] = b64demap[str[1]];
    byte[2] = b64demap[str[2]];
    byte[3] = b64demap[str[3]];

    if ((byte[0] > 0xFD) || (byte[1] > 0xFD) || (byte[2] == 0xFF)) {
        return 0;
    }

    *raw++ = (byte[0] << 2) + (byte[1] >> 4);
    if (byte[2] == 0xFE && byte[3] == 0xFE) {
        /* xx== */
    } else if (byte[2] < 0xFD && byte[3] == 0xFE) {
        /* xxx= */
        *raw++ = (byte[1] << 4) + (byte[2] >> 2);
    } else if (byte[2] < 0xFD && byte[3] < 0xFD) {
        /* xxxx */
        *raw++ = (byte[1] << 4) + (byte[2] >> 2);
        *raw++ = (byte[2] << 6) + (byte[3] >> 0);
    } else {
        /* Invalid byte in cipher */
        return 0;
    }

    *raw = 0;
    return ((void*)raw - plain);
}
