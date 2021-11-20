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

#define B64PAD '='

static const char b64enmap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encode(const void *plain, const size_t len, char *cipher)
{
    if (len == 0) {
        /* nothing to encode */
        *cipher = '\0';
        return 0;
    }

    const uint8_t *bytes = plain;
    const char *start = cipher;
    size_t left = len;

    while (left > 2) {
        uint32_t b = bytes[2];
        b += bytes[1] << 8;
        b += bytes[0] << 16;
        cipher[0] = b64enmap[(b >> 18)];
        cipher[1] = b64enmap[(b >> 12) & 0x3F];
        cipher[2] = b64enmap[(b >> 6) & 0x3F];
        cipher[3] = b64enmap[(b & 0x3F)];
        cipher += 4;
        bytes += 3;
        left -= 3;
    }

    if (left) {
        cipher[0] = b64enmap[bytes[0] >> 2];
        if (left == 1) {
            cipher[1] = b64enmap[(bytes[0] & 0x03) << 4];
            cipher[2] = B64PAD;
        } else if (left == 2) {
            cipher[1] = b64enmap[((bytes[0] & 0x03) << 4) + (bytes[1] >> 4)];
            cipher[2] = b64enmap[(bytes[1] & 0x0f) << 2];
        }
        cipher[3] = B64PAD;
        cipher += 4;
    }

    *cipher = '\0';
    return (cipher - start);
}
