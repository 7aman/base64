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

#include "../base64/base64.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

static int assert_valid_case(uint8_t *buf, const uint32_t buf_len, char *str, const uint32_t str_len)
{
    char str_out[12];
    uint8_t buf_out[12];
    assert(b64_encode(buf, buf_len, str_out) == str_len);
    assert(memcmp(str_out, str, str_len) == 0);
    assert(b64_decode(str, str_len, buf_out) == buf_len);
    assert(memcmp(buf_out, buf, buf_len) == 0);
    return 0;
}

static int assert_invalid_case(char *cipher, const uint32_t len)
{
    uint8_t plain[12];
    assert(b64_decode(cipher, len, plain) == 0);
    return 0;
}

int b64_tests(void)
{
    assert_valid_case((void *)"", 0, "", 0);
    assert_valid_case((void *)"f", 1, "Zg==", 4);
    assert_valid_case((void *)"fo", 2, "Zm8=", 4);
    assert_valid_case((void *)"foo", 3, "Zm9v", 4);
    assert_valid_case((void *)"foob", 4, "Zm9vYg==", 8);
    assert_valid_case((void *)"fooba", 5, "Zm9vYmE=", 8);
    assert_valid_case((void *)"foobar", 6, "Zm9vYmFy", 8);

    assert_invalid_case((void *)"Zm9v>mFy", 8);
    assert_invalid_case((void *)"Z=9vYmFy", 8);
    assert_invalid_case((void *)"Zm9vY=Fy", 8);
    assert_invalid_case((void *)"Zm9vY", 5);
    return 0;
}

int main(int argc, char **argv) {

    if (b64_tests() == 0) {
        printf("passed!\r\n");
    } else {
        printf("failed!\r\n");
    }
    return 0;
}
