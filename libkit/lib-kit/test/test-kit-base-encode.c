#include <sxe-util.h>
#include <string.h>
#include <tap.h>

#include "kit.h"

int
main(int argc, char **argv)
{
    size_t blen, tlen;
    uint8_t bin[50];
    char txt[100];
    unsigned i;

    SXE_UNUSED_PARAMETER(argc);
    SXE_UNUSED_PARAMETER(argv);

    plan_tests(111);

    diag("The bin2hex/hex2bin interface");
    {
        snprintf(txt, sizeof(txt), "01234567890123456789");
        is(kit_bin2hex(txt, (const uint8_t *)"", 0, KIT_BIN2HEX_UPPER), 0, "Correctly encoded empty data");
        is_eq(txt, "", "Encode on empty buffer formatted as null-string");

        memset(bin, '\1', sizeof(bin));
        is(kit_hex2bin(bin, (const char *)"", 0), 0, "Correctly decoded empty data");

        is(kit_bin2hex(txt, (const uint8_t *)"\1\2\3\4", 4, KIT_BIN2HEX_LOWER), 8, "Translated a small binary string to hex");
        is_eq(txt, "01020304", "The hex data is correct");
        is(kit_hex2bin(bin, txt, 8), 4, "Translated it back to binary");
        ok(memcmp(bin, "\1\2\3\4", 4) == 0, "The binary is the same as the original");
        is(kit_bin2hex(txt, (const uint8_t *)"\12\24\36\50", 4, KIT_BIN2HEX_LOWER), 8, "Translated a small binary string to lowercase hex");
        is_eq(txt, "0a141e28", "The hex data is correct");
        is(kit_hex2bin(bin, txt, 8), 4, "Translated it back to binary");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");
        is(kit_bin2hex(txt, (const uint8_t *)"\12\24\36\50", 4, KIT_BIN2HEX_UPPER), 8, "Translated a small binary string to uppercase hex");
        is_eq(txt, "0A141E28", "The hex data is correct");

        memset(bin, '\0', 4);
        is(kit_hex2bin(bin, txt, 8), 4, "Translated it back to binary");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        memset(bin, '\0', 4);
        is(kit_hex2bin(bin, txt, 6), 3, "Translated part of it back to binary");
        ok(memcmp(bin, "\12\24\36", 3) == 0, "The binary is the same as the original");

        memset(bin, '\0', 4);
        is(kit_hex2bin(bin, txt, 7), 3, "Translated an odd number of characters back to binary - only read 3 binary bytes");
        ok(memcmp(bin, "\12\24\36", 3) == 0, "The binary is the same as the original");
    }

    diag("The base16encode/base16decode interface");
    {
        memset(txt, '\0', 8);
        blen = 4;
        tlen = sizeof(txt);
        is(kit_base16encode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), NULL, "Got no error from kit_base16encode()");
        is(tlen, 8, "tlen was set to 8");
        is(blen, 4, "blen remains at 4");
        is_eq(txt, "0A141E28", "The txt data is correct");

        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base16decode(bin, &blen, txt, &tlen, 0), NULL, "Got no error from kit_base16decode()");
        is(blen, 4, "blen was set to 4");
        is(tlen, 8, "tlen was set to 8");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        diag("Setting up with input containing spaces");
        strcpy(txt, "0A141E28 323c4650");
        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base16decode(bin, &blen, txt, &tlen, 0), NULL, "Got no error from kit_base16decode()");
        is(blen, 4, "blen was set to 4");
        is(tlen, 8, "tlen was set to 8");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base16decode(bin, &blen, txt, &tlen, KIT_BASE_DECODE_SKIP_WHITESPACE), NULL,
           "Got no error from kit_base16decode(..., KIT_BASE_DECODE_SKIP_WHITESPACE)");
        is(blen, 8, "blen was set to 8");
        is(tlen, 17, "tlen was set to 17");
        ok(memcmp(bin, "\12\24\36\50\62\74\106\120", 8) == 0, "The binary is correct");

        diag("Verify overflow for empty output buffer");
        tlen = 0;
        blen = 4;
        is_eq(kit_base16encode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), "Output overflow", "Got overflow error for zero-length output buffer with encode");

        blen = 0;
        tlen = sizeof(txt);
        is_eq(kit_base16decode(bin, &blen, txt, &tlen, 0), "Output overflow", "Got overflow error for zero-length output buffer with decode");
    }

    diag("The base32encode/base32decode interface");
    {
        memset(txt, '\0', 8);
        blen = 4;
        tlen = sizeof(txt);
        is(kit_base32encode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), NULL, "Got no error from kit_base32encode()");
        is(tlen, 7, "tlen was set to 7");
        is(blen, 4, "blen remains at 4");
        is_eq(txt, "BIKB4KA", "The base32 data is correct");

        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base32decode(bin, &blen, txt, &tlen, 0), NULL, "Got no error from kit_base32decode()");
        is(blen, 4, "blen was set to 4");
        is(tlen, 7, "tlen was set to 7");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        diag("Same again, but with a small output buffer");
        blen = 3;
        tlen = sizeof(txt);
        is_eq(kit_base32decode(bin, &blen, txt, &tlen, 0), "Output overflow", "Got an error from kit_base32decode()");

        diag("Adding some padding to the end of the input");
        strcat(txt, "=");
        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base32decode(bin, &blen, txt, &tlen, 0), NULL, "Got no error from kit_base32decode()");
        is(blen, 4, "blen was set to 4");
        is(tlen, 7, "tlen was set to 7 - despite the padding character (which was ignored)");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        diag("Verify overflow for empty output buffer");
        tlen = 0;
        blen = 4;
        is_eq(kit_base32encode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), "Output overflow", "Got overflow error for zero-length output buffer with encode");

        blen = 0;
        tlen = sizeof(txt);
        is_eq(kit_base32decode(bin, &blen, txt, &tlen, 0), "Output overflow", "Got overflow error for zero-length output buffer with decode");
    }

    diag("The base32hexencode/base32hexdecode interface");
    {
        memset(txt, '\0', 8);
        blen = 4;
        tlen = sizeof(txt);
        is(kit_base32hexencode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), NULL, "Got no error from kit_base32hexencode()");
        is(tlen, 7, "tlen was set to 7");
        is(blen, 4, "blen remains at 4");
        is_eq(txt, "18A1SA0", "The base32hex data is correct");

        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base32hexdecode(bin, &blen, txt, &tlen, 0), NULL, "Got no error from kit_base32hexdecode()");
        is(blen, 4, "blen was set to 4");
        is(tlen, 7, "tlen was set to 7");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        diag("Same again, but with a small output buffer");
        blen = 3;
        tlen = sizeof(txt);
        is_eq(kit_base32hexdecode(bin, &blen, txt, &tlen, 0), "Output overflow", "Got an error from kit_base32hexdecode()");

        diag("Adding some padding to the end of the input");
        strcat(txt, "=");
        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base32hexdecode(bin, &blen, txt, &tlen, 0), NULL, "Got no error from kit_base32hexdecode()");
        is(blen, 4, "blen was set to 4");
        is(tlen, 7, "tlen was set to 7 - despite the padding character (which was ignored)");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        diag("Verify overflow for empty output buffer");
        tlen = 0;
        blen = 4;
        is_eq(kit_base32hexencode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), "Output overflow", "Got overflow error for zero-length output buffer with encode");

        blen = 0;
        tlen = sizeof(txt);
        is_eq(kit_base32hexdecode(bin, &blen, txt, &tlen, 0), "Output overflow", "Got overflow error for zero-length output buffer with decode");
    }

    diag("The base64encode/base64decode interface");
    {
        memset(txt, '\0', 8);
        blen = 4;
        tlen = sizeof(txt);
        is(kit_base64encode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), NULL, "Got no error from kit_base64encode()");
        is(tlen, 8, "tlen was set to 8");
        is(blen, 4, "blen remains at 4");
        is_eq(txt, "ChQeKA==", "The base64 data is correct");

        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base64decode(bin, &blen, txt, &tlen, 0), NULL, "Got no error from kit_base64decode()");
        is(blen, 4, "blen was set to 4");
        is(tlen, 8, "tlen was set to 8");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        diag("Test the whole base64 character set");
        const uint8_t binary[] = { 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14, 0x93, 0x51,
                                   0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92, 0x59, 0xa7, 0xa2, 0x9a,
                                   0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf };
        memcpy(bin, binary, blen = sizeof(binary));
        memset(txt, '\0', tlen = sizeof(txt));
        is(kit_base64encode(txt, &tlen, bin, &blen), NULL, "Got no error from kit_base64encode()");
        is(tlen, 64, "tlen was set to 64");
        is(blen, 48, "blen remains at 48");
        is_eq(txt, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", "The base64 data is correct");

        memset(bin, '\0', blen = sizeof(bin));
        tlen = strlen(txt);
        is(kit_base64decode(bin, &blen, txt, &tlen, 0), NULL, "Got no error from kit_base64decode()");
        is(blen, 48, "blen was set to 48");
        is(tlen, 64, "tlen was set to 64");
        ok(memcmp(bin, binary, sizeof(binary)) == 0, "The binary is the same as the original");

        diag("Some padding tests");
        for (i = 7; i > 5; i--) {
            txt[i] = '\0';
            blen = sizeof(bin);
            tlen = sizeof(txt);
            is_eq(kit_base64decode(bin, &blen, txt, &tlen, 0), "Padding characters missing", "Got an error from kit_base64decode()");
        }

        diag("Setting up some bogus base64 padding");
        strcpy(txt, "AwEAAYvgW===");
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is_eq(kit_base64decode(bin, &blen, txt, &tlen, 0), "Padding characters missing", "Got no error from kit_base64decode()");

        strcpy(txt, "AwEAAYvgWb=b");
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is_eq(kit_base64decode(bin, &blen, txt, &tlen, 0), "Padding characters missing", "Got an error from kit_base64decode()");

        diag("Some overflow tests");
        for (i = 8; i > 4; i--) {
            blen = 4;
            tlen = i;
            is_eq(kit_base64encode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), "Output overflow", "Got an error from kit_base64encode() - tlen %u", i);
        }

        diag("Verify overflow for empty output buffer");
        tlen = 0;
        blen = 4;
        is_eq(kit_base64encode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), "Output overflow", "Got overflow error for zero-length output buffer with encode");

        blen = 0;
        tlen = sizeof(txt);
        is_eq(kit_base64decode(bin, &blen, txt, &tlen, 0), "Output overflow", "Got overflow error for zero-length output buffer with decode");
    }

    diag("The base64urlencode/base64urldecode interface");
    {
        memset(txt, '\0', 8);
        blen = 4;
        tlen = sizeof(txt);
        is(kit_base64urlencode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), NULL, "Got no error from kit_base64urlencode()");
        is(tlen, 6, "tlen was set to 6");
        is(blen, 4, "blen remains at 4");
        is_eq(txt, "ChQeKA", "The base64url data is correct");

        memset(bin, '\0', 4);
        blen = sizeof(bin);
        tlen = sizeof(txt);
        is(kit_base64urldecode(bin, &blen, txt, &tlen), NULL, "Got no error from kit_base64urldecode()");
        is(blen, 4, "blen was set to 4");
        is(tlen, 6, "tlen was set to 6");
        ok(memcmp(bin, "\12\24\36\50", 4) == 0, "The binary is the same as the original");

        diag("Test the whole base64url character set");
        const uint8_t binary[] = { 0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14, 0x93, 0x51,
                                   0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92, 0x59, 0xa7, 0xa2, 0x9a,
                                   0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf };
        memcpy(bin, binary, blen = sizeof(binary));
        memset(txt, '\0', tlen = sizeof(txt));
        is(kit_base64urlencode(txt, &tlen, bin, &blen), NULL, "Got no error from kit_base64urlencode()");
        is(tlen, 64, "tlen was set to 64");
        is(blen, 48, "blen remains at 48");
        is_eq(txt, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", "The base64url data is correct");

        memset(bin, '\0', blen = sizeof(bin));
        tlen = strlen(txt);
        is(kit_base64urldecode(bin, &blen, txt, &tlen), NULL, "Got no error from kit_base64urldecode()");
        is(blen, 48, "blen was set to 48");
        is(tlen, 64, "tlen was set to 64");
        ok(memcmp(bin, binary, sizeof(binary)) == 0, "The binary is the same as the original");

        diag("Some overflow tests");
        for (i = 6; i > 4; i--) {
            blen = 4;
            tlen = i;
            is_eq(kit_base64urlencode(txt, &tlen, (const uint8_t *)"\12\24\36\50", &blen), "Output overflow", "Got an error from kit_base64urlencode() - tlen %u", i);
        }
    }

    return exit_status();
}
