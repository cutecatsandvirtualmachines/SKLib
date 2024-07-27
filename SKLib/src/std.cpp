#include "std.h"

char cpp::isalnum(char ch)
{
    return
        (ch >= '0' && ch <= '9')
        || (ch >= 'A' && ch <= 'Z')
        || (ch >= 'a' && ch <= 'z')
        || ch == '_'
        || ch == '-'
        || ch == '.'
        ;
}

char cpp::isalnumcap(char ch) {
    return
        (ch >= '0' && ch <= '9')
        || (ch >= 'A' && ch <= 'Z');
}

bool cpp::isalnumstr(char* str) {
    int i = 0;

    while (str[i]) {
        if (!isalnum(str[i++]))
            return false;
    }
    return true;
}

bool cpp::isalnumstr_s(char* str, size_t max) {
    int len = (int)strnlen_s(str, max);
    if (!len)
        return false;

    for (int i = 0; i < len; i++) {
        if (!isalnum(str[i]))
            return false;
    }
    return true;
}
