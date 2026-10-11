#include <charconv>
#include <cstring>
#include <cmath>
extern "C" int vh_number(double d, char *out) {
 if (!std::isfinite(d)) return -1;
 if (d == 0) {strcpy(out,"0");return 1;}
 char b[64]; auto r=std::to_chars(b,b+64,d,std::chars_format::scientific); *r.ptr=0;
 strcpy(out,b); return int(r.ptr-b);
}
