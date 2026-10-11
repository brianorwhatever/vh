// Primitive binary64 formatting only. JSON and VH-Log are implemented in Ada.
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>

static_assert(sizeof(double) == 8 && std::numeric_limits<double>::is_iec559);

extern "C" int vh_number(double number, char *output) {
    if (!std::isfinite(number)) return -1;
    if (number == 0) {
        std::strcpy(output, "0");
        return 1;
    }

    // C++17 to_chars supplies shortest round-tripping, nearest binary64 digits.
    // Apply RFC 8785 / ECMAScript's fixed-versus-exponential notation limits.
    char buffer[64];
    const auto formatted = std::to_chars(
        buffer, buffer + sizeof(buffer), number, std::chars_format::scientific);
    if (formatted.ec != std::errc()) return -1;
    const std::string text(buffer, formatted.ptr);
    const auto exponent_position = text.find('e');
    const int exponent = std::stoi(text.substr(exponent_position + 1));
    std::string digits = text.substr(0, exponent_position);
    const bool negative = digits[0] == '-';
    if (negative) digits.erase(0, 1);
    const auto dot = digits.find('.');
    if (dot != std::string::npos) digits.erase(dot, 1);

    std::string result = negative ? "-" : "";
    if (exponent >= -6 && exponent < 21) {
        const int integer_digits = exponent + 1;
        if (integer_digits <= 0) {
            result += "0." + std::string(-integer_digits, '0') + digits;
        } else if (integer_digits >= static_cast<int>(digits.size())) {
            result += digits + std::string(integer_digits - digits.size(), '0');
        } else {
            result += digits.substr(0, integer_digits) + "." +
                      digits.substr(integer_digits);
        }
    } else {
        result += digits.substr(0, 1);
        if (digits.size() > 1) result += "." + digits.substr(1);
        result += "e";
        if (exponent >= 0) result += "+";
        result += std::to_string(exponent);
    }
    std::strcpy(output, result.c_str());
    return static_cast<int>(result.size());
}
