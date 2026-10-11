#include "vh_log.hpp"
#include <iostream>
#include <sodium.h>
int main() {
    if (sodium_init() < 0)
        return 1;
    std::string line;
    while (std::getline(std::cin, line)) {
        vhlog::Json id = nullptr, response;
        try {
            auto request = vhlog::parse(line);
            id = request.at("id");
            response = {{"id", id},
                        {"ok", true},
                        {"result", vhlog::dispatch(request.at("op"), request.at("input"))}};
        } catch (const std::exception &e) {
            response = {{"id", id}, {"ok", false}, {"error", e.what()}};
        }
        std::cout << response.dump() << '\n' << std::flush;
    }
}
