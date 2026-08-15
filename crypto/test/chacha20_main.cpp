#include <iostream>

#include "chacha20_rfc.h"
#include "../chacha20.h"

int main() {
    ChaCha20RFC rfc(true);
    rfc.run();
}