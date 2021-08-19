Implementation included from https://github.com/XKCP/XKCP

We've included file Keccak-readable-and-compact.c from Standalone/CompactFIPS202/C folder with minor modifications
We added explicit cast to unsigned to result of MIN function with arguments (unsigned, unsigned long long) hopefully changing no semantic
Because we aim to address all warnings printed by compiler

We use pre-final variant of Keccak(1088, 512, in, inlen, 1, out, outlen);

Difference is in the way data is returned from keccak function.

With our parameters standard Keccak returns up to 136 bytes as is, then performs additional permutation per 136 bytes

Our Keccak returns up to 200 bytes as is, and cannot return more

We added #define LITTLE_ENDIAN to the code, because this increases speed 3x