# Documentation

The pages of `docs/` hold what does not belong to one directory: how to build, what an integrator must know, and
the reports behind the design. [DOCUMENTATION.md](DOCUMENTATION.md) says which page owns which kind of fact.

| Page | Contents |
| --- | --- |
| [BUILDING.md](BUILDING.md) | Requirements, the CPU and GPU builds, every CMake option, installing |
| [SECURITY-NOTES.md](SECURITY-NOTES.md) | Constant time, randomness, threads, stack, what is not destroyed, the GPU backends |
| [FIPS-140-3.md](FIPS-140-3.md) | The FIPS 140-3 mode (`OPENPQC_FIPS140_3`): what it does, what is tested, what remains; designed for FIPS 140-3, not validated |
| [FIPS-140-3-security-policy.md](FIPS-140-3-security-policy.md) | The draft of the mode's security policy (SP 800-140B) |
| [GPU_ACCELERATION.md](GPU_ACCELERATION.md) | The GPU design, the measurements and the comparison with published GPU work |
| [PRIMITIVES.md](PRIMITIVES.md) | The mathematical primitives of the schemes and their groups |
| [SOURCE_MAP.md](SOURCE_MAP.md) | mlkem-native file by file: what is FIPS 203 and what mlkem-native added |
| [catalog/](catalog/README.md) | Per-symbol catalogs of the upstream projects |
| [DOCUMENTATION.md](DOCUMENTATION.md) | How the documentation is organised, and the rules it follows |

Elsewhere: the [API guide](../include/openpqc/README.md), the [source guide](../src/README.md), the
[tests](../tests/README.md), the [benchmarks](../bench/README.md), and [SECURITY.md](../SECURITY.md).
