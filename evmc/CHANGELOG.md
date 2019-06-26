# Changelog

## [6.3.0] - unreleased

- Changed: [[#293](https://github.com/ethereum/evmc/pull/293)]
  In C++ API `evmc::result::raw()` renamed to `evmc::result::release_raw()`.
- Changed: [[#311](https://github.com/ethereum/evmc/pull/311)]
  In `evmc_load_and_create()` the `error_code` is optional (can be `NULL`).
- Fixed:
  [[#261](https://github.com/ethereum/evmc/issues/261),
  [#263](https://github.com/ethereum/evmc/pull/263)]
  The `vmtester` tool now builds with MSVC with `/std:c++17`.
- Fixed:
  [[#305](https://github.com/ethereum/evmc/issues/305),
  [#306](https://github.com/ethereum/evmc/pull/306)]
  A loaded VM with incompatible ABI version is not properly destroyed.

## [6.2.2] - 2019-05-16

- Fixed: [[#281](https://github.com/ethereum/evmc/pull/281)]
  Compilation error of `evmc::result::raw()` in Visual Studio fixed.
- Fixed: [[#282](https://github.com/ethereum/evmc/pull/282)]
  The `evmc::result`'s move assignment operator fixed.

## [6.2.1] - 2019-04-29

- Fixed:
  [[#256](https://github.com/ethereum/evmc/issues/256),
  [#257](https://github.com/ethereum/evmc/issues/257)]
  Disallow implicit conversion from C++ `evmc::result` to `evmc_result` 
  causing unintendent premature releasing of resources. 

## [6.2.0] - 2019-04-25

- Added: [[#216](https://github.com/ethereum/evmc/pull/216)]
  CMake option `EVMC_TEST_TOOLS` to build evmc-vmtester without bothering with internal unit tests.
- Added:
  [[#217](https://github.com/ethereum/evmc/pull/217)]
  [[#226](https://github.com/ethereum/evmc/pull/226)]
  The full C++ EVMC API for both VM and Host implementations.
- Added: [[#201](https://github.com/ethereum/evmc/pull/201), [#202](https://github.com/ethereum/evmc/pull/202), [#233](https://github.com/ethereum/evmc/pull/233)]
  Initial and rough bindings for Rust.  It is possible to implement an
  EVMC VM in Rust utilising some helpers.
- Added: 
  [[#230](https://github.com/ethereum/evmc/pull/230)]
  [[#232](https://github.com/ethereum/evmc/pull/232)]
  Handling of DLL loading errors greatly improved by `evmc_last_error_msg()` function.
- Changed: [[#195](https://github.com/ethereum/evmc/pull/195)]
  The minimum supported GCC version is 6 (bumped from undocumented version 4.8).
- Changed: [[#197](https://github.com/ethereum/evmc/pull/197)]
  Go bindings improved by introduction of the `TxContext` struct.
- Changed:
  [[#221](https://github.com/ethereum/evmc/pull/221)]
  [[#234](https://github.com/ethereum/evmc/pull/234)]
  [[#238](https://github.com/ethereum/evmc/pull/238)]
  [[#241](https://github.com/ethereum/evmc/pull/241)]
  [[#242](https://github.com/ethereum/evmc/pull/242)]
  A lot of evmc-vmtester improvements.
- Changed: [[#251](https://github.com/ethereum/evmc/pull/251)]
  [Cable] upgraded to version 0.2.17.
- Deprecated: [[#196](https://github.com/ethereum/evmc/pull/196)]
  The `EVMC_CONSTANTINOPLE2` revision name is deprecated, replaced with `EVMC_PETERSBURG`.


## [6.1.1] - 2019-02-13

- Added: [[#192](https://github.com/ethereum/evmc/pull/192)]
  Documentation of elements of evmc_revision.
- Fixed: [[#190](https://github.com/ethereum/evmc/pull/190)]
  Compilation with GCC 5 because of the "deprecated" attribute applied
  to an enum element.

## [6.1.0] - 2019-01-24

- Added: [[#174](https://github.com/ethereum/evmc/pull/174)]
  The **Istanbul** EVM revision.
- Added: [[#182](https://github.com/ethereum/evmc/pull/182)]
  The `is_zero()` C++ helper for basic data types.
- Added: [[#186](https://github.com/ethereum/evmc/pull/186)]
  Reserved the post-Constantinople EVM revision number.
- Added: [[#187](https://github.com/ethereum/evmc/pull/187)]
  C++ wrappers for VM and execution result objects.
- Deprecated: [[#184](https://github.com/ethereum/evmc/pull/184)]
  The `EVMC_LATEST_REVISION` is deprecated, replaced with `EVMC_MAX_REVISION`.

## [6.0.2] - 2019-01-16

- Fixed: [[#179](https://github.com/ethereum/evmc/pull/179)]
  Add missing salt argument for CREATE2 in Host in Go bindings.

## [6.0.1] - 2018-11-10

- Fixed: [[#169](https://github.com/ethereum/evmc/pull/169)]
  Integration of EVMC as a CMake subproject is easier because 
  Hunter is not loaded unless building tests (`EVMC_TESTING=ON`) is requested.

## [6.0.0] - 2018-10-24

- Added: [[#116](https://github.com/ethereum/evmc/pull/116)]
  [EVMC Host implementation example](https://github.com/ethereum/evmc/blob/master/examples/example_host.cpp).
- Added: [[#127](https://github.com/ethereum/evmc/pull/127)]
  Support for Constantinople SSTORE net gas metering.
- Added: [[#133](https://github.com/ethereum/evmc/pull/133)]
  Support for Constantinople CREATE2 salt in Go bindings.
- Added: [[#144](https://github.com/ethereum/evmc/pull/144)]
  A VM can now report its **capabilities** (i.e. EVM and/or ewasm).
- Added: [[#159](https://github.com/ethereum/evmc/pull/159)]
  [EVMC Host implementation guide](https://ethereum.github.io/evmc/hostguide.html).
- Added: [[#160](https://github.com/ethereum/evmc/pull/160)]
  [EVMC VM implementation guide](https://ethereum.github.io/evmc/vmguide.html).
- Changed: [[#119](https://github.com/ethereum/evmc/pull/119)]
  EVMC loader symbol searching has been generalized.
- Changed: [[#125](https://github.com/ethereum/evmc/pull/125)]
  The `evmc_context_fn_table` renamed to `evmc_host_interface`.
- Changed: [[#128](https://github.com/ethereum/evmc/pull/128)]
  The `evmc_message` fields reordered.
- Changed: [[#136](https://github.com/ethereum/evmc/pull/136)]
  The `evmc_set_option()` now returns more information about the failure cause.
- Changed: [[#138](https://github.com/ethereum/evmc/pull/138)], [[#140](https://github.com/ethereum/evmc/pull/140)]
  In C the `bool` type is used instead of `int` for true/false flags.
- Changed: [[#152](https://github.com/ethereum/evmc/pull/152)]
  Introduction of the `evmc_bytes32` type.
- Changed: [[#154](https://github.com/ethereum/evmc/pull/154)]
  Simplification of signatures of Host methods.

## [5.2.0] - 2018-08-28

- Feature: [[#81](https://github.com/ethereum/evmc/pull/81)]
  Use also "evmc_create" function name for loading EVMC DLLs.
- Fix: [[#92](https://github.com/ethereum/evmc/pull/92)]
  The evmc.h header compatibility with C++98 fixed.
- Fix: [[#93](https://github.com/ethereum/evmc/pull/93)], [[#103](https://github.com/ethereum/evmc/pull/103)]
  Compilation and build configuration fixes.
- Improved: [[#97](https://github.com/ethereum/evmc/pull/97)], [[#107](https://github.com/ethereum/evmc/pull/107)]
  Documentation improvements, including documentation for the VM Tester.

## [5.1.0] - 2018-08-23

- Feature: [[#41](https://github.com/ethereum/evmc/pull/41)]
  Go language bindings for EVMC.
- Feature: [[#56](https://github.com/ethereum/evmc/pull/56), [#62](https://github.com/ethereum/evmc/pull/62)]
  New error codes.
- Feature: [[#67](https://github.com/ethereum/evmc/pull/67), [#68](https://github.com/ethereum/evmc/pull/68), [#70](https://github.com/ethereum/evmc/pull/70)]
  More helper functions.
- Fix: [[#72](https://github.com/ethereum/evmc/pull/72)]
  Go bindings: Properly handle unknown error codes.
- Improved: [[#58](https://github.com/ethereum/evmc/pull/58)]
  Documentation has been extended.
- Improved: [[#59](https://github.com/ethereum/evmc/pull/59)]
  Optional Result Storage helper module has been separated.
- Improved: [[#75](https://github.com/ethereum/evmc/pull/75)]
  Cable upgraded to 0.2.11.
- Improved: [[#77](https://github.com/ethereum/evmc/pull/77)]
  The license changed from MIT to Apache 2.0.

## [5.0.0] - 2018-08-10

- Feature: [[#23](https://github.com/ethereum/evmc/pull/23), [#24](https://github.com/ethereum/evmc/pull/24)]
  List of status codes extended and reordered.
- Feature: [[#32](https://github.com/ethereum/evmc/pull/32)]
  VM Tracing API.
- Feature: [[#33](https://github.com/ethereum/evmc/pull/33), [#34](https://github.com/ethereum/evmc/pull/34)]
  The support library with metrics tables for EVM1 instructions.
- Feature: [[#35](https://github.com/ethereum/evmc/pull/35)]
  Ability to create EVMC CMake package.
- Feature: [[#40](https://github.com/ethereum/evmc/pull/40)]
  The loader support library for VM dynamic loading.
- Feature: [[#45](https://github.com/ethereum/evmc/pull/45)]
  Constantinople: Support for `CREATE2` instruction.
- Feature: [[#49](https://github.com/ethereum/evmc/pull/49)]
  Constantinople: Support for `EXTCODEHASH` instruction.
- Feature: [[#52](https://github.com/ethereum/evmc/pull/52)]
  Constantinople: Storage status is reported back from `evmc_set_storage()`.


[6.3.0]: https://github.com/ethereum/evmc/compare/v6.2.1...master
[6.2.2]: https://github.com/ethereum/evmc/releases/tag/v6.2.2
[6.2.1]: https://github.com/ethereum/evmc/releases/tag/v6.2.1
[6.2.0]: https://github.com/ethereum/evmc/releases/tag/v6.2.0
[6.1.1]: https://github.com/ethereum/evmc/releases/tag/v6.1.1
[6.1.0]: https://github.com/ethereum/evmc/releases/tag/v6.1.0
[6.0.2]: https://github.com/ethereum/evmc/releases/tag/v6.0.2
[6.0.1]: https://github.com/ethereum/evmc/releases/tag/v6.0.1
[6.0.0]: https://github.com/ethereum/evmc/releases/tag/v6.0.0
[5.2.0]: https://github.com/ethereum/evmc/releases/tag/v5.2.0
[5.1.0]: https://github.com/ethereum/evmc/releases/tag/v5.1.0
[5.0.0]: https://github.com/ethereum/evmc/releases/tag/v5.0.0

[Cable]: https://github.com/ethereum/cable