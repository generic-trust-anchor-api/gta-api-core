# Generic Trust Anchor API Core

## Introduction
This project contains an example implementation for the basic
functionality that has to be provided by the GTA API framework as
described in [ISO/IEC TS 30168](https://www.iso.org/standard/53288.html) Figure 2.

Please note, that the development is currently work in progress and no
releases have been created up to the time being.

## Structure of the Repository
| File        | Description |
| :---        |      :---   |
| ./meson_options.txt | Project specific configuration options used by Meson build system |
| ./cross-files | Configurations for cross compile targets in Meson |
| ./subprojects | External build dependencies that are used by Meson, i.e., the cmocka framework and the ISO/IEC TS 30168 header files |
| ./src | Reference implementation for the GTA API framework/middleware code |
| ./platform  | Platform specific code |
| ./test      | Test suite for the GTA API framework/middleware code |
| ./util      | Some useful basic data types used by the reference implementation |

## Dependencies
The build and test of the implementation relies on some tools and frameworks:
* libcmocka-dev: The cmocka unit test framework
* meson: Python-based build system generator like Automake or CMake
* ninja-build: Build tool like make
* build-essential: Meta-package to install a full build environment on Debian-based systems
* libssl-dev: Development package for OpenSSL
* cmake: This is not necessarily required but meson can build CMake based sub-modules
* pkg-config: Tool required by meson to figure out compiler/linker options for library dependencies 
* gcovr: Tool required to extract coverage information
* lcov: Tool required to compose coverage reports

On Debian-based Linux distributions the build dependencies can be installed
with the following command:
```
$ apt install libcmocka-dev meson ninja-build build-essential libssl-dev cmake pkg-config
```
The optional packages can be installed with the following command:
```
$ apt install gcovr lcov valgrind
```

## Local build
* In the project root, initialize build system and build directory (like
  ./configure for automake):
```
$ meson setup <build_dir>
```

* Compile the code, the build directory is specified with the `-C` option:
```
$ ninja -C <build_dir>
```

* The tests are executed by calling ninja with the test target selected:
```
$ ninja -C <build_dir> test
```

* To install the library and header files, the following target can be used:
```
$ sudo ninja -C <build_dir> install
```

* The Valgrind tool can be used to perform some dynamic code analysis by calling
  the following target:
```
$ ninja -C <build_dir> gta_framework_memcheck
```

All build artifacts are kept in the specified build directory. It is also
possible to use several build directories in parallel with different
configurations.

## Cross Builds / Cross Compilation
Meson is well suited for cross compilation. For this, a cross configuration file
is required. This file has to be passed to meson when the build directory is
configured.

```
$ meson setup <build_dir> --cross-file cross-files/aarch64-linux-gnu.txt
```

The file aarch64-linux-gnu.txt allows building for the ARM64 architecture on a
x86 Debian Linux machine with the prerequisite that the required compiler was
installed before with the following command:

```
$ apt install gcc-aarch64-linux-gnu
```

## Meson Options File
Meson allows to customize the build with an option file which includes user
specified, project specific options that modify the characteristics of the
build. The defined options are accessed by the `meson.build` files and are
specified in the file `meson_options.txt`. This allows a separation of the build
scripts and the build options.

Currently the following options are available:

| Option Name | Possible values | Description |
| :---------- | :-------------- | :---------- |
| build       | combo: { 'debug', 'release' } | Select the build type with associated tool configuration (e.g., compiler flags for debugging). |
| build-dependencies | boolean : { true, false } | Select whether to build dependencies locally rather than use system installed libraries. |

## Coverage Report
For coverage reporting the code has to be instrumented. Meson can be
instructed to perform the instrumentation by specifying the respective compiler
options. Furthermore, additional build targets are generated to create different
coverage reports.

* Configure build environment for coverage reporting:
```
$ meson setup <build_dir> -Db_coverage=true
```

* Create all available coverage reports:
```
$ ninja -C <build_dir> test
$ ninja -C <build_dir> coverage
```
Notes:
* It seems that there is a bug in meson. It is required to execute the test
  suite before generating the coverage reports.
* The coverage-target creates all available reports. Alternatively, only
  required reports can be generated by using the following targets:
   * coverage-xml
   * coverage-text
   * coverage-sonarqube
   * coverage-html
* Especially, the html-target creates a nice report that can be viewed in a
  web-browser. It can be found in the build directory under
 `meson-logs/coveragereport/index.html`


## Test Results
Meson does only report tests results on per test executable basis in the
terminal. More detailed test results are exported to junit XML-files. These files
can be found in the build directory in the test subdirectory.
