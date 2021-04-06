---
layout: post
title: Compiling SQLCipher on Windows and Linux
category: note
permalink: note/compiling-sqlcipher/
tags: notes
---

Zetetic does not provide a dynamic library installer for users. Therefore, a static library is a great choice to deliver.

## Windows
OpenSSL headers are required. You can install it via the C++ Library Manager from Microsoft: [vcpkg](https://github.com/microsoft/vcpkg).  vcpkg could be installed anywhere.

```powershell
PS> .\vcpkg install openssl:x64-windows-static
PS> .\vcpkg install openssl:x86-windows-static
```

The most convenient way to let the SQLCipher compiler find these headers is to move vcpkg's openssl install dir to the root of SQLCipher.  
  
Now open Makefile.msc in a text editor and replace the lines:  
```makefile
# Flags controlling use of the in memory btree implementation
#
# SQLITE_TEMP_STORE is 0 to force temporary tables to be in a file, 1 to
# default to file, 2 to default to memory, and 3 to force temporary
# tables to always be in memory.
#
TCC = $(TCC) -DSQLITE_TEMP_STORE=1
RCC = $(RCC) -DSQLITE_TEMP_STORE=1
```
by the following:
```makefile
# Flags controlling use of the in memory btree implementation
#
# SQLITE_TEMP_STORE is 0 to force temporary tables to be in a file, 1 to
# default to file, 2 to default to memory, and 3 to force temporary
# tables to always be in memory.
#
TCC = $(TCC) -DSQLITE_TEMP_STORE=2
RCC = $(RCC) -DSQLITE_TEMP_STORE=2

TCC = $(TCC) -DSQLITE_HAS_CODEC
RCC = $(RCC) -DSQLITE_HAS_CODEC

!IF "$(PLATFORM)"=="x64"
TCC = $(TCC) -I"openssl-windows_x64-windows-static\include"
RCC = $(RCC) -I"openssl-windows_x64-windows-static\include"
!ELSEIF "$(PLATFORM)"=="x86"
TCC = $(TCC) -I"openssl-windows_x86-windows-static\include"
RCC = $(RCC) -I"openssl-windows_x86-windows-static\include"
!ENDIF

!IF "$(PLATFORM)"=="x64"
LTLIBPATHS = $(LTLIBPATHS) /LIBPATH:"openssl-windows_x64-windows-static\lib"
LTLIBS = $(LTLIBS) libcrypto.lib libssl.lib
!ELSEIF "$(PLATFORM)"=="x86"
LTLIBPATHS = $(LTLIBPATHS) /LIBPATH:"openssl-windows_x86-windows-static\lib"
LTLIBS = $(LTLIBS) libcrypto32.lib libssl32.lib
!ENDIF

# for OpenSSL: https://github.com/openssl/openssl/blob/3d362f190306b62a17aa2fd475b2bc8b3faa8142/NOTES.WIN#L112
LTLIBS = $(LTLIBS) WS2_32.Lib Gdi32.Lib AdvAPI32.Lib Crypt32.Lib User32.Lib
```
Finally, run `nmake /f Makefile.msc` command, and `sqlcipher.dll` will be generated.

## Linux
Make sure OpenSSL headers are installed on your workstation. Using package managers is a great choice.  
  
```bash
export SQLITE_HAS_CODEC
export SQLITE_TEMP_STORE=2

./configure --enable-tempstore=yes LDFLAGS="-lcrypto"
```
Then, call the make tool
```bash
make
```
`libsqlite3.so` (instead of `libsqlcipher.so`) will be generated.

Compiling on macOS seems to follow the same routine save that a .dylib file substitutes the .so file.