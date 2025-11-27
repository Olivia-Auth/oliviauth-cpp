# Download Dependencies

This folder should contain the following files. Download them before compiling.

## 1. json.hpp (nlohmann/json)

**Download from:** https://github.com/nlohmann/json/releases

1. Go to the latest release
2. Download `json.hpp` from `single_include/nlohmann/json.hpp`
3. Place it in this folder as `json.hpp`

Direct link (may be outdated):
https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp

## 2. httplib.h (cpp-httplib)

**Download from:** https://github.com/yhirose/cpp-httplib

1. Go to the repository
2. Download `httplib.h` from the root
3. Place it in this folder as `httplib.h`

Direct link:
https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h

## 3. OpenSSL

**Download from:** https://slproweb.com/products/Win32OpenSSL.html

1. Download Win64 OpenSSL v3.x.x (NOT Light version)
2. Install to default location
3. Copy files:

```
From: C:\Program Files\OpenSSL-Win64\include\openssl\*
To:   oliviauth/deps/openssl/include/openssl/

From: C:\Program Files\OpenSSL-Win64\lib\libssl.lib
To:   oliviauth/deps/openssl/lib64/libssl.lib

From: C:\Program Files\OpenSSL-Win64\lib\libcrypto.lib
To:   oliviauth/deps/openssl/lib64/libcrypto.lib
```

For x86 builds, also copy to `lib/` folder.

## Final Structure

After downloading, this folder should look like:

```
deps/
├── json.hpp              <- nlohmann/json single header
├── httplib.h             <- cpp-httplib single header
├── DOWNLOAD_DEPS.md      <- This file
└── openssl/
    ├── include/
    │   └── openssl/
    │       ├── ssl.h
    │       ├── rsa.h
    │       ├── evp.h
    │       ├── pem.h
    │       ├── rand.h
    │       ├── err.h
    │       ├── sha.h
    │       ├── hmac.h
    │       ├── bio.h
    │       ├── buffer.h
    │       └── ... (all OpenSSL headers)
    ├── lib/              <- x86 libraries
    │   ├── libssl.lib
    │   └── libcrypto.lib
    └── lib64/            <- x64 libraries
        ├── libssl.lib
        └── libcrypto.lib
```
