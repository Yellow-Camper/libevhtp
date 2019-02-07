| ![LOGO](http://i.imgur.com/uBd4iIz.png) | <h1>Libevhtp</h1> |
| :------------- | -------------: |

[![Build Status](https://travis-ci.org/criticalstack/libevhtp.svg?branch=develop)](https://travis-ci.org/criticalstack/libevhtp)
[![Gitter](https://badges.gitter.im/criticalstack/libevhtp.svg)](https://gitter.im/criticalstack/libevhtp?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
[![Packaging status](https://repology.org/badge/tiny-repos/libevhtp.svg)](https://repology.org/metapackage/libevhtp/versions)

<a href="https://scan.coverity.com/projects/libevhtp">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/15294/badge.svg"/>
</a>

## Required Dependencies
* [gcc](http://gcc.gnu.org/) or [clang](https://clang.llvm.org/)
* [Libevent2](http://libevent.org)
* [CMake](http://cmake.org)

## Optional Dependencies
* [OpenSSL](http://openssl.org)
* pthreads
* [onig (regex)](https://github.com/kkos/oniguruma)

## Building
* cd build
* cmake ..
* make
* make examples

## For Windows MinGW
* cmake -G "MSYS Makefiles" -DCMAKE_INCLUDE_PATH=/mingw/include -DCMAKE_LIBRARY_PATH=/mingw/lib -DCMAKE_INSTALL_PREFIX=/mingw  .
* make

## Performance stuff

While we never documented any benchmark publically,
the popular open source project [ZIMG](http://zimg.buaa.us) did a bit of that
for us.The ZIMG team decided to move away from NGINX to libevhtp for their
software, and the results were pretty outstanding. Here is a graph showing their
application under very high load

![ZIMG GRAPH](/zimg_vs_nginx.png)

The X-axis is the number of connections, while the Y-axis is requests per
second.

You can read the whole article here: [Architecture Design of an Image Server](http://zimg.buaa.us/documents/Architecture_Design_of_Image_Server/)

Slightly outdated (Now faster!)
![HI NGINX](http://i.imgur.com/kiSkSLH.png)
