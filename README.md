CPUMiner
========

This is a multi-threaded CPU miner, fork of [hyc](//github.com/hyc)' cpuminer-multi.

#### Table of contents

* [Algorithms](#algorithms)
* [Dependencies](#dependencies)
* [Download](#download)
* [Build](#build)
* [Usage instructions](#usage-instructions)
* [Donations](#donations)
* [Credits](#credits)
* [License](#license)

Algorithms
==========
#### Currently supported
 * ✓ __KangarooTwelve__ (Aeon)

Dependencies
============
* libcurl			http://curl.haxx.se/libcurl/
* jansson			http://www.digip.org/jansson/ (jansson is included in-tree)

Download
========
* No binary release, user are recommended to self compile.

Build
=====

#### Basic *nix build instructions:
 * ./autogen.sh	# only needed if building from git repo
 * Optimal GCC flags are built in - you only need to use -march=native if you want it
 * CFLAGS="*-march=native*" ./configure
   * # Use -march=native if building for a single machine
 * make

#### Architecture-specific notes:
 * This miner works only on x86 and x86-64. Feel free to port to other arch.
 * The build system will auto detect whether your cpu is 64 or 32 bit.

Usage instructions
==================
Run "minerd --help" to see options.

### Connecting through a proxy

Use the --proxy option.

To use a SOCKS proxy, add a socks4:// or socks5:// prefix to the proxy host  
Protocols socks4a and socks5h, allowing remote name resolving, are also available since libcurl 7.18.0.

If no protocol is specified, the proxy is assumed to be a HTTP proxy.  
When the --proxy option is not used, the program honors the http_proxy and all_proxy environment variables.

### Solo mining

Using bitmonerod v0.9.3.1 or newer, specify your url as "daemon+tcp://<host>:<port>/json_rpc"

Donations
=========
Donations for the work done in this fork are accepted at
* AEON: `WmsLqy8dcJRdafR96Nd3UZCUx83JhS3FRi4ftwZG6sxdGRNTTrrAh6zXuacpCEyZZ7ZMACcthMU3pMHbg4zZ9nqv2TQyL992U`

Credits
=======
This CPUMiner-multi was forked from hyc@github. Originally it was a cryptonight miner fork developed by Wolf
from LucasJones's miner.
Daemon solo mining was developed by hyc@github.

License
=======
GPLv2.  See COPYING for details.
