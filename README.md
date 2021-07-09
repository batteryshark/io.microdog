# io_microdog
GSMH Emulation Layer and Replacement API

This project aims to bring an emulated GSMH client library into parity with the original MD3.3,MD3.4, and MD4.0 
RainbowChina MicroDog client libraries and make them available for modern operating system configurations.

In addition, driver emulation is also included for testing purposes.

What does this mean?

- "Full-Stack" emulation of GSMH solutions.
- Compile and run against real or simulated hardware.
- Compile against original vendor libraries or open-source.

What's Done?
- Generic Driver Emulation Logic (should work for everything)
- Linux Client Library 4.0 emulation (UNIX Sockets)

What's Left?
- Legacy undocumented functionality.
- Replacement 3.x Kernel Module
- Replacement 4.0 Daemon
- API Support for 3.x
- Windows Support 