# nShark v1.0

> **Note**:
> This project was originally developed six years ago (uploaded in 2024) as a personal learning exercise. It was stored in my archives for a long time before being uploaded for portfolio purposes. It was intended to serve as a stepping stone in my development journey and to showcase my progress at the time. However, please note that the project has not been actively maintained since its creation. It may contain bugs, outdated dependencies, or inefficiencies that reflect my skill level during the initial development phase. As such, this project should primarily be viewed as a learning resource rather than a fully functional or production-ready tool. Contributions and updates are not expected, and users are encouraged to use it for educational purposes rather than practical applications.

nShark is a network scanning tool written in C++, designed to explore various network scanning techniques. This project was originally created to learn about network security concepts and improve C++ programming skills.

```
         .''''''''.         -< nShark v1.0 by h3xbu4n34 (a.k.a ihuomtia) >-
        /  /o\ /o\ \    Contact me at: ihuomtia at google mail dot com
       /  /\/\/\/\/\    Usage:
  /---/   \/\/\/\/\/            -h <host[s]> : specify one or more hosts.
  \  /            /             -p <port[s]> : specify one or more ports.
   \/           /               -c           : use connect scan *0 (!R).
   /          /                 -s           : use stealth syn scan (R).
  /         /                   -n           : use stealth null scan (R).
 /        /                     -x           : use stealth xmas scan (R).
 |       /                      -f           : use stealth fin scan (R).
 \     /                        -C           : disable colors *1.
  \   /                         -v           : be verbose.
   \  \                         -H           : show this help message.
    \   \                Explanation:
    /     \                     (R)          : requires root rights.
   /===|===\                    (!R)         : doesn't requires root rights.
   \/\/\/\/\/                   *0           : this is the default scan if you aren't the root user, otherwise syn.
                                *1           : disables colors, this is useful for some terminals.
  (  )  (  )  (  )  )    Examples:
 ()()()()()()()()()()(          syn scan      : nShark -h 127.0.0.1 -p 80,443,22,21 -s -v
() () () () () () () ()         fin scan      : nShark -h 192.168.1.1-255 -p 80-120 -f -v
()()()()()()()()()()()()(       xmas scan     : nShark -h google.com,youtube.com -p 443,80 -x
()()()()()()()()()()()()(       scan all ports: nShark -h 192.168.1.1-255,192.168.4.1/24 -p 0-65535
```

## Project Status

- **Not Maintained**: This project is no longer actively maintained or updated.
- **Contains Bugs**: As a learning project, it contains numerous bugs and inefficiencies.
- **Outdated Practices**: The code may not reflect current best practices in C++ or network security.
- **Learning Resource**: Despite its limitations, this project can serve as a starting point for those interested in learning about network scanning techniques and C++ programming.

## Features

- Multiple scanning techniques (for learning purposes):
  - Connect scan
  - Stealth SYN scan
  - Stealth NULL scan
  - Stealth XMAS scan
  - Stealth FIN scan
- Support for scanning multiple hosts and ports
- Verbose mode for detailed output
- Color-coded output (with option to disable)

## Prerequisites

- C++ compiler (supporting C++11 or later)
- Make
- Root privileges for certain scan types

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/nShark.git
   ```
2. Navigate to the project directory:
   ```
   cd nShark
   ```
3. Compile the project:
   ```
   make
   ```

## Usage

```
Usage:
  ./nShark [options]

Options:
  -h <host[s]> : specify one or more hosts
  -p <port[s]> : specify one or more ports
  -c           : use connect scan (default for non-root, doesn't require root)
  -s           : use stealth SYN scan (requires root)
  -n           : use stealth NULL scan (requires root)
  -x           : use stealth XMAS scan (requires root)
  -f           : use stealth FIN scan (requires root)
  -C           : disable colors
  -v           : be verbose
  -H           : show help message
```

## Examples

1. SYN scan:
   ```
   sudo ./nShark -h 127.0.0.1 -p 80,443,22,21 -s -v
   ```

2. FIN scan:
   ```
   sudo ./nShark -h 192.168.1.1-255 -p 80-120 -f -v
   ```

3. XMAS scan:
   ```
   sudo ./nShark -h google.com,youtube.com -p 443,80 -x
   ```

4. Scan all ports:
   ```
   sudo ./nShark -h 192.168.1.1-255,192.168.4.1/24 -p 0-65535
   ```

## Learning Opportunities

While this project is not suitable for production use, it offers several learning opportunities:

1. Understanding basic network scanning techniques
2. Exploring C++ programming concepts
3. Working with sockets and network protocols
4. Implementing command-line interfaces
5. Structuring a medium-sized C++ project

Readers are encouraged to identify bugs, inefficiencies, and areas for improvement as part of their learning process.

## Disclaimer

This tool is for educational purposes only. It contains bugs and should not be used in any production or real-world scanning scenarios. Ensure you have permission before scanning any networks or systems that you do not own or have explicit authorization to test.

## Contributing

As this is a personal learning project that is no longer maintained, contributions are not being accepted. However, feel free to fork the project and modify it for your own learning purposes.

## License

This project is open-source and available under the [MIT License](https://opensource.org/licenses/MIT).

## Contact

For any questions about this learning project, please contact the author at: ihuomtia at google mail dot com
