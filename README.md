![crates.io](https://img.shields.io/crates/v/porkchop.svg)

# porkchop

Decryption utility for Yaesu ham radio firmware images.

## Background

Yaesu provides a firmware update utility for their ham radios that contains an encrypted firmware image. This utility reimplements the decryption algorithm found in the update utility and emits a decrypted image.

A more in-depth blog post about how the encryption works can be found [on my blog](https://landaire.net//yaesu-obfuscation/).

## Building

```
git clone https://github.com/landaire/porkchop.git
cd porkchop
cargo build
```

You can optionally install it direct from crates.io:

```
cargo install porkchop
```

## Usage

```
porkchop 0.1.0
Decryption utility for Yaesu ham radio firmware images.

USAGE:
    porkchop <input> [output]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <input>     Input file
    <output>    Output file, stdout if not present
```

Example:

```
porkchop firmware_update_utility.exe firmware.bin
```

