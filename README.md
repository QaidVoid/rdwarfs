# rdwarfs

An independent Rust library and tool set for reading
[DwarFS](https://github.com/mhx/dwarfs) images.

DwarFS is a read-only filesystem image format built for deduplication and
compression. `rdwarfs` reads those images from Rust, with no C++
toolchain and a dependency graph that is four crates for a plain reader.

## Attribution

Written from the MIT-licensed format documentation
(`doc/dwarfs-format.md`) and interface definitions
(`thrift/metadata.thrift`, `history.thrift`, `compression.thrift`,
`features.thrift`) published by the DwarFS project. Two encodings come
from elsewhere, both permissively licensed: Frozen2 from
[fbthrift](https://github.com/facebook/fbthrift) (Apache-2.0) and FSST
from the [reference implementation](https://github.com/cwida/fsst)
(MIT), a published algorithm by Peter Boncz, Viktor Leis and Thomas
Neumann.

Images are read only. Test fixtures are produced by upstream `mkdwarfs`
and committed under `tests/vectors`; regenerate them with
`tests/make-vectors.sh`.

## Status

The library reads format version 2.5 images across the upstream 0.15
tools' ordering, packing, codec, and block-size options. FLAC and RICEPP
compressed sections are recognised but not decoded.

## Binaries

| Binary | Purpose |
| --- | --- |
| `dwarfsck` | Inspect and verify an image |
| `dwarfsextract` | Extract an image to a directory or a tar stream |
| `dwarfs` | Mount an image read-only over FUSE |

```
dwarfsck -i image.dwarfs --check-integrity
dwarfsextract -i image.dwarfs -o ./out
dwarfs image.dwarfs /mnt/point
```

An image embedded in a larger file is read by giving its byte range:

```
dwarfsextract -i packed.bin -O 100000 --image-size 504618 -o ./out
```

## Compression levels

`-l` selects a bundle, not a single knob: a block size and a codec for
each kind of section. Individual flags override their own part of it, so
`-l 9 -S 22` means level 9 everything except the block size.

| Level | Block size | Block data | Schema | Metadata |
| --- | --- | --- | --- | --- |
| 0 | 1 MiB | none | none | none |
| 1 | 1 MiB | lz4 | zstd:16 | none |
| 2 | 1 MiB | lz4hc:9 | zstd:16 | none |
| 3 | 2 MiB | lz4hc:9 | zstd:16 | none |
| 4 | 4 MiB | zstd:11 | zstd:16 | none |
| 5 | 8 MiB | zstd:19 | zstd:16 | none |
| 6 | 16 MiB | zstd:22 | zstd:16 | none |
| 7 | 16 MiB | zstd:22 | zstd:16 | zstd:22 |
| 8 | 16 MiB | lzma:9 | zstd:16 | lzma:9 |
| 9 | 64 MiB | lzma:9 | zstd:16 | lzma:9 |

`--order` chooses how file content reaches the segmenter: `none` (walk
order), `path` (the default), `revpath` (groups by extension), or
`similarity` (groups files whose content resembles each other).
Deduplication here is global rather than windowed, so path order, which
keeps a directory's files together, is usually already the best choice;
`similarity` is provided for parity and rarely wins.

The default is level 7. The table mirrors the one the reference
implementation documents, so the same `-l` produces a comparable image
from either tool.

## Features

Reading and writing are independent. Enable only what you need.

| Feature | Default | Effect |
| --- | --- | --- |
| `read` | yes | Open images, traverse metadata, read file content |
| `fuse` | no | FUSE adapter and the `dwarfs` binary; implies `read` |
| `zstd` | yes | Zstandard codec |
| `lzma` | yes | LZMA codec, framed as xz |
| `lz4` | yes | LZ4 and LZ4HC codecs |
| `brotli` | yes | Brotli codec |
| `tar` | yes | Tar output for `dwarfsextract` |
| `cli` | yes | The four binaries and their argument parser |
| `parallel` | yes | Compress and extract across a thread pool |
| `mmap` | yes | Memory-map an image opened by path |
| `flac` | no | Reserved; decoding is not implemented |
| `ricepp` | no | Reserved; decoding is not implemented |

A codec contributes only the directions the capability features enable.
Building with `read` and `zstd` gives a zstd decoder and no encoder.

`parallel` and `mmap` are deliberately not implied by `read`.
Cargo unifies features across a build graph, so a workspace that holds
both a bulk extractor and a size-constrained reader has to be able to enable
them for one and not the other. A read-only build pulls in five
dependencies:

```
$ cargo tree --no-default-features --features read,zstd --depth 1
rdwarfs
|-- libc
|-- sha2
|-- thiserror
|-- xxhash-rust
`-- zstd
```

## Reading

An image is read through an `ImageSource`. `Vec<u8>` and `FileSource`
are provided; `FileSource` reads positionally and maps nothing, which
is what to use when an I/O fault must surface as an error.

```rust,ignore
use rdwarfs::format::{FileSource, Image};
use rdwarfs::fs::Filesystem;

let image = Image::from_source(FileSource::open("image.dwarfs")?)?;
let fs = Filesystem::open(image)?;

for entry in fs.walk()? {
    println!("{}", String::from_utf8_lossy(&entry.path));
}

let node = fs.lookup(b"/usr/bin/tool")?;
let bytes = fs.read_file(node.inode)?;
```

`Filesystem::read_at` reads a byte range through a caller-supplied
`BlockCache`, so a reader can serve arbitrary offsets without
materialising a whole file.

## Reading from an embedded image

```rust,ignore
use rdwarfs::format::{FileSource, Image};
use rdwarfs::fs::{BlockCache, Filesystem};

// The image lives at `offset..offset + len` inside a larger file.
let source = FileSource::open("packed-binary")?;
let fs = Filesystem::open(Image::from_window(source, offset, len)?)?;

let node = fs.lookup(b"/docs/readme.txt")?;
let cache = BlockCache::new(8 << 20);
let bytes = fs.read_at(node.inode, 0, 4096, &cache)?;
```

No thread pool is reachable from this path, and nothing larger than the
cache budget is held resident.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
