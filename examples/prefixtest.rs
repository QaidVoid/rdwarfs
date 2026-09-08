use std::time::Instant;
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let image = rdwarfs::format::Image::open(&path).unwrap();
    let rec = *image
        .sections()
        .iter()
        .filter(|s| s.header.section_type == rdwarfs::format::SectionType::Block)
        .max_by_key(|s| s.header.payload_len)
        .unwrap();
    println!("  codec {:?}", rec.header.compression);
    for want in [1usize << 20, 4 << 20, 16 << 20] {
        let t = Instant::now();
        let got = image.decompress_section_prefix(&rec, want).unwrap();
        println!(
            "  prefix {:>4} MiB -> {:?} bytes in {:.1} ms",
            want >> 20,
            got.as_ref().map(|v| v.len()),
            t.elapsed().as_secs_f64() * 1000.0
        );
    }
    let t = Instant::now();
    let full = image.decompress_section(&rec, 1 << 26).unwrap();
    println!(
        "  full  {} bytes in {:.1} ms",
        full.len(),
        t.elapsed().as_secs_f64() * 1000.0
    );
}
