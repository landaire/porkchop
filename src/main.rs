
use std::io::{Write};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(
    name = "porkchop",
    about = "Decryption utility for Yaesu ham radio firmware images."
)]
struct Opt {
    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,

    /// Output file, stdout if not present
    #[structopt(parse(from_os_str))]
    output: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let opt = Opt::from_args();
    let pe_data = std::fs::read(opt.input)?;

    let update_info = porkchop::update_info_from_pe(pe_data.as_slice())?;
    let decrypted_firmware = porkchop::decrypt(update_info)?;

    if let Some(output_file) = opt.output {
        std::fs::write(output_file, decrypted_firmware)?;
    } else {
        // Write to stdout
        let stdout = std::io::stdout();
        stdout.lock().write_all(decrypted_firmware.as_slice())?;
    }

    Ok(())
}
