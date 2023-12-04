use std::io::Write;

use anyhow::Context;
use clap::Parser;
use goblin::mach::header;
use goblin::mach::load_command::Dylib;
use goblin::mach::load_command::DylibCommand;
use goblin::mach::load_command::LC_LOAD_DYLIB;
use goblin::mach::parse_magic_and_ctx;
use goblin::mach::Mach;
use goblin::mach::MachO;
use goblin::mach::SingleArch;
use scroll::{ctx::SizeWith, IOwrite};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The MachO file
    #[arg(short, long)]
    file: String,

    /// The dylibs to install
    #[arg(short, long)]
    adds: Vec<String>,

    /// The dylibs to uninstall
    #[arg(short, long)]
    dels: Vec<String>,
}

pub struct MachOInfo<'a> {
    /// The parsed Mach-O binary.
    pub macho: MachO<'a>,

    // The offset
    pub offset: usize,

    /// The raw data backing the Mach-O binary.
    pub data: &'a [u8],
}

pub struct MachOModification {
    // The offset
    pub offset: usize,

    /// The raw data backing the Mach-O binary.
    pub data: Vec<u8>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let macho_data = std::fs::read(&args.file)?;

    let macho_data = install_dylibs(macho_data, &args.adds)?;

    std::fs::write("g:\\dms.bin", macho_data)?;

    Ok(())
}

fn install_dylibs(mut macho_data: Vec<u8>, dylibs: &Vec<String>) -> anyhow::Result<Vec<u8>> {
    let mach = Mach::parse(&macho_data)?;

    let machos = match mach {
        Mach::Binary(macho) => vec![MachOInfo {
            macho: macho,
            offset: 0,
            data: &macho_data,
        }],
        Mach::Fat(multiarch) => {
            let mut machos = vec![];

            for (index, arch) in multiarch.arches()?.into_iter().enumerate() {
                let macho = match multiarch.get(index)? {
                    SingleArch::MachO(m) => m,
                    SingleArch::Archive(_) => continue,
                };

                machos.push(MachOInfo {
                    macho: macho,
                    offset: arch.offset as usize,
                    data: arch.slice(&macho_data),
                });
            }

            machos
        }
    };

    let mut modifications = Vec::new();

    for macho_arch in machos {
        let ctx = parse_magic_and_ctx(macho_arch.data, 0)?
            .1
            .expect("context should have been parsed before");

        let text_seg = macho_arch
            .macho
            .segments
            .iter()
            .find(|s| {
                let name = s.name().ok();
                match name {
                    Some(n) => n == "__TEXT",
                    None => false,
                }
            })
            .context("No __TEXT segment")?;

        let text_section_offset = text_seg
            .sections()?
            .iter()
            .find(|s| {
                let name = s.0.name().ok();
                match name {
                    Some(n) => n == "__text",
                    None => false,
                }
            })
            .map(|s| &s.0)
            .context("No __text section")?
            .offset;

        let header_size = header::Header::size_with(&ctx);

        let lc_free_space =
            (text_section_offset - macho_arch.macho.header.sizeofcmds) as usize - header_size;

        println!("lc_free_space is {}", lc_free_space);

        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        for dylib in dylibs {
            let name_bytes = dylib.as_bytes();
            let total = name_bytes.len() + (8 - name_bytes.len() % 8);

            let mut name: Vec<u8> = Vec::with_capacity(total);
            name.extend_from_slice(name_bytes);
            name.resize(total, 0);

            let lc = DylibCommand {
                cmd: LC_LOAD_DYLIB,
                cmdsize: 0x18 + name.len() as u32,
                dylib: Dylib {
                    name: 0x18,
                    timestamp: 2,
                    current_version: 0,
                    compatibility_version: 0,
                },
            };

            cursor.iowrite_with(lc, ctx.le)?;
            cursor.write(&name)?;
        }

        let all_bytes = cursor.into_inner();

        if lc_free_space < all_bytes.len() {
            return Err(anyhow::Error::msg(format!(
                "Not enough Load Command free space, need={}, got={}",
                all_bytes.len(),
                lc_free_space
            )));
        }

        // modify LoadCommand
        let cmds_size = all_bytes.len();
        modifications.push(MachOModification {
            offset: macho_arch.offset + header_size + macho_arch.macho.header.sizeofcmds as usize,
            data: all_bytes,
        });

        // modify header
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let mut header = macho_arch.macho.header;
        header.ncmds += dylibs.len();
        header.sizeofcmds += cmds_size as u32;
        cursor.iowrite_with(header, ctx)?;
        modifications.push(MachOModification {
            offset: macho_arch.offset,
            data: cursor.into_inner(),
        });
    }

    for m in modifications {
        macho_data[m.offset..][..m.data.len()].copy_from_slice(&m.data);
    } 

    Ok(macho_data)
}
