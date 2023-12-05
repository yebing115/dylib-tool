use std::collections::HashSet;
use std::io::Write;

use anyhow::Context;
use anyhow::Ok;
use clap::Parser;
use goblin::mach::header;
use goblin::mach::load_command::Dylib;
use goblin::mach::load_command::DylibCommand;
use goblin::mach::load_command::LC_LOAD_DYLIB;
use goblin::mach::parse_magic_and_ctx;
use goblin::mach::Mach;
use goblin::mach::MachO;
use goblin::mach::SingleArch;
use scroll::Pread;
use scroll::{ctx::SizeWith, IOwrite};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The MachO file
    #[arg(short, long)]
    file: String,

    /// The output file
    #[arg(short, long)]
    output: String,

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

    let mut dels = HashSet::new();
    for d in args.dels {
        dels.insert(d);
    }

    let mut adds = HashSet::new();
    for a in args.adds {
        adds.insert(a);
    }

    let mut macho_data = std::fs::read(&args.file)?;

    if !dels.is_empty() {
        uninstall_dylibs(&mut macho_data, &dels)?;
    }

    if !adds.is_empty() {
        install_dylibs(&mut macho_data, &adds)?;
    }
    std::fs::write(&args.output, macho_data)?;

    Ok(())
}

fn parse_macho<'a>(macho_data: &'a [u8]) -> anyhow::Result<Vec<MachOInfo<'a>>> {
    let mach = Mach::parse(macho_data)?;

    match mach {
        Mach::Binary(macho) => Ok(vec![MachOInfo {
            macho: macho,
            offset: 0,
            data: macho_data,
        }]),
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
                    data: arch.slice(macho_data),
                });
            }

            Ok(machos)
        }
    }
}

fn install_dylibs(macho_data: &mut Vec<u8>, dylibs: &HashSet<String>) -> anyhow::Result<()> {
    let machos = parse_macho(macho_data)?;

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

        let old_header = &macho_arch.macho.header;
        let header_size = header::Header::size_with(&ctx);

        let lc_free_space = (text_section_offset - old_header.sizeofcmds) as usize - header_size;

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
        let cmds_size = all_bytes.len();
        if lc_free_space < cmds_size {
            return Err(anyhow::Error::msg(format!(
                "Not enough Load Command free space, need={}, got={}",
                cmds_size, lc_free_space
            )));
        }

        let lc_codesign = macho_arch
            .macho
            .load_commands
            .iter()
            .find(|lc| match lc.command {
                goblin::mach::load_command::CommandVariant::CodeSignature(_) => true,
                _ => false,
            });

        match lc_codesign {
            Some(lc) => {
                // move codesign data
                let move_len = (header_size + old_header.sizeofcmds as usize) - lc.offset;
                modifications.push(MachOModification {
                    offset: macho_arch.offset + cmds_size + lc.offset as usize,
                    data: macho_arch.data[lc.offset..][..move_len].to_vec(),
                });

                // add load dylib command
                modifications.push(MachOModification {
                    offset: macho_arch.offset + lc.offset as usize,
                    data: all_bytes,
                });
            }
            None => {
                modifications.push(MachOModification {
                    offset: macho_arch.offset + header_size + old_header.sizeofcmds as usize,
                    data: all_bytes,
                });
            }
        }

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

    Ok(())
}

fn uninstall_dylibs(macho_data: &mut Vec<u8>, dylibs: &HashSet<String>) -> anyhow::Result<()> {
    let machos = parse_macho(macho_data)?;

    let mut modifications = Vec::new();

    for macho_arch in machos {
        let ctx = parse_magic_and_ctx(macho_arch.data, 0)?
            .1
            .expect("context should have been parsed before");

        let old_header = &macho_arch.macho.header;
        let header_size = header::Header::size_with(&ctx);

        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let mut ncmds = 0;
        for lc in &macho_arch.macho.load_commands {
            match &lc.command {
                goblin::mach::load_command::CommandVariant::LoadDylib(c)
                | goblin::mach::load_command::CommandVariant::LoadWeakDylib(c)
                | goblin::mach::load_command::CommandVariant::LoadUpwardDylib(c) => {
                    let name = macho_arch
                        .data
                        .pread::<&str>(lc.offset + c.dylib.name as usize)?;
                    if !dylibs.contains(name) {
                        cursor.write(&macho_arch.data[lc.offset..][..lc.command.cmdsize()])?;
                        ncmds += 1;
                    }
                }
                c => {
                    cursor.write(&macho_arch.data[lc.offset..][..c.cmdsize()])?;
                    ncmds += 1;
                }
            }
        }

        // clear old cmds
        modifications.push(MachOModification {
            offset: macho_arch.offset + header_size,
            data: b"\0".repeat(old_header.sizeofcmds as usize),
        });

        // copy new cmds
        let cmds_bytes = cursor.into_inner();
        let cmds_size = cmds_bytes.len();
        modifications.push(MachOModification {
            offset: macho_arch.offset + header_size,
            data: cmds_bytes,
        });

        // modify header
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let mut header = macho_arch.macho.header;
        header.ncmds = ncmds;
        header.sizeofcmds = cmds_size as u32;
        cursor.iowrite_with(header, ctx)?;
        modifications.push(MachOModification {
            offset: macho_arch.offset,
            data: cursor.into_inner(),
        });
    }

    for m in modifications {
        macho_data[m.offset..][..m.data.len()].copy_from_slice(&m.data);
    }

    Ok(())
}
