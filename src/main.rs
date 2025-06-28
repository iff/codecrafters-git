use clap::{Parser, Subcommand};

pub(crate) mod commands;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
#[clap(rename_all = "kebab_case")]
enum Command {
    Init {},
    CatFile {
        #[arg(short = 'p')]
        pretty: bool,
        #[arg(action)]
        hash: String,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::CatFile { pretty, hash } => commands::cat_file::invoke(pretty, &hash),
        Command::Init {} => commands::init::invoke(),
    }
}
