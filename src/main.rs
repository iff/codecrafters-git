use clap::{Parser, Subcommand};

pub(crate) mod commands;
pub(crate) mod object;
pub(crate) mod pack;

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
    Clone {
        #[arg(action)]
        url: String,
        #[arg(action)]
        path: Option<String>,
    },
    CommitTree {
        #[arg(short = 'p')]
        parent: Option<String>,
        #[arg(short = 'm')]
        message: String,
        #[arg(action)]
        tree: String,
    },
    HashObject {
        #[arg(short = 'w')]
        write: bool,
        #[arg(action)]
        path: String,
    },
    LsTree {
        #[arg(long)]
        name_only: bool,
        #[arg(action)]
        hash: String,
    },
    WriteTree {},
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Command::CatFile { pretty, hash } => commands::cat_file::invoke(pretty, &hash),
        Command::Clone { url, path } => commands::clone::invoke(&url, path),
        Command::CommitTree {
            parent,
            message,
            tree,
        } => commands::commit_tree::invoke(&message, parent, &tree),
        Command::Init {} => commands::init::invoke(),
        Command::HashObject { write, path } => commands::hash_object::invoke(write, &path),
        Command::LsTree { name_only, hash } => commands::ls_tree::invoke(name_only, &hash),
        Command::WriteTree {} => commands::write_tree::invoke(),
    }
}
