from ofrak.ofrak_cli import setup_ofrak_cli_argparser, ListSubCommand, DepsSubCommand

if __name__ == "__main__":
    subcommands = [ListSubCommand(), DepsSubCommand()]
    parser = setup_ofrak_cli_argparser(subcommands)
    args = parser.parse_args()

    args.func(args)
