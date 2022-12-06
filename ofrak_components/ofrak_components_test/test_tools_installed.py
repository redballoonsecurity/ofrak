from ofrak.ofrak_cli import OFRAKCommandLineInterface


def test_install_checks():
    ofrak_cli = OFRAKCommandLineInterface()
    ofrak_cli.parse_and_run(["deps", "--package", "ofrak_components", "-c"])
