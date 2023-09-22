import argparse
import os

from playwright.sync_api import sync_playwright


START_URL = "https://www.nxp.com/design/software/development-software/s32-design-studio-ide/s32-design-studio-for-power-architecture:S32DS-PA"


def run(page, email: str, password: str, outfile: str) -> None:
    print(f"Going to page {START_URL}", flush=True)
    page.goto(START_URL)
    page.get_by_role("listitem").filter(
        has_text="Build Tools NXP Embedded GCC for Power Architecture"
    ).filter(has_text="Linux").get_by_role("link", name="Download", exact=True).click()

    print("Signing in", flush=True)
    page.locator("#username").click()
    page.keyboard.type(email)
    page.locator("#password").click()
    page.keyboard.type(password)
    page.get_by_role("button", name="SIGN IN").click()

    print("Accepting terms and conditions", flush=True)
    page.get_by_role("button", name="I Accept").click()

    print("Waiting for download", flush=True)
    with page.expect_download() as download_info:
        # Download begins when the page is loaded
        pass
    os.rename(download_info.value.path(), outfile)

    print(f"Complete! Saved to {outfile}", flush=True)


def main(args):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        run(page, args.email, args.password, args.outfile)
        context.close()
        browser.close()


if __name__ == "__main__":
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("email")
    argument_parser.add_argument("password")
    argument_parser.add_argument(
        "-o", "--outfile", default="/tmp/gcc-4.9.4-Ee200-eabivle-x86_64-linux-g2724867.zip"
    )
    main(argument_parser.parse_args())
