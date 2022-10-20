# Getting Started

## Tutorial

The best way to get started with OFRAK is to go through the interactive tutorial.

Run it with the following commands:

```shell
make tutorial-image  # create the Docker image for the tutorial
make tutorial-run
```

It takes a minute for the notebook to start up. Once running, you can access the tutorial from [localhost:8888](http://localhost:8888) with your web browser. Have fun!

## GUI

OFRAK comes with a web-based GUI frontend for visualizing and manipulating binary targets. The OFRAK GUI runs by default in most of the OFRAK images, including the tutorial image. (Note that for now, the frontend is only built in the `ofrak_ghidra` and `ofrak_binary_ninja` analyzer backend configurations.)

To access the GUI, navigate to <http://localhost> and start by dropping anything you'd like into it!

## Docs

The official documentation for the most up-to-date OFRAK lives at <https://ofrak.com/docs/>.

If you would like to generate the docs yourself for offline viewing, follow the instructions in the [`docs/README.md`](https://github.com/redballoonsecurity/ofrak/blob/master/docs/README.md) file.

## Guides and examples

Once you've completed the tutorial, you'll be interested in the following resources (which you can see on the left of this page):

- More details about how OFRAK works and how to use it: `User Guide` and `Contributor Guide`;
- References: `Examples`, covering common tasks you might want to perform with OFRAK, and the `Code Reference`.

## Frequently Asked Questions (FAQ)

_Why do my CodeRegions not have any code?_

- You probably forgot to discover the analysis/disassembler backend you intended to use.
- When **not** using the Ghidra analysis backend you will also need to discover the capstone components.
- Check out the [Ghidra Backend User Guide](./user-guide/ghidra.md) and [Binary Ninja Backend User Guides](./user-guide/binary_ninja.md).

_I ran a modifier and flushed the resource. The bytes did change, but my view is reporting the same values. Why?_

- The bytes may have changed, but the analysis that depends on those bytes may not have been forced to re-run. You can force this analysis to update by re-running `await resource.view_as` if you want to get an updated view after modifying data the view depends on.

<div align="right">
<img src="./assets/square_01.png" width="125" height="125">
</div>
