# Getting Started

The best way to get started with OFRAK is to go through the interactive tutorial.

Run it with the following commands:
```shell
make tutorial-image  # create the Docker image for the tutorial
make tutorial-run
```

Once the Ghidra server has started and the Jupyter notebook is up (this should take about one minute), follow the displayed instructions to access the Jupyter noteboks and have fun!

Once you've completed the tutorial, you'll be interested in the following resources (which you can see on the left of this page):

- **More details** about how OFRAK works and how to use it: `User Guide` and `Contributor Guide`;
- **References**: `Examples`, covering common tasks you might want to perform with OFRAK, and the `Code Reference`.

#Frequently Asked Questions (FAQ)

_Why do my CodeRegions not have any code?_

- You probably forgot to discover the analysis/disassembler backend you intended to use.
- When **not** using the Ghidra analysis backend you will also need to discover the capstone components.
- Check out the [Ghidra Backend User Guide](./user-guide/ghidra.md) and [Binary Ninja Backend User Guides](./user-guide/binary_ninja.md).

_I ran a modifier and flushed the resource. The bytes did change, but my view is reporting the same values. Why?_

- The bytes may have changed, but the analysis that depends on those bytes may not have been forced to re-run. You can force this analysis to update by re-running `await resource.view_as` if you want to get an updated view after modifying data the view depends on.

<div align="right">
<img src="./assets/square_01.png" width="125" height="125">
</div>
