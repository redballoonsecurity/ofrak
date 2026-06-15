# OFRAK App

The OFRAK App is the primary graphical user interface for OFRAK. This repository
contains the front end code for this web-based interface.

The back end code is found [here](backend/ofrak_server.py).

## How to Run the Code for Development

On a computer with Docker installed, run the following command. This will start
up the proxy container, the back end container, and the front end container for
development.

```
make app-stack-dev
```

In order for the app stack to start up successfully, there must be a local build of
  an OFRAK Docker image tagged as `latest`. You can build this using:

```bash
python3 build_image.py --config ofrak-ghidra.yml --base --finish
```
See the [Docker instructions](../docs/install/docker.md) for more information.

The app server maps the repo directory into a NodeJS Docker container that
exposes port `8888`, compiles the code, and runs a web server. Any changes to
the repo files outside the container should cause the front end to be rebuilt
inside the container, which becomes visible after a browser refresh.

For publishing deployment versions of the app stack, it is possible to use the
image as part of a multi-stage Docker build in which the Svelte code is compiled
to static HTML, CSS, and JavaScript, and copied into the nginx container. 

Change the global variables at the top of the `Makefile` to configure how the
code is built and deployed.

## How to Read the Code

The front end code is written in Svelte. Svelte is an alternative to web
frameworks like React, Vue, and Angular.js. Unlike its competitors, Svelte is a
compiler that transforms `.svelte` files into static HTML, CSS, and JavaScript
to be deployed anywhere. Code written in these Svelte files is almost the same
as vanilla HTML, CSS, and JavaScript, but with less boilerplate.

The `Makefile` and `compose.yml` files demonstrate how different pieces of the
code fit together. The `Makefile` specifies how to run the Docker stack
described by the `compose.yml`. This stack has three components: an nginx
reverse proxy, a running instance of the OFRAK `aiohttp`-based back end, and a
live-rebuilding Svelte instance for thre front end. These containers in the
stack are specified in `backend/proxy.Dockerfile`,
`backend/ofrak_server.Dockerfile`, and `app.Dockerfile`, respectively.

The main front end application code is located in the `src` directory. The
`src/App.svelte` file is the top-level component that imports all of the other
components (which may, themselves, import other components). Each component is
in its own `.svelte` file. 

The following graph shows which components import which other components.

![](import-graph.png)

Helper functions live in `src/helpers.js`, and global [Svelte
stores](https://svelte.dev/docs#run-time-svelte-store) live in `src/stores.js`.
In `src/ofrak` there are JavaScript implementations of the OFRAK resource class
that fetch remote data from the back end. 

The `public` directory is the folder containing all of the static site material
that is served. Svelte compiles the source files into `dist`.

---

# Attribution

The GUI bundles royalty free synthwave music from Nihilore.

- <http://www.nihilore.com/synthwave>
- <http://www.nihilore.com/license>
