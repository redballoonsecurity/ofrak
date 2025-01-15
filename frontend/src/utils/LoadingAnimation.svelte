<style>
  .container {
    width: 100%;
    height: 100%;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: center;
    align-content: stretch;
  }

  .text {
    position: relative;
    /* TODO: Make this more dynamic */
    top: 125px;
    left: 0;
  }

  canvas {
    flex-grow: 1;

    width: 100%;
    height: 100%;
  }
</style>

<script context="module">
  const animations = ["/loading/cubes.spline", "/loading/stacks.spline"];
  let currentIndex = 0;

  let animationData = [];
  (async () => {
    for (const path of animations) {
      const dataBuffer = await fetch(path, { cache: "force-cache" })
        .then((r) => r.blob())
        .then((b) => b.arrayBuffer());
      animationData.push(new Uint8Array(dataBuffer));
    }

    currentIndex = Math.floor(Math.random() * animationData.length);
  })();
</script>

<script>
  import LoadingText from "./LoadingText.svelte";

  import { onDestroy, onMount } from "svelte";

  import { Application } from "@splinetool/runtime";

  let canvas, app, timeout;

  onMount(() => {
    timeout = setTimeout(() => {
      if (canvas) {
        app = new Application(canvas);
        app.start(animationData[currentIndex]);
        app.setZoom(0.75);

        currentIndex = (currentIndex + 1) % animationData.length;
      }
    }, 1500);
  });

  onDestroy(() => {
    if (app) {
      app.dispose();
    } else {
      clearTimeout(timeout);
    }
  });
</script>

<div class="container">
  <div class="text">
    <LoadingText />
  </div>
  <canvas bind:this="{canvas}"></canvas>
</div>
