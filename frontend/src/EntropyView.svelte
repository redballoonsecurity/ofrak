<style>
  canvas,
  .tall {
    margin: 0;
    padding: 0;
    width: 100%;
    height: calc(100% - 2em);
    max-width: 64px;
    flex-grow: 1;
    flex-shrink: 1;
    border: 1px solid var(--main-fg-color);
  }

  canvas {
    cursor: pointer;
    /* https://stackoverflow.com/a/18556117 */
    image-rendering: -moz-crisp-edges;
    image-rendering: -webkit-optimize-contrast;
    image-rendering: -o-crisp-edges;
    image-rendering: crisp-edges;
    -ms-interpolation-mode: nearest-neighbor;
    image-rendering: optimizeSpeed;
    image-rendering: pixelated;
  }
</style>

<script>
  import LoadingTextVertical from "./LoadingTextVertical.svelte";

  import { hexToByteArray } from "./helpers.js";
  import { selectedResource } from "./stores.js";

  import { onMount } from "svelte";

  export let scrollY;
  let data = undefined;

  async function loadData(resource) {
    await resource.data_summary();
    let summaryAttributes =
      resource.get_attributes()["ofrak.core.entropy.entropy.DataSummary"];
    data =
      summaryAttributes !== undefined
        ? hexToByteArray(summaryAttributes?.entropy_samples)
        : undefined;
  }

  $: if (selectedResource !== undefined && $selectedResource !== undefined) {
    data = undefined;
    let summaryAttributes =
      $selectedResource.get_attributes()[
        "ofrak.core.entropy.entropy.DataSummary"
      ];
    if (summaryAttributes !== undefined) {
      data = hexToByteArray(summaryAttributes?.entropy_samples);
    } else {
      loadData($selectedResource);
    }
  }

  const alignment = 64;
  let mounted = false,
    clicking = false;
  let canvas, imageData;
  $: if (canvas !== undefined && canvas !== null && data !== undefined) {
    canvas.width = alignment;
    canvas.height = Math.max(Math.floor(data.length / alignment), 1);
  }

  onMount(() => {
    mounted = true;
  });

  $: if (
    mounted &&
    canvas !== undefined &&
    canvas !== null &&
    data !== undefined
  ) {
    const context = canvas.getContext("2d");
    imageData = context.createImageData(canvas.width, canvas.height);

    for (let i = 0; i < data.length; i++) {
      const value = data[i];

      // There are four colors per pixel, hence four array entries per byte of data
      const index = i * 4;
      imageData.data[index + 0] = value;
      imageData.data[index + 1] = value;
      imageData.data[index + 2] = value;
      // Always use 100% opacity
      imageData.data[index + 3] = 255;
    }
  }

  $: if (mounted && canvas !== undefined && canvas !== null && imageData) {
    const context = canvas.getContext("2d");
    context.putImageData(imageData, 0, 0);

    context.strokeStyle = "red";
    context.lineWidth = Math.ceil(canvas.height / 512);
    if (
      data !== undefined &&
      data.length > alignment * 3 &&
      $scrollY.viewHeight !== 1
    ) {
      // Offset Y by 0.5 because of: https://stackoverflow.com/a/48970774
      context.strokeRect(
        0,
        Math.ceil($scrollY.top * canvas.height) - 0.5,
        alignment,
        Math.ceil(($scrollY.viewHeight * canvas.height) / 2)
      );
    }

    context.imageSmoothingEnabled = false;
    context.mozImageSmoothingEnabled = false;
    context.webkitImageSmoothingEnabled = false;
    context.msImageSmoothingEnabled = false;
  }
</script>

{#if data !== undefined}
  <canvas
    bind:this="{canvas}"
    on:mousedown="{(e) => {
      if ($scrollY.viewHeight < 1) {
        $scrollY.top = e.offsetY / canvas.offsetHeight;
        $scrollY.top = Math.max(Math.min($scrollY.top, 1), 0);
        clicking = true;
      }
    }}"
    on:mouseup="{(e) => {
      clicking = false;
    }}"
    on:mouseleave="{(e) => {
      clicking = false;
    }}"
    on:mousemove="{(e) => {
      if (clicking && $scrollY.viewHeight < 1) {
        $scrollY.top = e.offsetY / canvas.offsetHeight;
        $scrollY.top = Math.max(Math.min($scrollY.top, 1), 0);
      }
    }}"
    on:wheel="{(e) => {
      if ($scrollY.viewHeight < 1) {
        $scrollY.top += e.deltaY * 0.0001;
        $scrollY.top = Math.max(Math.min($scrollY.top, 1), 0);
      }
    }}"
  >
    Entropy graph
  </canvas>
{:else}
  <div class="tall">
    <LoadingTextVertical />
  </div>
{/if}
