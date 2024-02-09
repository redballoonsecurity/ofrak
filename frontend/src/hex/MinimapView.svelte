<style>
  .minimap {
    height: 100%;
    width: 100%;
  }
</style>

<script>
  import JumpToOffset from "./JumpToOffset.svelte";
  import EntropyView from "./EntropyView.svelte";
  import ByteclassView from "./ByteclassView.svelte";
  import MagnitudeView from "./MagnitudeView.svelte";
  import CarouselSelector from "../utils/CarouselSelector.svelte";
  export let dataLenPromise, currentPosition;
  let carouselSelection;
</script>

<div class="minimap">
  <JumpToOffset dataLenPromise="{dataLenPromise}" />
  {#if carouselSelection === "Entropy"}
    <EntropyView />
  {:else if carouselSelection === "Byteclass"}
    <ByteclassView />
  {:else if carouselSelection === "Magnitude"}
    <MagnitudeView />
  {/if}
  <div class="carousel">
    <CarouselSelector
      options="{['Magnitude', 'Entropy', 'Byteclass']}"
      bind:selectedString="{carouselSelection}"
    />
  </div>
</div>
