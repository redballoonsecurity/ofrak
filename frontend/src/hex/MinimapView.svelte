<style>
  .minimap {
    width: 64px;
    max-width: 64px;
    height: 75vh;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    align-items: center;
  }
</style>

<script>
  import JumpToOffset from "./JumpToOffset.svelte";
  import EntropyView from "./EntropyView.svelte";
  import ByteclassView from "./ByteclassView.svelte";
  import MagnitudeView from "./MagnitudeView.svelte";
  import CarouselSelector from "../utils/CarouselSelector.svelte";
  export let dataLength, currentPosition;
  let carouselSelection;
</script>

<div class="minimap">
  <JumpToOffset currentPosition="{currentPosition}" />
  {#if carouselSelection === "Entropy"}
    <EntropyView
      dataLength="{dataLength}"
      currentPosition="{currentPosition}"
    />
  {:else if carouselSelection === "Byteclass"}
    <ByteclassView
      dataLength="{dataLength}"
      currentPosition="{currentPosition}"
    />
  {:else if carouselSelection === "Magnitude"}
    <MagnitudeView
      dataLength="{dataLength}"
      currentPosition="{currentPosition}"
    />
  {/if}
  <div class="carousel">
    <CarouselSelector
      options="{['Magnitude', 'Entropy', 'Byteclass']}"
      bind:selectedString="{carouselSelection}"
    />
  </div>
</div>
