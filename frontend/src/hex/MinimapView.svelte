<style>
  .minimap {
    width: 64px;
    max-width: 64px;
    height: calc(100% - 8em);
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
  export let currentPosition;
  let carouselSelection;
</script>

<div class="minimap">
  <JumpToOffset bind:currentPosition="{currentPosition}" />
  {#if carouselSelection === "Entropy"}
    <EntropyView bind:currentPosition="{currentPosition}" />
  {:else if carouselSelection === "Byteclass"}
    <ByteclassView bind:currentPosition="{currentPosition}" />
  {:else if carouselSelection === "Magnitude"}
    <MagnitudeView bind:currentPosition="{currentPosition}" />
  {/if}
  <div class="carousel">
    <CarouselSelector
      options="{['Magnitude', 'Entropy', 'Byteclass']}"
      bind:selectedString="{carouselSelection}"
    />
  </div>
</div>
