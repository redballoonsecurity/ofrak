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
  export let dataLenPromise;
  let carouselSelection;
  let dataLength = 0;

  $: dataLenPromise.then((r) => {
    dataLength = r;
  });
</script>

<div class="minimap">
  <JumpToOffset />
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
