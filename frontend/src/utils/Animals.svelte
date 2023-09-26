<style>
  img {
    object-fit: scale-down;
    width: 100%;
    transform: translate(0, 105%);
    transition: transform 0.5s;
    max-height: 150px;
  }

  .hover {
    transform: translate(0, 20%);
  }

  .container {
    position: absolute;
    bottom: 0;
    display: flex;
    flex-flow: row nowrap;
    justify-content: space-evenly;
    overflow: hidden;
  }
</style>

<script>
  import { animals } from "../animals.js";

  export let x,
    selectedAnimal,
    visible = true;
  $: selectedAnimal = Math.floor((x / window.innerWidth) * 5);
</script>

{#if visible}
  <div class="container">
    {#each animals as animal, index}
      <div>
        <img
          src="{animal.src}"
          alt="{animal.name}"
          class:hover="{selectedAnimal == index}"
        />
      </div>
    {/each}
  </div>
{/if}
