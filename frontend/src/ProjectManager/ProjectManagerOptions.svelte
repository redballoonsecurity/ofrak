<style>
  .hbox {
    width: 100%;
    height: 100%;
  }
  .options {
    display: flex;
    flex-direction: column;
    margin: 1em;
    font-size: x-large;
  }
</style>

<script>
  export let focus, selectedBinaryName, forceRefreshProject;
</script>

<div class="hbox">
  <div class="options">
    {#if focus}
      <svelte:component
        this="{focus.object}"
        bind:selectedBinaryName="{selectedBinaryName}"
        bind:forceRefreshProject="{forceRefreshProject}"
        bind:args="{focus.args}"
      />
    {:else}
      Click anywhere to see its options.
    {/if}
  </div>
</div>
