<style>
  .hbox {
    width: 100%;
    height: 100%;
  }
  .options {
    display: flex;
    flex-direction: column;
    font-size: x-large;
    max-width: 100%;
    max-height: 100%;
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
