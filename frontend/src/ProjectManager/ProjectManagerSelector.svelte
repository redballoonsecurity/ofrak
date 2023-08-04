<style>
  .hbox2 {
    width: 100%;
    padding: 2em;
    overflow-y: hidden;
  }
  .content {
    font-size: x-large;
    display: flex;
    flex-direction: column;
    width: 100%;
    overflow: auto;
  }
</style>

<script>
  import ProjectManagerCheckbox from "./ProjectManagerCheckbox.svelte";

  export let projectElementOptions, selection, focus;
</script>

<div class="hbox2">
  <div class="content">
    {#each projectElementOptions as projectOption}
      <div class="element">
        <ProjectManagerCheckbox
          option="{projectOption['name']}"
          bind:selection="{selection}"
          bind:focus="{focus}"
        />
      </div>
    {/each}
  </div>
</div>
