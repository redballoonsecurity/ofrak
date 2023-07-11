<style>
  .hbox {
    width: 100%;
    padding: 2em;
    overflow-y: hidden;
  }
  .title {
    padding-bottom: 0.5em;
    text-align: center;
    font-size: xx-large;
    font-weight: bold;
    text-transform: uppercase;
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
  import ProjectManagerFocusableLabel from "./ProjectManagerFocusableLabel.svelte";

  export let title, projectElementOptions, selection, focus, description;
</script>

<div class="hbox">
  <div class="title">
    <ProjectManagerFocusableLabel
      bind:focus="{focus}"
      label="{title}"
      focusText="{description}"
    />
  </div>
  <div class="content">
    {#each projectElementOptions as projectOption}
      <div class="element">
        <ProjectManagerCheckbox
          option="{projectOption}"
          bind:selection="{selection}"
          bind:focus="{focus}"
        />
      </div>
    {/each}
  </div>
</div>
