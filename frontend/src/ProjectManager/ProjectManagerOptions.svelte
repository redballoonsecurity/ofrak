<style>
  .hbox {
    width: 100%;
    height: 100%;
  }
  .options-box {
    display: flex;
    outline: solid 2px var(--main-fg-color);
    border-radius: 1em;
    height: 95%;
    font-size: x-large;
  }
  .options {
    display: flex;
    flex-direction: column;
    margin: 1em;
  }
</style>

<script>
  export let focus;
</script>

<div class="hbox">
  <div class="options-box">
    <div class="options">
      {#if focus}
        {focus}
      {/if}
    </div>
  </div>
</div>
