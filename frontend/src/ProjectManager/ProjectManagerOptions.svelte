<style>
  .hbox {
    width: 100%;
    height: 100%;
    padding: 2em;
  }
  .options-box {
    display: flex;
    outline: solid 2px var(--main-fg-color);
    border-radius: 5%;
    height: 95%;
    font-size: x-large;
  }
  .options {
    display: flex;
    flex-direction: column;
  }
</style>

<script>
  export let focus;
</script>

<div class="hbox">
  <div class="options-box">
    <div class="options">
      "{focus}"
    </div>
  </div>
</div>
