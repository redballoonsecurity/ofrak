<style>
  button {
    border: 0;
  }

  .left-button {
    padding-right: 1em;
  }

  .right-button {
    padding-left: 1em;
  }

  p {
    margin: 0;
    display: inline;
    text-align: center;
    flex-grow: 1;
    user-select: none;
    cursor: default;
  }

  .container {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-between;
    font-size: 0.95em;
  }
</style>

<script>
  export let selectedString,
    options = [];
  let selected = 0;
  $: selectedString =
    options[((selected % options.length) + options.length) % options.length];
</script>

<div class="container">
  <button
    class="left-button"
    on:click="{() => {
      selected--;
    }}"
  >
    &lt;
  </button>
  <p>
    {selectedString}
  </p>
  <button
    class="right-button"
    on:click="{() => {
      selected++;
    }}"
  >
    &gt;
  </button>
</div>
