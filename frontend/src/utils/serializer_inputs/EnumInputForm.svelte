<style>
  select {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    padding: 0.5em 1em;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
    width: 100%;
    margin: 0 0 1em;
  }

  option {
    font-family: monospace;
  }
</style>

<script>
  export let node, element;

  if (element === undefined) {
    if (node.default !== null) {
      element = node.default[1];
    } else {
      element = null;
    }
  }
</script>

<select bind:value="{element}">
  {#if !element}
    <option selected disabled value="{null}">
      Please select a {node.type.split(".").at(-1)}
    </option>
  {/if}
  {#each Object.entries(node.enum) as [name, enum_value]}
    <option value="{enum_value}">
      {name}
    </option>
  {/each}
</select>
