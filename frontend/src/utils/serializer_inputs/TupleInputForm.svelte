<script>
  export let node, element, baseForm;

  if (element === undefined) {
    if (node.default !== null) {
      element = node.default[1];
    } else {
      element = [];
    }
  }
</script>

{#each node.args as arg, i}
  <svelte:component
    this="{baseForm}"
    node="{arg}"
    bind:element="{element[i]}"
  />
{/each}
