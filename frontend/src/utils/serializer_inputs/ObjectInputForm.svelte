<script>
  export let node, element, baseForm;

  if (element === undefined) {
    if (node.default !== null) {
      element = node.default[1];
    } else {
      element = [node.type, {}];
    }
  }

  const [objectType, objectFieldVals] = element;
</script>

{#each node.fields as field, i}
  <svelte:component
    this="{baseForm}"
    node="{field}"
    bind:element="{objectFieldVals[field.name]}"
  />
{/each}
