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
  import Checkbox from "../Checkbox.svelte";

  export let node, nodeName, element, baseForm;

  function extractTypeNodeFromOptional(optionalNode) {
    for (const arg of optionalNode.args) {
      if (arg.type !== "builtins.NoneType") {
        return arg;
      }
    }
    return null;
  }

  function guessSelectedTypeFromExistingValue() {
    const t = typeof element;

    // Each filter will run on each arg (possible type in union) to see if the existing element
    // could be of the given type arg
    // WHAT WE DON'T DO: the first arg matching a filter will be returned
    // INSTEAD: The first filter that matches an arg, will cause that arg to be returned
    // This allows prioritizing which matches we make based PRIMARILY  on the order of the filters
    // and SECONDARILY on the order of args, RATHER THAN PRIMARILY on the order of the args and
    // SECONDARILY on the order of the filters

    const filters = [
      (arg) => arg.type === "builtins.int" && t === "number",
      (arg) => arg.type === "builtins.bool" && t === "boolean",
      (arg) =>
        arg.type === "builtins.bytes" &&
        t === "string" &&
        element.match("([0-9a-fA-F][0-9a-fA-F])*"),
      (arg) => arg.type === "builtins.str" && t === "string",
      (arg) => arg.type === "typing.Iterable" && Array.isArray(element),
      (arg) => arg.type === "typing.List" && Array.isArray(element),
      (arg) => arg.type === "typing.Tuple" && Array.isArray(element),
      (arg) => arg.type === "typing.Dict" && Array.isArray(element),
      (arg) => arg.type === "typing.Optional", // Union[Optional[xyz], etc.] is bad form but possible
      (arg) =>
        !arg.type.startsWith("typing") &&
        !arg.type.startsWith("builtins") &&
        t === "object",
    ];

    for (const f of filters) {
      const matches = node.args.filter(f);
      if (matches) {
        return matches[0];
      }
    }

    return null;
  }

  console.log(
    "in Optional field " + nodeName + " initial element is " + element
  );

  // sets the initially selected value
  let unionTypeSelect;
  if (element === undefined) {
    if (node.default !== null) {
      [unionTypeSelect, element] = node.default;
    } else {
      unionTypeSelect = node.args[0];
    }
  } else {
    unionTypeSelect = guessSelectedTypeFromExistingValue();
  }

  let optionalSupplied = element !== null;

  $: {
    if (!optionalSupplied) {
      element = null;
    }
  }
</script>

{#if node.type === "typing.Union"}
  <select bind:value="{unionTypeSelect}">
    {#if !unionTypeSelect}
      <option value="{element}" selected disabled> Select a type </option>
    {/if}
    {#each node.args as arg}
      {#if unionTypeSelect === arg}
        <option value="{arg}" selected>
          {arg.type}
        </option>
      {:else}
        <option value="{arg}">
          {arg.type}
        </option>
      {/if}
    {/each}
  </select>
  {#if unionTypeSelect != null}
    <svelte:component
      this="{baseForm}"
      node="{unionTypeSelect}"
      bind:element="{element}"
    />
  {/if}
{:else if node.type === "typing.Optional"}
  <Checkbox checked="{optionalSupplied}" bind:value="{optionalSupplied}" />
  {#if optionalSupplied}
    <svelte:component
      this="{baseForm}"
      node="{extractTypeNodeFromOptional(node)}"
      bind:element="{element}"
    />
  {/if}
{/if}
