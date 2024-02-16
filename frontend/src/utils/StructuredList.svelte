<script>
  export let object,
    noQuotes = false;

  function convertObject(obj) {
    if (Array.isArray(obj)) {
      if (!obj.every((x) => Array.isArray(x) && x.length == 2)) {
        return;
      }

      return Object.fromEntries(obj);
    }
  }

  $: convertedObject = convertObject(object);
</script>

{#if object === null || object === undefined}
  None
{:else if convertedObject}
  <svelte:self object="{convertedObject}" />
{:else if Array.isArray(object) && object.length === 0}
  None
{:else if Array.isArray(object)}
  <ol>
    {#each object as value}
      <li>
        <svelte:self object="{value}" />
      </li>
    {/each}
  </ol>
{:else if typeof object === "string" && noQuotes}
  {object}
{:else if typeof object === "string" && !noQuotes}
  "{object}"
  {#if /^-?\d+$/.test(object)}
    (0x{parseInt(object).toString(16)})
  {/if}
{:else if typeof object === "object" && Object.keys(object).length === 0}
  None
{:else if typeof object === "object"}
  <ul>
    {#each Object.entries(object) as [key, value]}
      <li>
        <svelte:self object="{key}" noQuotes="{true}" />:
        <svelte:self object="{value}" />
      </li>
    {/each}
  </ul>
{:else if typeof object === "number"}
  0x{object.toString(16)} ({object})
{:else}
  {object}
{/if}
