<script>
  import Checkbox from "./Checkbox.svelte";

  export let field, field_entries;

  field_entries[field["name"]] = field["default"];
</script>

<p>
  {console.log(field["name"])}
  {console.log(field["type"])}
  {console.log(field["args"])}
  {console.log(field["fields"])}
  {console.log(field["default"])}

  {field["name"]}
  {#if field["type"] == "builtins.bool"}
    <Checkbox bind:checked="{field_entries[field['name']]}" />
  {:else if field["type"] == "builtins.str" || field["type"] == "builtins.int"}
    <input class="{field}" bind:value="{field_entries[field['name']]}" />
  {/if}

  {#if field["args"].length > 0}
    {#each field["args"] as arg}
      {#if arg == "builtins.bool"}
        <Checkbox bind:checked="{field_entries[field['name']]}" />
      {:else if arg == "builtins.str" || arg == "builtins.int"}
        {arg}
        <input class="{field}" bind:value="{field_entries[field['name']]}" />
      {/if}
    {/each}
  {/if}

  {#if field["fields"].length > 0}
    {#each field["fields"] as nested_field}
      <svelte:self
        field="{nested_field}"
        bind:field_entries="{field_entries[field['fields']]}"
      />
    {/each}
  {/if}
</p>
