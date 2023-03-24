<style>
  button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 var(--main-fg-color),
      inset -1px -1px 0 var(--main-fg-color);
  }

  button:active {
    box-shadow: inset 2px 2px 0 var(--main-fg-color),
      inset -2px -2px 0 var(--main-fg-color);
  }

  .container {
    min-height: 100%;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: stretch;
    align-content: center;
  }

  .inputs {
    flex-grow: 1;
  }

  .inputs *:first-child {
    margin-top: 0;
  }

  .actions {
    margin-top: 2em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: center;
    align-content: center;
  }

  input {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid white;
    flex-grow: 1;
    margin-left: 1ch;
  }

  form {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid white;
    flex-grow: 1em;
    margin-left: 2em;
    border: 2px solid rgb(255, 255, 255)(255, 255, 255);
    border-radius: 4px;
  }
  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  label {
    margin-bottom: 1em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: baseline;
    align-content: center;
    white-space: nowrap;
  }

  .row {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: baseline;
    align-content: center;
    white-space: nowrap;
  }

  .error {
    margin-top: 2em;
  }
</style>

<script>
    import { selectedResource, config } from "./stores";
    import Icon from "./Icon.svelte";
    import ComponentConfigField from "./ComponentConfigField.svelte";
    let component = undefined;
    let submitted = false;
    let field_entries = {};
    export let modifierView;

</script>

<div class="container">
    <form on:submit="{async (e) => {
        await $selectedResource.get_config_for_component(component);
        submitted = true;
    }}">
        <input bind:value={component}>
    </form>
    <p>
        {#if submitted}
            {$config["name"]};
            {#each $config["fields"] as field}
              <ComponentConfigField field={field} field_name={field["name"]} field_type={field["type"]} bind:field_entries={field_entries}/>
            {/each}
        {/if}
    </p>
    
    <button on:click="{(e) => {
        $selectedResource.run_component(component, $config["name"], field_entries);
    }}">
      Run Componenet
    </button>
    <button on:click="{() => (modifierView = undefined)}">Cancel</button>

</div>