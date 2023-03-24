<script>
    import Checkbox from './Checkbox.svelte';

    export let field;
    export let field_name;
    export let field_type;
    export let field_entries;

    if(field_type == "builtins.bool"){
        field_entries[field_name] = false;
    } else {
        field_entries[field_name] = "";
    }

</script>

<p>
    {field_name}
    {#if (field_type == "builtins.bool")}
        <Checkbox bind:checked="{field_entries[field_name]}"/>
    {:else}
        <input class={field} bind:value="{field_entries[field_name]}">
    {/if}
</p>
