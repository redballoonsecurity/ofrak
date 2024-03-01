<style>
  button {
    margin-bottom: 0;
    border: 1px solid white;
  }

  .tabs button:focus {
    border-bottom: 2px solid var(--main-bg-color);
    outline: 0;
  }

  .tabs button {
    margin-right: 0.5em;
    border-bottom: 0px;
  }

  hr {
    display: block;
    height: 1px;
    border: 0;
    border-top: 1px solid white;
    margin-top: -1px;
    padding: 0;
  }
</style>

<script>
  import { onMount } from "svelte";
  export let tabs, tabId, defaultTab;
  onMount(async () => {
    tabId = defaultTab;
    document.getElementById(tabId).click();
  });

  function resetTab() {
    if (!tabs.map((x) => x.id).includes(tabId)) {
      tabId = defaultTab;
    }
  }

  $: resetTab(tabs, tabId);
</script>

<div class="tabs">
  {#each tabs as tab}
    {#if tabId == tab.id}
      <button
        style="border-bottom: 2px solid var(--main-bg-color)"
        id="{tab.id}"
        on:click="{(e) => {
          tabId = tab.id;
        }}">{tab.title}</button
      >
    {:else}
      <button
        id="{tab.id}"
        on:click="{(e) => {
          tabId = tab.id;
        }}">{tab.title}</button
      >
    {/if}
  {/each}
</div>

<hr />
