<style>
  .content {
    position: sticky;
    top: 0;
    height: 100%;
    width: 100%;
    overflow: hidden;
  }

  .breadcrumb {
    padding-bottom: 1em;
    background: var(--main-bg-color);
  }

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

  .content hr {
    display: block;
    height: 1px;
    border: 0;
    border-top: 1px solid white;
    margin-top: -1px;
    padding: 0;
  }
</style>

<script>
  import { selectedResource } from "../stores";
  import Breadcrumb from "../utils/Breadcrumb.svelte";
  import { onMount } from "svelte";
  export let tabs, initTabId;
  let displayType;
  onMount(async () => {
    document.getElementById(initTabId).click();
  });
</script>

<div class="content">
  <div class="breadcrumb">
    <Breadcrumb />
  </div>
  <div class="tabs">
    {#each tabs as tab}
      {#if displayType == tab.id}
        <button
          style="border-bottom: 2px solid var(--main-bg-color)"
          id="{tab.id}"
          on:click="{(e) => {
            displayType = tab.id;
          }}">{tab.title}</button
        >
      {:else}
        <button
          id="{tab.id}"
          on:click="{(e) => {
            displayType = tab.id;
          }}">{tab.title}</button
        >
      {/if}
    {/each}
  </div>

  <hr />
  {#each tabs as tab}
    {#if displayType == tab.id}
      <svelte:component this="{tab.component}" {...tab.props} />
    {/if}
  {/each}
</div>
