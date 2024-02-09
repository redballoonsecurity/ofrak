<style>
  ol {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  li {
    display: inline;
  }

  li:not(:first-child):before {
    content: " / ";
    color: var(--main-fg-color);
    cursor: default;
    margin-left: 0.35ch;
    margin-right: 0.35ch;
  }

  li:not(:last-child) button {
    color: var(--accent-text-color);
  }

  li:not(:last-child) button:hover {
    text-decoration: underline;
  }

  li:last-child button {
    cursor: default;
  }

  li:first-child button {
    padding-left: 0;
  }

  button {
    border: 0;
    padding: 0;
    text-align: left;
  }
</style>

<script>
  import LoadingText from "./LoadingText.svelte";

  import { selected, selectedResource } from "../stores.js";

  let ancestorsPromise;
  $: if ($selectedResource !== undefined) {
    ancestorsPromise = $selectedResource
      .get_ancestors()
      .then((a) => a.reverse().concat([$selectedResource]));
  }
</script>

{#await ancestorsPromise}
  <LoadingText />
{:then ancestors}
  {#if ancestors !== null && ancestors !== undefined}
    <ol>
      {#each ancestors as ancestor}
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <li
          on:click="{(e) => {
            $selected = ancestor.get_id();
          }}"
        >
          <button>
            {ancestor.get_caption()}
          </button>
        </li>
      {/each}
    </ol>
  {/if}
{/await}
