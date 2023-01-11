<style>
  button {
    border: 0;
    margin: 0;
    padding-left: 0.5em;
    padding-right: 0.5em;
  }

  ul {
    list-style: none;
    margin: 0;
    padding-left: 1.5em;
    white-space: nowrap;
  }

  ul li {
    padding-left: 1.25em;
    border-left: 1px solid var(--main-fg-color);
  }

  ul li:before {
    content: "";
    border-bottom: 1px solid var(--main-fg-color);
    width: 1em;
    height: 0.25em;
    display: block;
    position: relative;
    left: -1.25em;
    top: 0.7em;
  }

  ul li:last-child {
    border-left: none;
    margin-top: -0.75em;
  }

  ul li:last-child:before {
    border-left: 1px solid var(--main-fg-color);
    height: 1em;
  }

  .selected {
    background-color: var(--selected-bg-color);
    background-clip: border-box;
    color: var(--main-bg-color);
  }

  .comment {
    /* align with the caption above */
    padding-left: 1ch;
    margin: 0;
    color: var(--comment-color);
  }

  .comment button {
    padding: 0;
    padding-right: 0.5ch;
  }

  .comment :global(.comment_icon) {
    margin: 0;
    background-color: var(--comment-color);
  }
</style>

<script>
  import Icon from "./Icon.svelte";
  import Hoverable from "./Hoverable.svelte";
  import LoadingText from "./LoadingText.svelte";

  import { selected } from "./stores.js";

  export let rootResource,
    resourceNodeDataMap,
    collapsed = true;
  let self,
    childrenPromise,
    commentsPromise,
    childrenCollapsed = false;
  $: {
    if (resourceNodeDataMap[self?.id] === undefined) {
      resourceNodeDataMap[self?.id] = {};
    }
    if (resourceNodeDataMap[self?.id].collapsed === undefined) {
      resourceNodeDataMap[self?.id].collapsed = collapsed;
    }
    if (resourceNodeDataMap[self?.id].childrenPromise === undefined) {
      resourceNodeDataMap[self?.id].childrenPromise =
        rootResource.get_children();
    }
    if (resourceNodeDataMap[self?.id].commentsPromise === undefined) {
      resourceNodeDataMap[self?.id].commentsPromise =
        rootResource.get_comments();
    }
    childrenPromise = resourceNodeDataMap[self?.id].childrenPromise;
    commentsPromise = resourceNodeDataMap[self?.id].commentsPromise;
    collapsed = resourceNodeDataMap[self?.id].collapsed;
  }

  async function onClick(e) {
    // https://stackoverflow.com/a/53939059
    if (e.detail > 1) {
      return;
    }
    if ($selected === self?.id) {
      $selected = undefined;
    } else {
      $selected = self?.id;
    }
  }

  function onDoubleClick(e) {
    resourceNodeDataMap[self?.id].collapsed = !collapsed;
    // Expand children recursively on double click
    if (!collapsed) {
      childrenCollapsed = false;
    }
    $selected = self?.id;
  }

  async function onDeleteClick(optional_range) {
    // Delete the selected comment.
    // As a side effect, the corresponding resource gets selected.
    $selected = self?.id;
    await rootResource.delete_comment(optional_range);
    resourceNodeDataMap[$selected].commentsPromise =
      rootResource.get_comments();
  }

  $: if ($selected !== undefined && $selected === self?.id) {
    self?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
</script>

{#await childrenPromise then children}
  {#if children?.length > 0}
    <button
      on:click="{() => {
        resourceNodeDataMap[self?.id].collapsed = !collapsed;
        childrenCollapsed = !collapsed;
      }}"
    >
      {#if collapsed}
        [+{children.length}]
      {:else}
        [-]
      {/if}
      <!-- Ugly next line is required to prevent Svelte from adding space after the button -->
    </button>{/if}{/await}<button
  on:click="{onClick}"
  on:dblclick="{onDoubleClick}"
  bind:this="{self}"
  class:selected="{$selected === self?.id}"
  id="{rootResource.get_id()}"
>
  {rootResource.get_caption()}
</button>
{#await commentsPromise then comments}
  {#each comments as comment}
    {#await rootResource.prettify_comment(comment) then comment_pretty}
      <div class="comment">
        <Hoverable let:hovering>
          <button
            title="Delete this comment"
            on:click="{onDeleteClick(comment[0])}"
          >
            <Icon
              class="comment_icon"
              url="{hovering ? '/icons/trash_can.svg' : '/icons/comment.svg'}"
            />
          </button></Hoverable
        >{comment_pretty}
      </div>
    {/await}
  {/each}
{/await}

{#await childrenPromise}
  <LoadingText />
{:then children}
  {#if !collapsed && children.length > 0}
    <ul>
      {#each children as child}
        <li>
          <div>
            <svelte:self
              rootResource="{child}"
              collapsed="{childrenCollapsed}"
              bind:resourceNodeDataMap="{resourceNodeDataMap}"
            />
          </div>
        </li>
      {/each}
    </ul>
  {/if}
{/await}
