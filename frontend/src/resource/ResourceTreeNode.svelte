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

  div.morebutton {
    padding-left: 1.25em;
    margin: 2em 0;
  }

  div.morebutton button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    border: 1px solid var(--main-fg-color);
    border-radius: 0;
    font-size: smaller;
    overflow: hidden;
    box-shadow: none;
  }

  div.morebutton button:hover,
  div.morebutton button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 var(--main-fg-color),
      inset -1px -1px 0 var(--main-fg-color);
  }

  div.morebutton button:active {
    box-shadow: inset 2px 2px 0 var(--main-fg-color),
      inset -2px -2px 0 var(--main-fg-color);
  }

  .selected {
    background-color: var(--selected-bg-color);
    background-clip: border-box;
    color: var(--main-bg-color);
  }

  .lastModified {
    text-decoration-line: underline;
    text-decoration-color: var(--last-modified-color);
    text-decoration-thickness: 2px;
  }

  .allModified {
    text-decoration-line: underline;
    text-decoration-color: var(--all-modified-color);
    text-decoration-thickness: 2px;
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
  import LoadingText from "../utils/LoadingText.svelte";

  import { onDestroy } from "svelte";
  import { selected, resourceNodeDataMap } from "../stores.js";
  import { shortcuts } from "../keyboard";
  import Comment from "../views/Comment.svelte";

  export let rootResource,
    selectNextSibling = () => {},
    selectPreviousSibling = () => {},
    collapsed = true,
    childrenCollapsed = true,
    searchResults;
  let firstChild,
    childrenPromise,
    commentsPromise,
    lastModified,
    allModified,
    selfId = rootResource.get_id(),
    kiddoChunksize = 512;

  $: {
    if ($resourceNodeDataMap[selfId] === undefined) {
      $resourceNodeDataMap[selfId] = {};
    }
    if ($resourceNodeDataMap[selfId].collapsed === undefined) {
      $resourceNodeDataMap[selfId].collapsed = collapsed;
    }
    if ($resourceNodeDataMap[selfId].childrenPromise === undefined) {
      $resourceNodeDataMap[selfId].childrenPromise =
        rootResource.get_children();
    }
    if ($resourceNodeDataMap[selfId].commentsPromise === undefined) {
      $resourceNodeDataMap[selfId].commentsPromise =
        rootResource.get_comments();
    }
    if ($resourceNodeDataMap[selfId].lastModified === undefined) {
      $resourceNodeDataMap[selfId].lastModified = false;
    }
    if ($resourceNodeDataMap[selfId].allModified === undefined) {
      $resourceNodeDataMap[selfId].allModified = false;
    }
    childrenPromise = $resourceNodeDataMap[selfId].childrenPromise;
    commentsPromise = $resourceNodeDataMap[selfId].commentsPromise;
    collapsed = $resourceNodeDataMap[selfId].collapsed;
    lastModified = $resourceNodeDataMap[selfId].lastModified;
    allModified = $resourceNodeDataMap[selfId].allModified;
  }

  function updateRootModel() {
    rootResource.update();
    rootResource = rootResource;
  }
  $: updateRootModel(childrenPromise);

  $: childrenPromise?.then((children) => {
    if (children?.length > 0) {
      firstChild = children[0];
    }
  });

  $: if ($selected === selfId) {
    shortcuts["h"] = () => {
      $resourceNodeDataMap[selfId].collapsed = true;
    };
    shortcuts["l"] = () => {
      $resourceNodeDataMap[selfId].collapsed = false;
    };
    shortcuts["j"] = () => {
      if (!collapsed && firstChild) {
        $selected = firstChild?.resource_id;
      } else {
        selectNextSibling();
      }
    };
    shortcuts["k"] = selectPreviousSibling;

    shortcuts["arrowleft"] = shortcuts["h"];
    shortcuts["arrowdown"] = shortcuts["j"];
    shortcuts["arrowup"] = shortcuts["k"];
    shortcuts["arrowright"] = shortcuts["l"];
  }

  async function onClick(e) {
    // https://stackoverflow.com/a/53939059
    if (e.detail > 1) {
      return;
    }
    if ($selected === selfId) {
      $selected = undefined;
    } else {
      $selected = selfId;
    }
  }

  function onDoubleClick(e) {
    $resourceNodeDataMap[selfId].collapsed = !collapsed;
    // Expand children recursively on double click
    if (!collapsed) {
      childrenCollapsed = false;
    }
    $selected = selfId;
  }

  // Swap "just modified" indication to "previously modified" indication
  onDestroy(() => {
    if ($resourceNodeDataMap[selfId].lastModified) {
      $resourceNodeDataMap[selfId].allModified =
        $resourceNodeDataMap[selfId].lastModified;
    }
  });
</script>

{#if !searchResults.matches || searchResults.matches.includes(selfId)}
  {#await childrenPromise then children}
    {#if children?.length > 0}
      <button
        on:click="{() => {
          $resourceNodeDataMap[selfId].collapsed = !collapsed;
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
    class:selected="{$selected === selfId}"
    class:lastModified="{$resourceNodeDataMap[selfId].lastModified}"
    class:allModified="{$resourceNodeDataMap[selfId].allModified}"
    id="{selfId}"
  >
    {rootResource.get_caption()}
  </button>
  {#await commentsPromise then comment_group}
    {#each comment_group as [comment_range, comment_strs]}
      {#each comment_strs as comment_text}
        <div class="comment">
          <Comment
            comment="{{ comment_range, comment_text }}"
            rootResource="{rootResource}"
            selfId="{selfId}"
          />
        </div>
      {/each}
    {/each}
  {/await}

  {#await childrenPromise}
    <LoadingText />
  {:then children}
    {#if !collapsed && children.length > 0}
      <ul>
        {#each children.slice(0, kiddoChunksize) as child, i}
          {#if !searchResults.matches || searchResults.matches.includes(child.get_id())}
            <li>
              <div>
                <svelte:self
                  rootResource="{child}"
                  collapsed="{childrenCollapsed}"
                  childrenCollapsed="{childrenCollapsed}"
                  selectNextSibling="{i ===
                  Math.min(kiddoChunksize, children.length) - 1
                    ? selectNextSibling
                    : () => {
                        $selected = children[i + 1]?.resource_id;
                      }}"
                  selectPreviousSibling="{i === 0
                    ? () => {
                        $selected = selfId;
                      }
                    : () => {
                        $selected = children[i - 1]?.resource_id;
                      }}"
                  searchResults="{searchResults}"
                />
              </div>
            </li>
          {/if}
        {/each}
        {#if children.length > kiddoChunksize}
          <div class="morebutton">
            <button on:click="{() => (kiddoChunksize += 512)}">
              Show 512 more children...
            </button>
          </div>
        {/if}
      </ul>
    {/if}
  {/await}
{/if}
