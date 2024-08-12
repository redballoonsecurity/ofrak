<style>
  .comment {
    white-space: pre;
  }

  button {
    border: 0px;
    filter: invert(20%);
  }

  button:hover {
    filter: invert(40%);
  }
</style>

<script>
  import { tick } from "svelte";
  import { currentPosition } from "../hex/stores.js";
  import { selected, resourceNodeDataMap } from "../stores.js";
  import Hoverable from "../utils/Hoverable.svelte";
  import Icon from "../utils/Icon.svelte";
  export let comment, rootResource, selfId;
  let addresses = comment.comment_text.matchAll(
    "#[a-fA-F0-9]+[@0x[0-9a-fA-F]+]*"
  );
  let text_elements = [];
  Array.from(addresses).forEach((location) => {
    let text_split = comment.comment_text.split(location[0]);
    text_elements.push(text_split[0]);
    text_elements.push(createAddressButton(location[0]));
    comment.comment_text = text_split.slice(1).join(location[0]);
  });

  text_elements.push(comment.comment_text);

  function createAddressButton(location) {
    let resource_id;
    let address = 0;
    if (location.includes("@")) {
      resource_id = location.split("@")[0].slice(1);
      address = location.split("@")[1];
    } else {
      resource_id = location.slice(1);
      address = 0;
    }
    let button = {};
    button.style = "border: 0px";
    button.content = location;
    button.onclick = async function () {
      $selected = resource_id;
      await tick();
      $currentPosition = Math.ceil(Number(address) / 16) * 16;
    };
    return button;
  }

  async function onDeleteClick(comment) {
    // Delete the selected comment.
    // As a side effect, the corresponding resource gets selected.
    $selected = selfId;
    await rootResource.delete_comment(
      comment.comment_range,
      comment.comment_text
    );
    $resourceNodeDataMap[$selected].commentsPromise =
      rootResource.get_comments();
  }
</script>

<div class="comment">
  <Hoverable let:hovering>
    <button title="Delete this comment" on:click="{onDeleteClick(comment)}">
      <Icon
        class="comment_icon"
        url="{hovering ? '/icons/trash_can.svg' : '/icons/comment.svg'}"
      />
    </button></Hoverable
  >
  {#each text_elements as element}
    {#if typeof element === "string"}
      <span>{element}</span>
    {:else}
      <span
        ><button style="{element.style}" on:click="{element.onclick}"
          >{element.content}</button
        ></span
      >
    {/if}
  {/each}
</div>
