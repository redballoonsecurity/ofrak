<style>
  .dropdown {
    text-align: left;
    position: absolute;
    margin-top: 3px;
  }

  textarea {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid white;
    flex-grow: 1;
    height: 10em;
    margin-left: 1ch;
    font: inherit;
  }

  textarea:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }
</style>

<script>
  import { onMount, tick } from "svelte";
  import DropDown from "./DropDown.svelte";
  import { getTextSizeInPixels } from "../helpers.js";

  export let comment, options, pattern;
  let autoOptions = options;
  let dropdown, string, input;

  function updateInput() {
    let match = comment.match(pattern);
    comment = comment.replace(match[0], string);
  }

  function hideMenu() {
    dropdown.style.display = "none";
  }

  function showMenu(e) {
    dropdown.style.display = "block";
    let textSize = getTextSizeInPixels(e.target, comment);
    dropdown.style.left = e.target.offsetLeft + textSize.width + "px";
  }

  function handle(e) {
    if (comment.match(pattern)) {
      showMenu(e);
    } else {
      hideMenu();
    }
    if (e.key == "Enter") {
      input.focus();
    }
  }

  function updateOptions() {
    let match = comment?.match(pattern);
    if (match) {
      string = match[0];
      autoOptions = options.filter((x) => x?.startsWith(string));
    }
  }

  onMount(() => {
    input.onkeyup = handle;
    dropdown.onkeyup = handle;
    hideMenu();
  });

  $: if (string) updateInput(string);
  $: if (comment) updateOptions(comment);
</script>

<textarea bind:this="{input}" type="text" bind:value="{comment}"></textarea>
<div class="container">
  <div bind:this="{dropdown}" class="dropdown">
    <DropDown options="{autoOptions}" bind:selection="{string}" />
  </div>
</div>
