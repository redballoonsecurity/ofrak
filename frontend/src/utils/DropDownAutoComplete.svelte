<style>
  .dropdown {
    text-align: left;
    position: absolute;
    margin-top: 3px;
  }

  input {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid white;
    flex-grow: 1;
    margin-left: 1ch;
  }

  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  .inputs {
    flex-grow: 1;
  }

  .inputs *:first-child {
    margin-top: 0;
  }
</style>

<script>
  import { onMount } from "svelte";
  import DropDown from "./DropDown.svelte";

  export let comment, options, pattern;
  let autoOptions = options;
  let dropdown, string, input;

  document.onkeyup = handle;

  function updateInput() {
    let match = comment.match(pattern);
    comment = comment.replace(match[0], string);
  }

  function hideMenu() {
    dropdown.style.display = "none";
  }

  function showMenu(e) {
    dropdown.style.display = "block";
    const c = document.createElement("canvas");
    const ctx = c.getContext("2d");
    ctx.font = `${getComputedStyle(e.target).getPropertyValue(
      "font-size"
    )} ${getComputedStyle(e.target).getPropertyValue("font-family")}`;
    let textSize = ctx.measureText(comment);
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
      console.log(string);
      console.log(options);
      autoOptions = options.filter((x) => x.startsWith(string));
    }
  }

  onMount(() => {
    dropdown = document.getElementById("dropdown");
    hideMenu();
  });

  $: if (string) updateInput(string);
  $: if (comment) updateOptions(comment);
</script>

<input bind:this="{input}" type="text" bind:value="{comment}" />
<div class="container">
  <div id="dropdown" class="dropdown">
    <DropDown options="{autoOptions}" bind:selection="{string}" />
  </div>
</div>
