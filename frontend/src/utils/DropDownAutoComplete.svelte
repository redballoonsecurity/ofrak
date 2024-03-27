<style>
  .dropdown {
    text-align: left;
    position: absolute;
    margin-top: 3px;
  }
</style>

<script>
  import { onMount } from "svelte";
  import DropDown from "./DropDown.svelte";

  export let input, string, options, pattern;
  let autoOptions = options,
    hidden = true;
  let dropdown;

  document.onkeyup = handle;

  function updateInput() {
    let match = input.match(pattern);
    input = input.replace(match[0], string);
  }

  function hideMenu() {
    dropdown.style.display = "none";
    hidden = true;
  }

  function showMenu(e) {
    dropdown.style.display = "block";
    const c = document.createElement("canvas");
    const ctx = c.getContext("2d");
    ctx.font = `${getComputedStyle(e.target).getPropertyValue(
      "font-size"
    )} ${getComputedStyle(e.target).getPropertyValue("font-family")}`;
    let textSize = ctx.measureText(input);
    dropdown.style.left = e.target.offsetLeft + textSize.width + "px";
    hidden = false;
  }

  function handle(e) {
    if (input.match(pattern)) {
      showMenu(e);
    } else {
      hideMenu();
    }
  }

  function updateOptions() {
    let match = input?.match(pattern);
    if (match) {
      string = match[0];
      autoOptions = options.filter((x) => x.startsWith(string));
    }
  }

  onMount(() => {
    dropdown = document.getElementById("dropdown");
    hideMenu();
  });

  $: if (string) updateInput(string);
  $: if (input) updateOptions(input);
</script>

<div class="container">
  <div id="dropdown" class="dropdown">
    <DropDown options="{autoOptions}" , bind:selection="{string}" />
  </div>
</div>
