<style>
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
  import { selected } from "../stores.js";
  export let comment;
  let range = comment[0];
  let text = comment[1];
  let addresses = text.matchAll("#[a-fA-F0-9]+[@0x[0-9a-fA-F]+]*", text);
  let text_elements = [];
  addresses.forEach((location) => {
    let text_split = text.split(location[0]);
    text_elements.push(text_split[0]);
    text_elements.push(createAddressButton(location[0]));
    text = text_split.slice(1).join(location[0]);
    // let addr = address[0].replace("@", "");
    // text = text.replace(address, `<button style="border: 0px" onclick=\'(e) => {${$currentPosition}=Number(${addr}})\'>${addr}</button>`)
  });
  text_elements.push(text);
  function createAddressButton(location) {
    let resource_id;
    let address = 0;
    if (location.includes("@")) {
      resource_id = location.split("@")[0].slice(1);
      address = location.split("@")[1];
    } else {
      resource_id = location.slice(1);
      address = range[0];
    }
    let button = {};
    button.style = "border: 0px";
    button.content = location;
    button.onclick = async function () {
      $selected = resource_id;
      await tick();
      $currentPosition = Number(address);
    };
    return button;
  }
</script>

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
