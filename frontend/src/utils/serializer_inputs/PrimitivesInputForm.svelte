<style>
  label {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: baseline;
  }

  input {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid var(--main-fg-color);
    flex-grow: 1;
    margin-left: 1ch;
    /* width: 100%;
    margin: 0;
    padding: 0; */
  }

  input:invalid {
    border-bottom: 1px solid var(--comment-color);
  }

  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  input:focus:invalid {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--comment-color);
  }
</style>

<script>
  import Checkbox from "../Checkbox.svelte";
  import { calculator } from "../../helpers";

  export let node, nodeName, element;

  const INT_PLACEHOLDERS = [
    "0x10 * 2 + 8",
    "(0x10 * 0x100 + 25) * 69",
    "0x3 + 5 - 0x2",
    "6 * 0x2 + 1",
    "0x4 * (0x2 + 2)",
    "12 / (0x3 * 0x2)",
    "0x7 - 0x2 * 0x3",
    "0x2 * (0x3 + 3)",
    "(0x2 ^ 3) - 1",
    "10 + 0x3 * 2",
    "0x3 * (0x2 + 2) + 2",
    "0x7 - 1 + 10",
  ];

  if (element === undefined) {
    if (node.default !== null) {
      element = node.default[1];
    } else {
      element = null;
    }
  }

  let _element = element;
  let intInput;

  $: if (node.type === "builtins.int") {
    try {
      element = calculator.calculate(_element);
      intInput?.setCustomValidity("");
    } catch {
      element = null;
      intInput?.setCustomValidity("Invalid expression.");
    }
  }
</script>

{#if node.type === "builtins.bool"}
  <Checkbox checked="{element}" bind:value="{element}" leftbox="{true}">
    {nodeName}
  </Checkbox>

  <!---->
{:else if node.type === "builtins.str"}
  <label>
    {nodeName}
    <input bind:value="{element}" />
  </label>

  <!---->
{:else if node.type === "builtins.bytes"}
  <label>
    {nodeName}
    <input
      pattern="([0-9a-fA-F][0-9a-fA-F])*"
      placeholder="00deadbeef00"
      bind:value="{element}"
    />
  </label>

  <!---->
{:else if node.type === "builtins.int"}
  <label>
    {nodeName}
    <input
      placeholder="{INT_PLACEHOLDERS[
        Math.floor(Math.random() * INT_PLACEHOLDERS.length)
      ]}"
      bind:value="{_element}"
      bind:this="{intInput}"
    />
  </label>

  <!---->
{/if}
