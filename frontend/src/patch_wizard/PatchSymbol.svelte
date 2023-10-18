<style>
  button {
    font-family: monospace;
    border-style: none;
  }

  .warning {
    text-decoration-line: underline;
    text-decoration-color: red;
  }
</style>

<script>
  export let symbolName, symbolRefMap;
  export let onClick = undefined;

  let titleText = "";

  let symbolInfo;

  if (symbolRefMap) {
    symbolInfo = symbolRefMap[symbolName];
  } else {
    symbolInfo = { name: symbolName, providedBy: [], requiredBy: [] };
  }

  if (symbolInfo.providedBy?.length > 0) {
    titleText += "Provided by ";
    titleText += symbolInfo.providedBy.join(",");
  }

  if (symbolInfo.requiredBy?.length > 0) {
    if (titleText.length > 0) {
      titleText += " and required by ";
    } else {
      titleText += "Required by ";
    }
    titleText += symbolInfo.requiredBy.join(",");
  }
</script>

{#if symbolInfo.providedBy?.length > 0}
  <button title="{titleText}" on:click="{onClick}">
    {symbolInfo.name}
  </button>
{:else}
  <button title="{titleText}" on:click="{onClick}" class="warning">
    {symbolInfo.name}
  </button>
{/if}
