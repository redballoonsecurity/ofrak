<style>
  p {
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

  let titleText = "";

  let symbolInfo;
  $: {
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
  }
</script>

{#if symbolInfo.providedBy?.length > 0}
  <p title="{titleText}">
    {symbolInfo.name}
  </p>
{:else}
  <p title="{titleText}" class="warning">
    {symbolInfo.name}
  </p>
{/if}
