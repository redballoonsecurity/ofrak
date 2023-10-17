<style>
  .box {
    border: thin solid;
    margin-bottom: 1ch;
  }

  .body {
    display: inline-flex;
    width: 100%;
  }

  .header-bar {
    border: thin solid;
    font-size: medium;
    padding: 0.3em;
  }

  .column {
    width: 50%;
    padding-left: 1ch;
    padding-right: 1ch;
  }

  .column-left {
    border-right: thin dashed;
  }

  .column-header {
    font-weight: bold;
    text-align: center;
    border-bottom: thin dashed;
  }

  .body-segments {
    display: flex;
    flex-wrap: wrap;
  }

  .body-symbols {
    text-align: left;
  }

  .warning {
    text-decoration-line: underline;
    text-decoration-color: red;
  }
</style>

<script>
  import SegmentWidget from "./SegmentWidget.svelte";
  import PatchSymbol from "./PatchSymbol.svelte";

  export let objectInfo, symbolRefMap;

  let locallyUndefinedSymbols = objectInfo.unresolvedSymbols.filter(
    (s) => !symbolRefMap.hasOwnProperty(s)
  );
</script>

<div class="box">
  <div class="header-bar">
    {objectInfo.name}
  </div>
  <div class="body">
    <div class="column column-left">
      <p class="column-header">Segments</p>
      <div class="body-segments">
        {#each objectInfo.segments as segInfo (segInfo.name)}
          <SegmentWidget segmentInfo="{segInfo}" />
        {/each}
      </div>
    </div>
    <div class="column">
      <p class="column-header">Symbols</p>
      <div class="body-symbols">
        {#if locallyUndefinedSymbols.length > 0}
          <p class="warning">
            {locallyUndefinedSymbols.length} unresolved symbol(s)!
          </p>
        {/if}
        Provides:
        {#each objectInfo.strongSymbols as sym}
          <PatchSymbol symbolInfo="{symbolRefMap[sym]}" />
        {/each}
        <br />
        Requires:
        {#each objectInfo.unresolvedSymbols as sym}
          <PatchSymbol symbolInfo="{symbolRefMap[sym]}" />
        {/each}
      </div>
    </div>
  </div>
</div>
