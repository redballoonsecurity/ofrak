<script>
  import ObjectWidget from "./ObjectWidget.svelte";

  export let patchInfo, refreshOverviewCallback;
</script>

<div>
  {#each patchInfo.objectInfos as objInfo}
    <ObjectWidget
      objectInfo="{objInfo}"
      symbolRefMap="{patchInfo.symbolRefMap}"
      refreshOverviewCallback="{refreshOverviewCallback}"
    />
  {/each}
</div>
