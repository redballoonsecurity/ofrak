<script>
  import ObjectWidget from "./ObjectWidget.svelte";

  export let patchInfo;
</script>

<div>
  {#each patchInfo.objectInfos as objInfo}
    <ObjectWidget
      objectInfo="{objInfo}"
      symbolRefMap="{patchInfo.symbolRefMap}"
    />
  {/each}
</div>
