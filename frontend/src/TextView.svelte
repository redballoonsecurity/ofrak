<style>
  .breadcrumb {
    position: sticky;
    top: 0;
    padding-bottom: 1em;
    background: var(--main-bg-color);
  }

  .hbox {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
    line-height: var(--line-height);
    font-size: 0.95em;
  }

  .spacer {
    width: 2em;
    min-width: 2em;
  }

  .line-numbers {
    text-align: right;
  }

  .textarea {
    white-space: pre;
  }
</style>

<script>
  import Breadcrumb from "./Breadcrumb.svelte";
  import LoadingAnimation from "./LoadingAnimation.svelte";

  export let dataPromise;

  const decoder = new TextDecoder();
  function bufferToString(buffer) {
    return decoder.decode(new Uint8Array(buffer));
  }
</script>

<div class="breadcrumb">
  <Breadcrumb />
</div>

{#await dataPromise.then(bufferToString)}
  <LoadingAnimation />
{:then data}
  <div class="hbox">
    <div class="line-numbers">
      {#each data.split("\n") as _, index}
        <div>{index + 1}</div>
      {/each}
    </div>

    <span class="spacer"></span>

    <div class="textarea">
      {data}
    </div>
  </div>
{/await}
