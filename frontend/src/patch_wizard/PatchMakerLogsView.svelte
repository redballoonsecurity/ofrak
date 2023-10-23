<style>
  .title {
    height: 10%;
  }

  .logs {
    height: calc(90% - 2em);
    overflow-y: scroll;
  }

  .message {
  }
</style>

<script>
  import { onMount, tick } from "svelte";
  import { settings } from "../stores";
  import Button from "../utils/Button.svelte";

  export let patchInfo, addLogBreak;

  let scrollingLogsNode;
  let abortController = new AbortController();
  let prevName = patchInfo.name;
  let messages = [];

  const linebreakMarker = {};

  addLogBreak = () => {
    messages = [...messages, linebreakMarker];
  };

  async function getNextMessage(patchName, aborter) {
    return fetch(
      `${$settings.backendUrl}/patch_wizard/listen_logs?patch_name=${patchName}`,
      {
        method: "POST",
        signal: aborter.signal,
      }
    )
      .then(async (r) => {
        if (!r.ok) {
          throw Error(JSON.stringify(await r.json(), undefined, 2));
        } else {
          messages = [...messages, await r.text()];
          // waits for svelte to update
          await tick();
          await scrollToBottom(scrollingLogsNode);
          return { ok: true, continue: true, err: null };
        }
      })
      .catch((reason) => {
        if (reason.name === "AbortError") {
          return { ok: true, continue: false, err: null };
        } else if (reason.name === "TypeError") {
          return { ok: true, continue: true, err: null };
        } else {
          return { ok: false, continue: true, reason: reason };
        }
      });
  }

  async function repeatedlyGetNextMessage(
    patchName,
    prevMessageResult,
    aborter
  ) {
    // Long polling with a recursive function
    if (prevMessageResult.continue) {
      if (!prevMessageResult.ok) {
        // small backoff if something went wrong with previous request
        // sleep for 3000 milliseconds
        console.error(prevMessageResult.reason);
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
      // Either timed out or got next log message successfully
      getNextMessage(patchName, aborter).then((r) =>
        repeatedlyGetNextMessage(patchName, r, aborter)
      );
    }
  }

  const scrollToBottom = async (node) => {
    node.scroll({ top: node.scrollHeight, behavior: "smooth" });
  };

  onMount(() =>
    repeatedlyGetNextMessage(
      patchInfo.name,
      { ok: true, continue: true },
      abortController
    )
  );

  $: {
    if (patchInfo.name !== prevName) {
      prevName = patchInfo.name;
      abortController.abort();
      abortController = new AbortController();
      repeatedlyGetNextMessage(
        patchInfo.name,
        { ok: true, continue: true },
        abortController
      );
    }
  }
</script>

<p class="title">PatchMaker Logs</p>
<div bind:this="{scrollingLogsNode}" class="logs">
  {#each messages as message}
    {#if message === linebreakMarker}
      <hr />
    {:else}
      <p class="message">{message}</p>
    {/if}
  {/each}
</div>
