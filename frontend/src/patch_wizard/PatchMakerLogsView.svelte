<style>
  .title {
    height: calc(10% - 1em);
    text-decoration: underline;
  }

  .logs {
    height: calc(90% - 2em);
    overflow-y: scroll;
  }

  .message {
  }
</style>

<script>
  import { onMount, onDestroy, tick } from "svelte";
  import { settings } from "../stores";

  export let patchInfo, addLogBreak;

  let scrollingLogsNode;
  let abortController = new AbortController();
  let prevName = patchInfo.name;
  let messages = [];

  const linebreakMarker = {};

  addLogBreak = () => {
    // Add linebreak to separate latest messages from old messages
    // But don't add double line breaks
    if (messages?.at(-1) !== linebreakMarker) {
      messages = [...messages, linebreakMarker];
    }
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
          return {
            ok: false,
            continue: true,
            err: JSON.stringify(await r.json(), undefined, 2),
          };
        } else {
          return {
            ok: true,
            continue: true,
            err: null,
            message: await r.text(),
          };
        }
      })
      .catch((err) => {
        if (err.name === "AbortError") {
          // Aborted by either destroying this logs view, or by selecting a different patch
          return { ok: true, continue: false, err: null };
        } else if (err.name === "TypeError") {
          // Likely just timed out, or backend is down
          return { ok: false, continue: true, err: err };
        } else {
          // Other unspecified problem
          return { ok: false, continue: true, err: err };
        }
      });
  }

  async function repeatedlyGetNextMessage(
    patchName,
    prevMessageResult,
    aborter,
    retries = 5
  ) {
    // Long polling with a recursive function
    if (prevMessageResult.message) {
      messages = [...messages, prevMessageResult.message];
      // waits for svelte to update
      await tick();
      await scrollToBottom(scrollingLogsNode);
    }
    if (prevMessageResult.continue && retries) {
      if (!prevMessageResult.ok) {
        // small backoff if something went wrong with previous request
        // sleep for 3000 milliseconds
        console.error(prevMessageResult.err);
        retries -= 1;
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
      // Either timed out or got next log message successfully
      getNextMessage(patchName, aborter).then((r) =>
        repeatedlyGetNextMessage(patchName, r, aborter, retries)
      );
    } else if (retries === 0) {
      messages = [...messages, "Connection to OFRAK backend lost!"];
      // waits for svelte to update
      await tick();
      await scrollToBottom(scrollingLogsNode);
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

  onDestroy(() => abortController.abort());

  $: {
    if (patchInfo.name !== prevName) {
      prevName = patchInfo.name;
      if (!abortController.signal.aborted) {
        abortController.abort();
        abortController = new AbortController();
        repeatedlyGetNextMessage(
          patchInfo.name,
          { ok: true, continue: true },
          abortController
        );
      }
    }
  }
</script>

<h3 class="title">PatchMaker Logs</h3>
<div bind:this="{scrollingLogsNode}" class="logs">
  {#each messages as message}
    {#if message === linebreakMarker}
      <hr />
    {:else}
      <p class="message">{message}</p>
    {/if}
  {/each}
</div>
