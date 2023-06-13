<style>
  :root {
    --line-height: 1.5em;
  }

  .sticky {
    position: sticky;
    top: 0;
  }

  .breadcrumb {
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
    position: absolute;
    font-size: 0.95em;
  }

  .spacer {
    width: 2em;
    min-width: 2em;
  }

  .byte {
    padding: 0.5ch;
  }

  .ascii {
    white-space: pre;
  }
</style>

<script>
  import Breadcrumb from "./Breadcrumb.svelte";
  import LoadingText from "./LoadingText.svelte";

  import { chunkList, buf2hex, hexToChar } from "./helpers.js";
  import { selectedResource, selected, settings } from "./stores.js";

  export let dataLenPromise, scrollY, resourceNodeDataMap, resources;
  let childRangesPromise = Promise.resolve(undefined);
  let chunkDataPromise = Promise.resolve(undefined);
  let childRanges,
    dataLength,
    resourceData,
    chunkData = [],
    chunks = [],
    start = 0,
    end = 64,
    startWindow = 0,
    endWindow = 0;

  const alignment = 16,
    chunkSize = 4096,
    windowSize = chunkSize * 10,
    windowPadding = 1024;

  $: dataLenPromise.then((r) => {
    dataLength = r;
  });
  $: dataLenPromise
    .then((length) => {
      if (length < 1024 * 1024 * 64 && $selectedResource) {
        return $selectedResource.get_data();
      }
    })
    .then((data) => {
      resourceData = data;
    });
  $: childRangesPromise.then((r) => {
    childRanges = r;
  });
  $: chunkDataPromise.then((r) => {
    chunks = r;
  });
  $: Promise.any([dataLenPromise, childRangesPromise]).then((_) => {
    // Hacky solution to minimap view box rectangle only updating on scroll
    // after data has loaded -- force a scroll to reload the rectangle after a
    // timeout
    setTimeout(() => {
      if (scrollY !== undefined) {
        $scrollY.top = 0;
      }
    }, 500);
  });

  // Sadly, this is the most flexible, most reliable way to get the line height
  // from arbitrary CSS units in pixels. It is definitely a little nasty :(
  const lineHeight = (() => {
    let div = document.createElement("div");
    div.style.visibility = "hidden";
    div.style.boxSizing = "content-box";
    div.style.height = "var(--line-height)";
    document.body.appendChild(div);
    let result = div.offsetHeight;
    div.remove();
    return result;
  })();

  async function getNewData() {
    start = Math.max(
      Math.floor((dataLength * $scrollY.top) / alignment) * alignment,
      0
    );
    end = Math.min(
      start + Math.floor($scrollY.viewHeightPixels / lineHeight) * alignment,
      dataLength
    );

    if (resourceData) {
      return chunkList(
        new Uint8Array(resourceData.slice(start, end)),
        alignment
      ).map((chunk) => chunkList(buf2hex(chunk), 2));
    }

    if (end > endWindow - windowPadding) {
      startWindow = Math.max(start - windowPadding, 0);
      endWindow = Math.min(startWindow + windowSize, dataLength);
      chunkData = await $selectedResource.get_data([startWindow, endWindow]);
    } else if (start < startWindow + windowPadding) {
      endWindow = Math.min(end + windowPadding, dataLength);
      startWindow = Math.max(endWindow - windowSize, 0);
      chunkData = await $selectedResource.get_data([startWindow, endWindow]);
    }

    return chunkList(
      new Uint8Array(chunkData.slice(start - startWindow, end - startWindow)),
      alignment
    ).map((chunk) => chunkList(buf2hex(chunk), 2));
  }
  $: if (scrollY !== undefined && $scrollY !== undefined) {
    chunkDataPromise = dataLenPromise.then(getNewData);
  }

  async function calculateRanges(resource, dataLenPromise, colors) {
    const children = await resource.get_children();
    if (children === []) {
      return [];
    }
    const childRanges = Object.entries(await resource.get_child_data_ranges())
      .filter(
        ([_, rangeInParent]) =>
          rangeInParent !== null && rangeInParent !== undefined
      )
      .sort((first, second) => first[1][0] - second[1][0])
      .map(([child_id, rangeInParent], i) => {
        // Important to sort before mapping so that the colors don't get mixed up.
        // If that were to happen, multiple ranges with the same color could be
        // adjacent.
        const [start, end] = rangeInParent;
        return {
          color: colors[i % colors.length],
          resource_id: child_id,
          start: start,
          end: end,
        };
      });
    let ranges = [];
    if (childRanges.length > 0) {
      ranges = [];
      let start = 0;
      for (const childRange of childRanges) {
        if (childRange.start - start > 0) {
          // Large ranges need to be broken into chunks because of a Chrome
          // rendering bug that wraps long continuous strings incorrectly after a
          // while
          for (let i = start; i < childRange.start; i += chunkSize) {
            ranges.push({
              color: null,
              resource_id: null,
              start: i,
              end: Math.min(i + chunkSize, childRange.start),
            });
          }
        }
        ranges.push(childRange);
        start = childRange.end;
      }
      ranges = ranges;
    } else if (childRanges.length == 0) {
      ranges = [];
      for (let i = 0; i < dataLength; i += chunkSize) {
        ranges.push({
          color: null,
          resource_id: null,
          start: i,
          end: Math.min(i + chunkSize, dataLength),
        });
      }
    }
    return ranges;
  }
  $: childRangesPromise = calculateRanges(
    $selectedResource,
    dataLenPromise,
    $settings.colors
  );

  function getRangeInfo(T, childRanges) {
    if (childRanges === undefined) {
      return null;
    }

    // Perform binary search using range start offsets.
    // https://en.wikipedia.org/wiki/Binary_search_algorithm#Algorithm
    let L = 0,
      R = childRanges.length - 1;
    while (true) {
      if (L > R) {
        break;
      }

      let m = Math.floor((L + R) / 2);
      let range = childRanges[m];
      if (range.start <= T && T < range.end) {
        let result = {
          foreground: "var(--main-bg-color)",
          background: range.color,
          resource_id: range.resource_id,
        };
        return result;
      } else if (range.start < T) {
        L = m + 1;
      } else if (range.start > T) {
        R = m - 1;
      }
    }

    return null;
  }
</script>

{#await dataLenPromise}
  <LoadingText />
{:then dataLength}
  {#if dataLength > 0}
    <!-- 
      The magic number below is the largest height that Firefox will support with
      a position: sticky element. Otherwise, the sticky element scrolls away.
      Found this by manual binary search on my computer. 
    -->
    <div
      style:height="min(8940000px, calc(var(--line-height) * {Math.ceil(
        dataLength / alignment
      )}))"
    >
      <div class="sticky">
        <div class="breadcrumb">
          <Breadcrumb />
        </div>
        <div class="hbox">
          {#await chunkDataPromise}
            <LoadingText />
          {:then chunks}
            <div>
              {#each chunks as _, chunkIndex}
                <div>
                  {(chunkIndex * alignment + start)
                    .toString(16)
                    .padStart(8, "0") + ": "}
                </div>
              {/each}
            </div>

            <span class="spacer"> </span>

            {#await childRangesPromise}
              <div>
                {#each chunks as hexes}
                  <div>
                    {#each hexes as byte}
                      <span class="byte">{byte}</span>
                    {/each}
                  </div>
                {/each}
              </div>
            {:then childRangesResult}
              <div>
                {#each chunks as hexes, chunkIndex}
                  <div>
                    {#each hexes as byte, byteIndex}
                      {@const rangeInfo = getRangeInfo(
                        chunkIndex * alignment + byteIndex + start,
                        childRangesResult,
                        byte
                      )}
                      {#if rangeInfo?.resource_id === null || rangeInfo?.resource_id === undefined}
                        <span class="byte">{byte}</span>
                      {:else}
                        <span
                          class="byte"
                          style:background-color="{rangeInfo.background}"
                          style:color="{rangeInfo.foreground}"
                          style:cursor="pointer"
                          style:user-select="none"
                          title="{rangeInfo.resource_id !== null
                            ? resources[rangeInfo.resource_id]?.get_caption() ||
                              rangeInfo.resource_id
                            : ''}"
                          on:dblclick="{() => {
                            resourceNodeDataMap[$selected].collapsed = false;
                            $selected = rangeInfo.resource_id;
                          }}">{byte}</span
                        >
                      {/if}
                    {/each}
                  </div>
                {/each}
              </div>
            {/await}

            <span class="spacer"></span>

            <div class="ascii">
              {#each chunks as hexes}
                <div>
                  {hexes.map(hexToChar).join("") + " "}
                </div>
              {/each}
            </div>
          {/await}
        </div>
      </div>
    </div>
  {:else}
    <div class="breadcrumb sticky">
      <Breadcrumb />
    </div>

    Resource has no data!
  {/if}
{/await}
