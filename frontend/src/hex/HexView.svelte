<style>
  .minimap {
    right: -1em;
    min-height: 100%;
    max-height: 100%;
    position: relative;
  }

  :root {
    --line-height: 1.5em;
  }

  .sticky {
    position: sticky;
    top: 0;
    height: 100%;
  }

  .hex-display {
    display: flex;
    flex-direction: row;
    overflow: hidden;
    justify-content: left;
    min-height: 100%;
    max-height: 100%;
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

  .byte {
    padding: 0.5ch;
  }
  .ascii {
    white-space: pre;
  }
</style>

<script>
  import LoadingText from "../utils/LoadingText.svelte";
  import MinimapView from "./MinimapView.svelte";
  import { chunkList, buf2hex, hexToChar } from "../helpers.js";
  import { selectedResource, selected, settings } from "../stores.js";
  import { onMount } from "svelte";
  import { currentPosition, dataLength, screenHeight } from "./stores";
  import SearchBar from "../utils/SearchBar.svelte";

  export let dataLenPromise, resourceNodeDataMap, resources;
  let dataSearchResults = {};
  let childRangesPromise = Promise.resolve(undefined);
  let chunkDataPromise = Promise.resolve(undefined);
  let childRanges,
    resourceData,
    chunkData = [],
    chunks = [],
    start = 0,
    end = 64,
    startWindow = 0,
    endWindow = 0;
  let hexDisplay = undefined;

  const alignment = 16,
    chunkSize = 4096,
    windowSize = chunkSize * 10,
    windowPadding = 1024;

  $: dataLenPromise
    .then((length) => {
      if (length < 1024 * 1024 * 64 && $selectedResource) {
        return $selectedResource.get_data();
      }
    })
    .then((data) => {
      resourceData = data;
    })
    .then(getNewData);
  $: childRangesPromise.then((r) => {
    childRanges = r;
  });
  $: chunkDataPromise.then((r) => {
    chunks = r;
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

  async function searchHex(query, options) {
    return await $selectedResource.search_data(query, options);
  }

  async function getNewData() {
    $dataLength = await dataLenPromise;
    start = $currentPosition;
    end = Math.min(start + $screenHeight, $dataLength);

    if (resourceData) {
      return chunkList(
        new Uint8Array(resourceData.slice(start, end)),
        alignment
      ).map((chunk) => chunkList(buf2hex(chunk), 2));
    }

    if (end > endWindow - windowPadding) {
      startWindow = Math.max(start - windowPadding, 0);
      endWindow = Math.min(startWindow + windowSize, $dataLength);
      chunkData = await $selectedResource.get_data([startWindow, endWindow]);
    } else if (start < startWindow + windowPadding) {
      endWindow = Math.min(end + windowPadding, $dataLength);
      startWindow = Math.max(endWindow - windowSize, 0);
      chunkData = await $selectedResource.get_data([startWindow, endWindow]);
    }

    return chunkList(
      new Uint8Array(chunkData.slice(start - startWindow, end - startWindow)),
      alignment
    ).map((chunk) => chunkList(buf2hex(chunk), 2));
  }

  $: updateData($currentPosition, $selectedResource);
  function updateData() {
    chunkDataPromise = dataLenPromise
      .then((length) => {
        if (length < 1024 * 1024 * 64 && $selectedResource) {
          return $selectedResource.get_data();
        }
      })
      .then((data) => {
        resourceData = data;
      })
      .then(getNewData);
  }

  $: updateResource($selectedResource);

  function updateResource() {
    $currentPosition = 0;
  }

  async function calculateRanges(resource, dataLenPromise, colors) {
    const children = await resource.get_children();
    if (children == []) {
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
    return childRanges;
  }
  $: childRangesPromise = calculateRanges(
    $selectedResource,
    dataLenPromise,
    $settings.colors
  );

  function binarySearchRanges(T, ranges) {
    // https://en.wikipedia.org/wiki/Binary_search_algorithm#Algorithm
    let L = 0,
      R = ranges.length - 1;
    while (true) {
      if (L > R) {
        break;
      }

      let m = Math.floor((L + R) / 2);
      let range = ranges[m];
      if (range.start <= T && T < range.end) {
        return range;
      } else if (range.start < T) {
        L = m + 1;
      } else if (range.start > T) {
        R = m - 1;
      }
    }
    return null;
  }

  function getRangeInfo(T, childRanges) {
    const info = {
      foreground: "var(--main-fg-color)",
      background: "var(--main-bg-color)",
      text_decoration: "none",
      cursor: "default",
      resource_id: null,
      user_select: "default",
      onDoubleClick: () => {},
      title: undefined,
    };
    if (!childRanges) {
      return info;
    }

    // Binary search for child ranges this byte overlaps with
    let childRange = binarySearchRanges(T, childRanges);
    if (childRange) {
      info.foreground = "var(--main-bg-color)";
      info.background = childRange.color;
      info.cursor = "pointer";
      info.resource_id = childRange.resource_id;
      info.user_select = "none";
      info.title =
        resources[childRange.resource_id]?.get_caption() ||
        childRange.resource_id;
      // info.onDoubleClick = () => {
      //   resourceNodeDataMap[$selected].collapsed = false;
      //   $selected = childRange.resource_id;
      // };
    }

    if (dataSearchResults.matches != undefined) {
      let dataSearchMatchRanges = dataSearchResults.matches.map((match) => {
        return { start: match[0], end: match[0] + match[1] };
      });
      let matchRange = binarySearchRanges(T, dataSearchMatchRanges);
      if (matchRange) {
        info.background = "var(--main-fg-color)";
        info.foreground = "var(--main-bg-color)";
      }
    }

    return info;
  }

  // React to local data searches
  $: if (dataSearchResults) {
    const localDataSearchResults = dataSearchResults;
    if (
      localDataSearchResults.matches?.length > 0 &&
      (localDataSearchResults.index || localDataSearchResults.index === 0)
    ) {
      dataLenPromise.then(($dataLength) => {
        $currentPosition =
          localDataSearchResults.matches[localDataSearchResults.index][0];
      });
    }
  }

  function refreshHeight() {
    hexDisplay = document.getElementById("hex-display");
    $screenHeight =
      Math.floor(hexDisplay.offsetHeight / lineHeight) * alignment;
    updateData();
  }

  onMount(() => {
    hexDisplay = document.getElementById("hex-display");
    refreshHeight();
  });
</script>

<svelte:window on:resize="{refreshHeight}" />
<SearchBar
  search="{searchHex}"
  liveUpdate="{false}"
  showResultsWidgets="{true}"
  bind:searchResults="{dataSearchResults}"
/>
<div
  class="hex-display"
  id="hex-display"
  on:wheel="{(e) => {
    $currentPosition += Math.floor(e.deltaY) * 16;
    if ($currentPosition > $dataLength - $screenHeight) {
      $currentPosition = $dataLength - $screenHeight;
    }
    if ($currentPosition < 0) {
      $currentPosition = 0;
    }
  }}"
>
  {#await dataLenPromise}
    <LoadingText />
  {:then $dataLength}
    {#if $dataLength > 0}
      <!-- 
        The magic number below is the largest height that Firefox will support with
        a position: sticky element. Otherwise, the sticky element scrolls away.
        Found this by manual binary search on my computer. 
      -->
      <div
        style:height="min(8940000px, calc(var(--line-height) * {Math.ceil(
          $dataLength / alignment
        )}))"
      >
        <div class="sticky">
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
                        <!-- svelte-ignore a11y-no-static-element-interactions -->
                        <span
                          class="byte"
                          style:background-color="{rangeInfo.background}"
                          style:color="{rangeInfo.foreground}"
                          style:cursor="{rangeInfo.cursor}"
                          style:user-select="{rangeInfo.user_select}"
                          style:text-decoration="{rangeInfo.text_decoration}"
                          title="{rangeInfo.title}"
                          on:dblclick="{rangeInfo.onDoubleClick}">{byte}</span
                        >
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
      Resource has no data!
    {/if}
  {/await}
  {#if resourceData != undefined}
    <div class="minimap">
      <MinimapView dataLenPromise="{dataLenPromise}" />
    </div>
  {/if}
</div>
