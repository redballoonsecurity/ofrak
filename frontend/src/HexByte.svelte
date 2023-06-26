<style>
  .byte {
    padding: 0.5ch;
  }
</style>

<script>
  export let byte, resources;

  function getRangeInfo(T, childRanges) {
    if (childRanges === undefined) {
      return {
        foreground: "inherit",
        background: "inherit",
        resource_id: "none",
      };
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

<span
  class="byte"
  style:background-color="{rangeInfo.background}"
  style:color="{rangeInfo.foreground}"
  style:cursor="pointer"
  style:user-select="none"
  title="{rangeInfo.resource_id !== null
    ? resources[rangeInfo.resource_id]?.get_caption() || rangeInfo.resource_id
    : ''}"
  on:dblclick="{() => {
    resourceNodeDataMap[$selected].collapsed = false;
    $selected = rangeInfo.resource_id;
  }}">{byte}</span
>
