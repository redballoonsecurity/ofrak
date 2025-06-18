<style>
  h1 {
    font-size: 1em;
  }

  .attributes {
    max-height: calc(100% - 3em);
    min-height: calc(100% - 3em);
    overflow: auto;
  }

  a {
    color: var(--main-fg-color);
  }
</style>

<script>
  import StructuredList from "../utils/StructuredList.svelte";

  import { cleanOfrakType } from "../helpers.js";

  export let resource;
  let attributes;
  $: if (resource !== undefined) {
    attributes = {};

    for (const [attrType, attrs] of Object.entries(resource.get_attributes())) {
      const skipped_attributes = [
        // already shown in the resource tree
        "ofrak.core.comments.CommentsAttributes",
        // verbose and unhelpful
        "ofrak.core.entropy.entropy.DataSummary",
        "ofrak.core.entropy.entropy.DataSummaryCache",
      ];
      if (skipped_attributes.includes(attrType)) {
        continue;
      }
      attributes[cleanOfrakType(attrType)] = attrs;
    }
  } else {
    attributes = undefined;
  }
</script>

<div class="attributes">
  {#if resource !== undefined}
    <h1>Tags:</h1>
    {#each resource.get_tags() as tag, i}
      <a
        href="{'https://ofrak.com/docs/reference/' +
          tag.split('.').slice(0, -1).join('/') +
          '.html#' +
          tag}"
        target="_blank"
        rel="noreferrer">{cleanOfrakType(tag)}</a
      >{i !== resource.get_tags().length - 1 ? ", " : ""}
    {/each}
    <h1>Attributes:</h1>
    <StructuredList object="{attributes}" />
  {/if}
</div>
