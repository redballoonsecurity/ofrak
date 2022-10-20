<style>
  h1 {
    font-size: 1em;
  }

  a {
    color: var(--main-fg-color);
  }
</style>

<script>
  import StructuredList from "./StructuredList.svelte";

  import { cleanOfrakType } from "./helpers.js";

  export let resource;
  let attributes;
  $: if (resource !== undefined) {
    attributes = {};

    for (const [attrType, attrs] of Object.entries(resource.get_attributes())) {
      const skipped_attributes = [
        // already shown in the resource tree
        "ofrak.core.comments.CommentsAttributes",
        // verbose and unhelpful
        "ofrak_components.entropy.entropy.DataSummary",
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

{#if resource !== undefined}
  <h1>Tags:</h1>
  {#each resource.get_tags() as tag, i}
    <a
      href="{'https://ofrak.com/docs/reference/' +
        tag.split('.').slice(0, -1).join('/') +
        '.html#' +
        tag}"
      target="_blank">{cleanOfrakType(tag)}</a
    >{i !== resource.get_tags().length - 1 ? ", " : ""}
  {/each}

  <h1>Attributes:</h1>
  <StructuredList object="{attributes}" />
{/if}
