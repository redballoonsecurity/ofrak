<style>
  .decompilation {
    white-space: pre;
    overflow: auto;
    min-height: calc(100% - 6em);
    max-height: calc(100% - 6em);
  }

  .highlight {
    background-color: var(--highlight-color);
  }
</style>

<script>
  import hljs from "highlight.js";
  import c from "highlight.js/lib/languages/c";
  import {
    selectedResource,
    resourceNodeDataMap,
    selected,
    settings,
  } from "../stores.js";

  let decompilation;
  hljs.registerLanguage("c", c);

  async function get_decompilation() {
    if (
      "ofrak.model._auto_attributes.AttributesType[DecompilationAnalysis]" in
      $selectedResource.attributes
    ) {
      var html = hljs.highlight(
        $selectedResource.attributes[
          "ofrak.model._auto_attributes.AttributesType[DecompilationAnalysis]"
        ]["decompilation"],
        { language: "c" }
      ).value;
      return html;
    } else {
      decompilation = "Decompiling...";
      return await $selectedResource.analyze().then(() => {
        var html = hljs.highlight(
          $selectedResource.attributes[
            "ofrak.model._auto_attributes.AttributesType[DecompilationAnalysis]"
          ]["decompilation"],
          { language: "c" }
        ).value;
        return html;
      });
    }
  }

  $: (async () => {
    decompilation = await get_decompilation($selectedResource);
  })();
</script>

<link rel="stylesheet" href="./code.css" />
<div class="decompilation">
  {@html decompilation}
  <br />
</div>
