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
  import { selectedResource } from "../stores.js";
  let decompilation;
  let searchString = "";
  hljs.registerLanguage("c", c);

  function get_decompilation() {
    if (
      "ofrak.model._auto_attributes.AttributesType[AngrDecompilationAnalysis]" in
      $selectedResource.attributes
    ) {
      var html = hljs.highlight(
        $selectedResource.attributes[
          "ofrak.model._auto_attributes.AttributesType[AngrDecompilationAnalysis]"
        ]["decompilation"],
        { language: "c" }
      ).value;
      return html;
    } else {
      return 'To see decompilation, click "Analyze" on the left toolbaar';
    }
  }

  $: decompilation = get_decompilation($selectedResource);
</script>

<link rel="stylesheet" href="./code.css" />
<div class="decompilation">
  {@html decompilation}
  <br />
</div>
