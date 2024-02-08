<style>
  .decompilation {
    white-space: pre;
  }

  .highlight {
    background-color: var(--highlight-color);
  }
</style>

<script>
  import hljs from "highlight.js";
  import c from "highlight.js/lib/languages/c";
  import { selectedResource } from "../stores.js";
  export const searchFunction = decompSearch;
  let decompilation;
  let searchString = "";
  hljs.registerLanguage("c", c);

  function get_decompilation() {
    console.log(searchString);
    if (
      "ofrak.model._auto_attributes.AttributesType[AngrDecompilationAnalysisResource]" in
      $selectedResource.attributes
    ) {
      var html = hljs.highlight(
        $selectedResource.attributes[
          "ofrak.model._auto_attributes.AttributesType[AngrDecompilationAnalysisResource]"
        ]["decompilation"],
        { language: "c" }
      ).value;
      return html;
    } else {
      return 'To see decompilation, click "Analyze" on the left toolbaar';
    }
  }

  function decompSearch(query) {
    searchString = query;
    return [];
  }

  $: decompilation = get_decompilation($selectedResource, searchString);
</script>

<link rel="stylesheet" href="./code.css" />
<div class="decompilation">
  {@html decompilation}
</div>
