<style>
  .hbox {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
    line-height: var(--line-height);
    font-size: var(--font-size, medium);
    overflow: auto;
    max-height: 100%;
    min-height: 100%;
  }

  .spacer {
    width: 2em;
    min-width: 2em;
  }

  .line-numbers {
    text-align: right;
  }

  .textarea {
    white-space: pre;
  }
</style>

<script>
  import hljs from "highlight.js";
  import python from "highlight.js/lib/languages/python";
  hljs.registerLanguage("python", python);
  export let script;
  export let language = "python";
</script>

<link rel="stylesheet" href="./code.css" />
<div class="hbox">
  <div class="line-numbers">
    {#each script as _, index}
      <div>{index + 1}</div>
    {/each}
  </div>

  <span class="spacer"></span>

  <div class="textarea">
    <code>
      {@html hljs.highlight(script.join("\n"), { language: language }).value}
    </code>
  </div>
</div>
