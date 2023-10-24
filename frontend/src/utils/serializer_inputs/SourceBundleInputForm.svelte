<script>
  import FileBrowser from "../FileBrowser.svelte";

  export let node, nodeName, element, baseForm;
  let files = null;

  if (element === undefined) {
    if (node.default !== null) {
      throw Error("Default values for SourceBundle inputs not supported");
    } else {
      element = [];
    }
  }

  async function slurpSourceBundle(files) {
    for (const file of files) {
      let text = await file.text();
      element.push([file.name, text]);
    }
    return element;
  }

  $: if (files) {
    slurpSourceBundle(files);
  }
</script>

<FileBrowser multiple="{true}" bind:files="{files}" />
