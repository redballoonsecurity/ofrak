<script>
  import FileBrowser from "../FileBrowser.svelte";
  export let description;
  let files;
</script>

"{description}"
<FileBrowser files="{files}" />
