<script>
  import Button from "../utils/Button.svelte";
  import SourceWidget from "./SourceWidget.svelte";

  export let subMenu, patchInfo;

  async function addNewSourceFile() {
    let input = document.createElement("input");
    input.type = "file";
    let newSourceInfo = { name: undefined, body: undefined };
    input.onchange = async (_) => {
      const file = Array.from(input.files).pop();
      // TODO: Send file to backend in here
      file.text().then((t) => (newSourceInfo.body = t.split("\n")));
      newSourceInfo.name = file.name;

      for (const existingSourceInfo of patchInfo.sourceInfos) {
        if (existingSourceInfo.name === newSourceInfo.name) {
          alert(
            "Source file with name " +
              newSourceInfo.name +
              " already exists! Delete it and try again."
          );
          console.error(
            "Source file with name " +
              newSourceInfo.name +
              " already exists! Delete it and try again."
          );
          return;
        }
      }

      patchInfo.sourceInfos = patchInfo.sourceInfos.concat([newSourceInfo]);
    };
    input.click();
  }

  async function deleteSourceFile(sourceInfo) {
    patchInfo.sourceInfos = patchInfo.sourceInfos.filter((e) => e.name !== sourceInfo.name);
  }
</script>

<div>
  <Button on:click="{() => (subMenu = undefined)}">Back</Button>
  {#each patchInfo.sourceInfos as sourceInfo}
    <SourceWidget
      bind:sourceInfo="{sourceInfo}"
      parentDeleteSource="{deleteSourceFile}"
    />
  {/each}

  <Button on:click="{addNewSourceFile}">Add new source file</Button>
</div>
