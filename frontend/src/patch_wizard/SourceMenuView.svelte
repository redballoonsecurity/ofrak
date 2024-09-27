<script>
  import Button from "../utils/Button.svelte";
  import SourceWidget from "./SourceWidget.svelte";
  import { settings } from "../stores";

  export let patchInfo, refreshOverviewCallback;

  function invalidateOnChange() {
    // Changes to source invalidate everything
    patchInfo.objectInfosValid = false;
    patchInfo.targetInfoValid = false;
  }

  async function addNewSourceFile() {
    let input = document.createElement("input");
    input.type = "file";
    let newSourceInfo = { name: undefined, body: undefined };
    input.onchange = async (_) => {
      const file = Array.from(input.files).pop();
      for (const existingSourceInfo of patchInfo.sourceInfos) {
        if (existingSourceInfo.name === file.name) {
          alert(
            "Source file with name " +
              file.name +
              " already exists! Delete it and try again."
          );
          console.error(
            "Source file with name " +
              file.name +
              " already exists! Delete it and try again."
          );
          return;
        }
      }

      file.text().then(async (t) => {
        newSourceInfo.body = t.split("\n");
        newSourceInfo.name = file.name;
        newSourceInfo.originalName = file.name;
        fetch(
          `${$settings.backendUrl}/patch_wizard/add_file?patch_name=${patchInfo.name}&file_name=${newSourceInfo.name}`,
          {
            method: "POST",
            body: t,
          }
        ).then(async (r) => {
          if (!r.ok) {
            throw Error(JSON.stringify(await r.json(), undefined, 2));
          } else {
            patchInfo.sourceInfos = patchInfo.sourceInfos.concat([
              newSourceInfo,
            ]);
            invalidateOnChange();
            refreshOverviewCallback();
          }
        });
      });
    };
    input.click();
  }

  async function deleteSourceFile(sourceInfo) {
    fetch(
      `${$settings.backendUrl}/patch_wizard/delete_file?patch_name=${patchInfo.name}&file_name=${sourceInfo.name}`,
      {
        method: "POST",
        body: "",
      }
    ).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      } else {
        patchInfo.sourceInfos = patchInfo.sourceInfos.filter(
          (e) => e.name !== sourceInfo.name
        );
        invalidateOnChange();
        refreshOverviewCallback();
      }
    });
  }
</script>

<div>
  {#each patchInfo.sourceInfos as sourceInfo}
    <SourceWidget
      bind:sourceInfo="{sourceInfo}"
      parentDeleteSource="{deleteSourceFile}"
      onChangeCallback="{invalidateOnChange}"
    />
  {/each}

  <Button on:click="{addNewSourceFile}">Add new source or header file</Button>
</div>
