<style>
  h1 {
    text-transform: uppercase;
    font-weight: bold;
    color: inherit;
    font-size: xxx-large;
    line-height: 1;
    margin: 0;
    max-width: 50%;
    text-align: center;
  }

  form {
    width: 35%;
    max-width: 50%;
    display: flex;
  }

  form > select {
    max-width: 90%;
    flex-grow: 1;
  }

  form > button {
    max-width: 10%;
    flex-grow: 1;
  }

  .center {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    width: 100%;
    height: 100%;
    color: var(--main-fg-color);
  }

  button,
  select,
  option {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    margin-left: 0.5em;
    margin-right: 0.5em;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0, inset -1px -1px 0;
  }

  button:active {
    box-shadow: inset 2px 2px 0, inset -2px -2px 0;
  }

  option {
    font-family: monospace;
  }

  .dragging {
    margin: 3em;
    border: 5px dashed var(--main-fg-color);
    width: calc(100% - 6em);
    height: calc(100% - 6em);
  }

  input[type="file"] {
    display: none;
  }

  .maxwidth {
    max-width: 50%;
    width: 50%;
    margin: 1em 0;
    display: flex;
    flex-direction: row;
    justify-content: center;
    align-items: center;
  }

  .clickable {
    cursor: pointer;
  }
</style>

<script>
  import Animals from "./Animals.svelte";
  import LoadingAnimation from "./LoadingAnimation.svelte";
  import LoadingText from "./LoadingText.svelte";
  import TextDivider from "./TextDivider.svelte";

  import { animals } from "./animals.js";
  import { selected, settings } from "./stores.js";
  import { remote_model_to_resource } from "./ofrak/remote_resource";

  import { onMount } from "svelte";
  import { numBytesToQuantity } from "./helpers";

  export let rootResourceLoadPromise,
    showRootResource,
    resources,
    rootResource,
    resourceNodeDataMap,
    browsedFiles,
    fileinput;
  let dragging = false,
    selectedPreExistingRoot = null,
    preExistingRootsPromise = new Promise(() => {}),
    tryHash = !!window.location.hash;
  let mouseX, selectedAnimal;
  const warnFileSize = 250 * 1024 * 1024;
  const fileChunkSize = warnFileSize;

  async function createRootResource(f) {
    let rootModel;
    if (
      f.size > warnFileSize &&
      !window.confirm(
        `Loading a large file (${numBytesToQuantity(
          f.size
        )} > ${numBytesToQuantity(warnFileSize)}) may be slow. Are you sure?`
      )
    ) {
      showRootResource = false;
      return;
    }
    if (f.size > warnFileSize) {
      for (var start = 0; start < f.size; start += fileChunkSize) {
        let end = Math.min(start + fileChunkSize, f.size);
        const result = await fetch(
          `${$settings.backendUrl}/root_resource_chunk?name=${f.name}&addr=${start}`,
          {
            method: "POST",
            body: await f.slice(start, end),
          }
        );
      }

      rootModel = await fetch(
        `${$settings.backendUrl}/create_chunked_root_resource?name=${f.name}`,
        {
          method: "POST",
        }
      ).then((r) => r.json());
    } else {
      rootModel = await fetch(
        `${$settings.backendUrl}/create_root_resource?name=${f.name}`,
        {
          method: "POST",
          body: await f.arrayBuffer(),
        }
      ).then((r) => r.json());
    }
    rootResource = remote_model_to_resource(rootModel, resources);
    $selected = rootModel.id;
  }

  function choosePreExistingRoot() {
    if (selectedPreExistingRoot) {
      dragging = false;
      showRootResource = true;

      rootResource = remote_model_to_resource(
        selectedPreExistingRoot,
        resources
      );
      $selected = selectedPreExistingRoot.id;

      rootResourceLoadPromise = Promise.resolve(undefined);
    }
  }

  async function handleDrop(e) {
    dragging = false;
    if (e.dataTransfer.files.length > 0) {
      showRootResource = true;
      const f = e.dataTransfer.files[0];
      rootResourceLoadPromise = createRootResource(f);
      await rootResourceLoadPromise;
    }
  }

  $: if (browsedFiles && browsedFiles.length > 0) {
    showRootResource = true;
    const f = browsedFiles[0];
    rootResourceLoadPromise = createRootResource(f);
  }

  async function getResourcesFromHash(resourceId) {
    const root = await fetch(
      `${$settings.backendUrl}/${resourceId}/get_root`
    ).then((r) => {
      if (!r.ok) {
        throw Error(r.statusText);
      }
      return r.json();
    });

    rootResource = remote_model_to_resource(root, resources);
    $selected = root.id;

    let resource = await fetch(`${$settings.backendUrl}/${resourceId}/`).then(
      (r) => {
        if (!r.ok) {
          throw Error(r.statusText);
        }
        return r.json();
      }
    );
    resources[resource.id] = remote_model_to_resource(resource, resources);
    if (resourceNodeDataMap[resource.id] === undefined) {
      resourceNodeDataMap[resource.id] = {};
    }
    resourceNodeDataMap[resource.id].collapsed = false;
    while (resource.parent_id) {
      resource = await fetch(
        `${$settings.backendUrl}/${resource.parent_id}/`
      ).then((r) => {
        if (!r.ok) {
          throw Error(r.statusText);
        }
        return r.json();
      });
      resources[resource.id] = remote_model_to_resource(resource, resources);

      if (resourceNodeDataMap[resource.id] === undefined) {
        resourceNodeDataMap[resource.id] = {};
      }
      resourceNodeDataMap[resource.id].collapsed = false;
    }

    showRootResource = true;
    rootResourceLoadPromise = Promise.resolve(undefined);
    $selected = resourceId;
  }

  if (tryHash) {
    const linkedId = window.location.hash.slice(1);
    getResourcesFromHash(linkedId).catch((error) => {
      console.error(error);
      window.location.replace("/");
    });
  }

  onMount(async () => {
    preExistingRootsPromise = await fetch(
      `${$settings.backendUrl}/get_root_resources`
    ).then((r) => r.json());
  });
</script>

{#if !tryHash}
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <div
    class="center clickable {dragging ? 'dragging' : ''}"
    on:dragover|preventDefault="{(e) => {
      dragging = true;
      mouseX = e.clientX;
    }}"
    on:dragleave|preventDefault="{() => (dragging = false)}"
    on:drop|preventDefault="{handleDrop}"
    on:mousemove="{(e) => (mouseX = e.clientX)}"
    on:mouseleave="{() => (mouseX = undefined)}"
    on:click="{() => fileinput.click()}"
    style:border-color="{animals[selectedAnimal]?.color ||
      "var(--main-fg-color)"}"
    style:color="{animals[selectedAnimal]?.color || "var(--main-fg-color)"}"
  >
    {#if !dragging}
      <h1>Drag in a file to analyze</h1>
      <p style:margin-bottom="0">
        Click anwyhere to browse for a file to analyze
      </p>
    {:else}
      <h1>Drop the file!</h1>
    {/if}

    <input type="file" bind:this="{fileinput}" bind:files="{browsedFiles}" />

    <div class="maxwidth">
      <TextDivider
        color="{animals[selectedAnimal]?.color || 'var(--main-fg-color)'}"
      >
        OR
      </TextDivider>
    </div>

    {#await preExistingRootsPromise}
      <LoadingText />
    {:then preExistingRootResources}
      {#if preExistingRootsPromise && preExistingRootsPromise.length > 0}
        <form on:submit|preventDefault="{choosePreExistingRoot}">
          <select
            on:click|stopPropagation="{() => undefined}"
            bind:value="{selectedPreExistingRoot}"
          >
            <option value="{null}">Open existing resource</option>
            {#each preExistingRootResources as preExistingRoot}
              <option value="{preExistingRoot}">
                {preExistingRoot.id} &ndash;
                {#if preExistingRoot.caption}
                  {preExistingRoot.caption}
                {:else}
                  Untagged
                {/if}
              </option>
            {/each}
          </select>

          <button
            on:click|stopPropagation="{() => undefined}"
            disabled="{!selectedPreExistingRoot}"
            type="submit">Go!</button
          >
        </form>
      {:else}
        No resources loaded yet.
      {/if}
    {:catch}
      <p>Failed to get any pre-existing root resources!</p>
      <p>The back end server may be down.</p>
    {/await}
    <Animals
      x="{mouseX}"
      visible="{true}"
      bind:selectedAnimal="{selectedAnimal}"
    />
  </div>
{:else}
  <div class="center">
    <LoadingAnimation />
  </div>
{/if}
