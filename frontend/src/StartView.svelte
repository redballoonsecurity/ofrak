<style>
  h1 {
    text-transform: uppercase;
    font-weight: bold;
    color: inherit;
    font-size: xxx-large;
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
</style>

<script>
  import Animals from "./Animals.svelte";
  import LoadingAnimation from "./LoadingAnimation.svelte";
  import LoadingText from "./LoadingText.svelte";

  import { animals } from "./animals.js";
  import { RemoteResourceFactory } from "./ofrak/remote_resource.js";
  import { selected } from "./stores.js";

  import { onMount } from "svelte";

  export let rootResourceLoadPromise,
    showRootResource,
    resourceFactory,
    rootResource,
    resourceNodeDataMap;
  let dragging = false,
    selectedPreExistingRoot = null,
    preExistingRootsPromise = new Promise(() => {}),
    tryHash = !!window.location.hash;
  let mouseX, selectedAnimal;

  function setBackend(_selectedRootID, _resourceFactory) {
    resourceFactory = _resourceFactory;
    rootResource = resourceFactory.create(_selectedRootID);
    $selected = _selectedRootID;
  }

  async function createRootResource(f) {
    const rootModel = await fetch(`/api/create_root_resource?name=${f.name}`, {
      method: "POST",
      body: await f.arrayBuffer(),
    }).then((r) => r.json());

    const _resourceFactory = new RemoteResourceFactory();
    _resourceFactory.add_to_cache(rootModel);
    setBackend(rootModel.id, _resourceFactory);
  }

  function choosePreExistingRoot() {
    if (selectedPreExistingRoot) {
      dragging = false;
      showRootResource = true;

      const _resourceFactory = new RemoteResourceFactory();
      _resourceFactory.add_to_cache(selectedPreExistingRoot);
      setBackend(selectedPreExistingRoot.id, _resourceFactory);

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

  async function getResourcesFromHash(resourceId) {
    const root = await fetch(`/api/${resourceId}/get_root`).then((r) => {
      if (!r.ok) {
        throw Error(r.statusText);
      }
      return r.json();
    });

    const _resourceFactory = new RemoteResourceFactory();
    _resourceFactory.add_to_cache(root);
    setBackend(root.id, _resourceFactory);

    let resource = await fetch(`/api/${resourceId}/`).then((r) => {
      if (!r.ok) {
        throw Error(r.statusText);
      }
      return r.json();
    });
    _resourceFactory.add_to_cache(resource);
    while (resource.parent_id) {
      resource = await fetch(`/api/${resource.parent_id}/`).then((r) => {
        if (!r.ok) {
          throw Error(r.statusText);
        }
        return r.json();
      });
      _resourceFactory.add_to_cache(resource);

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
    preExistingRootsPromise = await fetch(`/api/get_root_resources`).then((r) =>
      r.json()
    );
  });
</script>

{#if !tryHash}
  <div
    class="center {dragging ? 'dragging' : ''}"
    on:dragover|preventDefault="{(e) => {
      dragging = true;
      mouseX = e.clientX;
    }}"
    on:dragleave|preventDefault="{() => (dragging = false)}"
    on:drop|preventDefault="{handleDrop}"
    on:mousemove="{(e) => (mouseX = e.clientX)}"
    on:mouseleave="{() => (mouseX = undefined)}"
    style:border-color="{animals[selectedAnimal]?.color ||
      "var(--main-fg-color)"}"
    style:color="{animals[selectedAnimal]?.color || "var(--main-fg-color)"}"
  >
    {#if !dragging}
      <h1>Drag in a file to analyze</h1>
    {:else}
      <h1>Drop the file!</h1>
    {/if}

    {#await preExistingRootsPromise}
      <LoadingText />
    {:then preExistingRootResources}
      <form on:submit|preventDefault="{choosePreExistingRoot}">
        <select bind:value="{selectedPreExistingRoot}">
          <option value="{null}">None</option>
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

        <button disabled="{!selectedPreExistingRoot}" type="submit">Go!</button>
      </form>
    {:catch}
      <p>Failed to get any pre-existing root resources!</p>
      <p>The back end server may be down.</p>
    {/await}
    <Animals x="{mouseX}" visible="{true}" bind:selectedAnimal />
  </div>
{:else}
  <div class="center">
    <LoadingAnimation />
  </div>
{/if}
