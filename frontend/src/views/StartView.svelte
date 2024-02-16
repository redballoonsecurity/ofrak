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
    display: flex;
    width: 80%;
    max-width: 90%;
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

  select,
  option,
  input {
    background-color: var(--main-bg-color);
    color: inherit;
    border: 1px solid;
    border-color: inherit;
    border-radius: 0;
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    margin: 0.5em;
    font-size: inherit;
    font-family: var(--font);
    box-shadow: none;
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

  .project-options {
    display: flex;
    flex-direction: column;
  }

  .project-input {
    display: flex;
    flex-direction: column;
  }

  .project {
    display: flex;
    flex-direction: column;
    justify-content: stretch;
    align-items: stretch;
    max-width: 35%;
    width: 50%;
  }

  .advanced {
    display: flex;
    flex-direction: column;
    width: 100%;
  }

  .advanced-options {
    display: flex;
    flex-direction: row;
  }

  .advanced-check {
    margin: 0.5em;
  }

  .set-location-button {
    width: 25%;
  }

  .advanced-options > input {
    width: 75%;
  }

  /* TODO: This checkbox should be replaced with a properly placed button to access all settings */
  .experiment-features-check {
    position: fixed;
    top: 3em;
    left: 3em;
  }
</style>

<script>
  import Animals from "../utils/Animals.svelte";
  import LoadingAnimation from "../utils/LoadingAnimation.svelte";
  import LoadingText from "../utils/LoadingText.svelte";
  import TextDivider from "../utils/TextDivider.svelte";
  import Button from "../utils/Button.svelte";
  import Checkbox from "../utils/Checkbox.svelte";

  import { animals } from "../animals.js";
  import {
    selected,
    settings,
    selectedProject,
    resourceNodeDataMap,
  } from "../stores.js";
  import { remote_model_to_resource } from "../ofrak/remote_resource";
  import { numBytesToQuantity, saveSettings } from "../helpers";

  import { onMount } from "svelte";

  export let rootResourceLoadPromise,
    showRootResource,
    showProjectManager,
    resources,
    rootResource,
    browsedFiles,
    fileinput;
  let dragging = false,
    selectedPreExistingRoot = null,
    preExistingRootsPromise = new Promise(() => {}),
    preExistingProjectsPromise = new Promise(() => {}),
    tryHash = !!window.location.hash;
  let mouseX,
    selectedAnimal,
    showProjectOptions,
    newProjectName,
    gitUrl,
    projectPath,
    showAdvancedProjectOptions;
  const warnFileSize = 250 * 1024 * 1024;
  const fileChunkSize = warnFileSize;

  async function sendChunk(id, f, start) {
    let end = Math.min(start + fileChunkSize, f.size);
    await fetch(
      `${$settings.backendUrl}/root_resource_chunk?id=${id}&start=${start}&end=${end}`,
      {
        method: "POST",
        body: await f.slice(start, end),
      }
    );
  }

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
      let id = await fetch(
        `${$settings.backendUrl}/init_chunked_root_resource?name=${f.name}&size=${f.size}`,
        { method: "POST" }
      ).then((r) => r.json());
      let chunkStartAddrs = Array.from(
        { length: Math.ceil(f.size / fileChunkSize) },
        (v, i) => i * fileChunkSize
      );
      await Promise.all(
        chunkStartAddrs.map((start) => sendChunk(id, f, start))
      );

      rootModel = await fetch(
        `${$settings.backendUrl}/create_chunked_root_resource?id=${id}&name=${f.name}`,
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

  async function createNewProject() {
    let result = await fetch(`${$settings.backendUrl}/create_new_project`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: newProjectName,
      }),
    }).then((r) => {
      if (!r.ok) {
        throw Error(r.statusText);
      }
      return r.json();
    });
    $selectedProject = await fetch(
      `${$settings.backendUrl}/get_project_by_id?id=${result.id}`
    ).then((r) => {
      if (!r.ok) {
        throw Error(r.statusText);
      }
      return r.json();
    });
    showProjectManager = true;
  }

  async function cloneProjectFromGit() {
    let result = await fetch(`${$settings.backendUrl}/clone_project_from_git`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: gitUrl,
      }),
    })
      .then((r) => {
        if (!r.ok) {
          throw Error(r.statusText);
        }
        return r.json();
      })
      .catch((e) => {
        try {
          let errorObject = JSON.parse(e.message);
          alert(`${errorObject.type}: ${errorObject.message}`);
        } catch {
          alert(e);
        }
        console.error(e);
      });
    $selectedProject = await fetch(
      `${$settings.backendUrl}/get_project_by_id?id=${result.id}`
    ).then((r) => {
      if (!r.ok) {
        throw Error(r.statusText);
      }
      return r.json();
    });
    showProjectManager = true;
  }

  async function changeProjectPath() {
    let result = await fetch(`${$settings.backendUrl}/set_projects_path`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        path: projectPath,
      }),
    })
      .then((r) => {
        if (!r.ok) {
          throw Error(r.statusText);
        }
        return r.json();
      })
      .catch((e) => {
        try {
          let errorObject = JSON.parse(e.message);
          alert(`${errorObject.type}: ${errorObject.message}`);
        } catch {
          alert(e);
        }
        console.error(e);
      });
    projectPath = await fetch(`${$settings.backendUrl}/get_projects_path`).then(
      (r) => r.json()
    );
    preExistingProjectsPromise = await fetch(
      `${$settings.backendUrl}/get_all_projects`
    ).then((r) => r.json());
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
    if ($resourceNodeDataMap[resource.id] === undefined) {
      $resourceNodeDataMap[resource.id] = {};
    }
    $resourceNodeDataMap[resource.id].collapsed = false;
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

      if ($resourceNodeDataMap[resource.id] === undefined) {
        $resourceNodeDataMap[resource.id] = {};
      }
      $resourceNodeDataMap[resource.id].collapsed = false;
    }

    showRootResource = true;
    rootResourceLoadPromise = Promise.resolve(undefined);
    $selected = resourceId;
    $selectedProject = await fetch(
      `${$settings.backendUrl}/${resourceId}/get_project_by_resource_id`
    ).then((r) => {
      if (!r.ok) {
        throw Error(r.statusText);
      }
      return r.json();
    });
  }
  $: if ($settings) {
    saveSettings();
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
    projectPath = await fetch(`${$settings.backendUrl}/get_projects_path`).then(
      (r) => r.json()
    );
    preExistingProjectsPromise = await fetch(
      `${$settings.backendUrl}/get_all_projects`
    ).then((r) => r.json());
  });
</script>

{#if !tryHash}
  <div
    class="experiment-features-check"
    style:color="{animals[selectedAnimal]?.color || "var(--main-fg-color)"}"
  >
    <Checkbox
      bind:checked="{$settings.experimentalFeatures}"
      leftbox="{true}"
      nomargin="{true}">Enable Experimental OFRAK Features</Checkbox
    >
  </div>
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <div
    class="center clickable {dragging ? 'dragging' : ''}"
    on:dragover="{(e) => {
      e.preventDefault();
      dragging = true;
      mouseX = e.clientX;
    }}"
    on:dragleave="{(e) => {
      e.preventDefault();
      dragging = false;
    }}"
    on:drop="{(e) => {
      e.preventDefault();
      handleDrop(e);
    }}"
    on:mousemove="{(e) => (mouseX = e.clientX)}"
    on:mouseleave="{() => (mouseX = undefined)}"
    on:click="{() => {
      if (!showProjectOptions) {
        fileinput.click();
      }
    }}"
    style:border-color="{animals[selectedAnimal]?.color ||
      "var(--main-fg-color)"}"
    style:color="{animals[selectedAnimal]?.color || "var(--main-fg-color)"}"
  >
    {#if !dragging && !showProjectOptions}
      <h1>Drag in a file to analyze</h1>
      <p style:margin-bottom="0">
        Click anwyhere to browse for a file to analyze
      </p>
    {:else if dragging}
      <h1>Drop the file!</h1>
    {:else if showProjectOptions}
      <h1>Project Options</h1>
      <TextDivider
        color="{animals[selectedAnimal]?.color || 'var(--main-fg-color)'}"
      />
    {/if}
    {#if !showProjectOptions}
      <input type="file" bind:this="{fileinput}" bind:files="{browsedFiles}" />

      <div class="maxwidth">
        <TextDivider
          color="{animals[selectedAnimal]?.color || 'var(--main-fg-color)'}"
        >
          OR
        </TextDivider>
      </div>
    {/if}
    {#await preExistingRootsPromise}
      <LoadingText />
    {:then preExistingRootResources}
      {#if !showProjectOptions && preExistingRootsPromise && preExistingRootsPromise.length > 0}
        <form
          on:submit="{(e) => {
            e.preventDefault();
            choosePreExistingRoot();
          }}"
        >
          <select
            on:click="{(e) => {
              e.stopPropagation();
            }}"
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
          <Button
            on:click="{async (e) => {
              e.stopPropagation();
              $selectedProject = await fetch(
                `${$settings.backendUrl}/${selectedPreExistingRoot.id}/get_project_by_resource_id`
              ).then((r) => {
                if (!r.ok) {
                  throw Error(r.statusText);
                }
                return r.json();
              });
            }}"
            disabled="{!selectedPreExistingRoot}"
            type="submit">Go!</Button
          >
        </form>
      {:else if !showProjectOptions}
        No resources loaded yet.
      {/if}
    {:catch}
      <p>Failed to get any pre-existing root resources!</p>
      <p>The back end server may be down.</p>
    {/await}
    {#if $settings.experimentalFeatures}
      <div class="project">
        {#if showProjectOptions}
          <div class="project-options">
            <div class="project-input">
              <input
                on:click|stopPropagation
                type="text"
                bind:value="{newProjectName}"
                placeholder="Project Name"
              />
              <Button
                disabled="{!(newProjectName?.length > 0)}"
                on:click="{(e) => {
                  e.stopPropagation;
                  createNewProject();
                }}">Create New Project</Button
              >
            </div>
            <TextDivider
              color="{animals[selectedAnimal]?.color || 'var(--main-fg-color)'}"
            >
              OR
            </TextDivider>
            <div class="project-input">
              {#await preExistingProjectsPromise then projects}
                <select
                  on:click="{(e) => {
                    e.stopPropagation();
                  }}"
                  bind:value="{$selectedProject}"
                >
                  <option value="{undefined}" selected disabled
                    >Select a Project</option
                  >
                  {#each projects as project}
                    <option value="{project}">
                      {project.name}: {project.session_id}
                    </option>
                  {/each}
                </select>
                <Button
                  disabled="{!$selectedProject}"
                  on:click="{(e) => {
                    e.stopPropagation;
                    showProjectManager = true;
                  }}">Open Existing Project</Button
                >
              {/await}
            </div>
            <TextDivider
              color="{animals[selectedAnimal]?.color || 'var(--main-fg-color)'}"
            >
              OR
            </TextDivider>
            <div class="project-input">
              <input
                on:click="{(e) => {
                  e.stopPropagation();
                }}"
                type="text"
                bind:value="{gitUrl}"
                placeholder="Git Url"
              />
              <Button
                disabled="{!(gitUrl?.length > 0)}"
                on:click="{(e) => {
                  e.stopPropagation, cloneProjectFromGit();
                }}">Clone Project From Git</Button
              >
            </div>
          </div>
          <div class="advanced">
            <div class="advanced-check">
              <Checkbox
                leftbox="{true}"
                bind:checked="{showAdvancedProjectOptions}"
                >Show Advanced Options</Checkbox
              >
            </div>
            {#if showAdvancedProjectOptions}
              <div class="advanced-options">
                <input bind:value="{projectPath}" placeholder="{projectPath}" />
                <div class="set-location-button">
                  <Button
                    on:click="{(e) => {
                      e.stopPropagation();
                      changeProjectPath();
                    }}">Set Location</Button
                  >
                </div>
              </div>
            {/if}
          </div>
          <Button
            on:click="{(e) => {
              e.stopPropagation;
              showProjectOptions = false;
            }}">Back</Button
          >
        {:else}
          <Button
            on:click="{(e) => {
              e.stopPropagation();
              showProjectOptions = true;
            }}">Show Project Options</Button
          >
        {/if}
      </div>
    {/if}
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
