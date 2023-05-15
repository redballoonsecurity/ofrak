<style>
  button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
  }

  button:hover,
  button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 var(--main-fg-color),
      inset -1px -1px 0 var(--main-fg-color);
  }

  button:active {
    box-shadow: inset 2px 2px 0 var(--main-fg-color),
      inset -2px -2px 0 var(--main-fg-color);
  }

  .container {
    min-height: 100%;
    display: flex;
    flex-direction: column;
    flex-wrap: nowrap;
    justify-content: center;
    align-items: stretch;
    align-content: center;
  }

  .vert-grow {
    flex-grow: 1;
  }

  .inputs {
    display: flex;
    flex-direction: row;
    flex-wrap: wrap;
    justify-content: flex-start;
    align-items: baseline;
    align-content: flex-start;
  }

  .inputs *:first-child {
    margin-top: 0;
  }

  .inputs > * {
    margin: 1em 2em 1em 0;
  }

  .actions {
    margin-top: 2em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: center;
    align-content: center;
  }

  input {
    background: inherit;
    color: inherit;
    border: none;
    border-bottom: 1px solid var(--main-fg-color);
    flex-grow: 1;
    margin-left: 1ch;
  }

  input:focus {
    outline: none;
    box-shadow: inset 0 -1px 0 var(--main-fg-color);
  }

  label {
    margin-bottom: 1em;
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: space-evenly;
    align-items: baseline;
    align-content: center;
    white-space: nowrap;
    min-width: 20ch;
  }

  .error {
    margin-top: 2em;
  }

  input[type="file"] {
    display: none;
  }
</style>

<script context="module">
  const MAX_THEMES = 1;

  let lightThemes = [],
    darkThemes = [],
    themeNum = Math.floor(Math.random() * MAX_THEMES) + 1;
</script>

<script>
  import { loadSettings, settings } from "./stores.js";

  import Icon from "./Icon.svelte";
    import Checkbox from "./Checkbox.svelte";

  export let modifierView;
  let errorMessage, loadingDark, loadingLight, fileInput, browsedFiles;

  const originalSettings = JSON.parse(JSON.stringify($settings));

  // https://stackoverflow.com/a/12646864
  function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [array[i], array[j]] = [array[j], array[i]];
    }
  }

  async function huemintLight() {
    if (lightThemes.length > 0) {
      return lightThemes.pop();
    }
    try {
      const fetchPromise = fetch(
        `/themes/light/${themeNum.toString().padStart(2, "0")}.json`
      )
        .then(async (r) => {
          if (!r.ok) {
            throw Error(r.status);
          }
          return r.json();
        })
        .then((o) => {
          shuffleArray(o.results);
          o.results.forEach((p) => {
            lightThemes.push(p.palette);
          });
        });
      loadingLight = true;
      themeNum = Math.max((themeNum + 1) % (MAX_THEMES + 1), 1);
      await fetchPromise;
      loadingLight = false;
      if (lightThemes.length > 0) {
        return lightThemes.pop();
      }
    } catch (err) {
      errorMessage = `Huemint API called failed with ${err}`;
      loadingLight = false;
    }
  }

  async function huemintDark() {
    if (darkThemes.length > 0) {
      return darkThemes.pop();
    }
    try {
      const fetchPromise = fetch(
        `/themes/dark/${themeNum.toString().padStart(2, "0")}.json`
      )
        .then(async (r) => {
          if (!r.ok) {
            throw Error(r.status);
          }
          return r.json();
        })
        .then((o) => {
          shuffleArray(o.results);
          o.results.forEach((p) => {
            darkThemes.push(p.palette);
          });
        });
      loadingDark = true;
      themeNum = Math.max((themeNum + 1) % (MAX_THEMES + 1), 1);
      await fetchPromise;
      loadingDark = false;
      if (darkThemes.length > 0) {
        return darkThemes.pop();
      }
    } catch (err) {
      errorMessage = `Huemint API called failed with ${err}`;
      loadingDark = false;
    }
  }

  function setTheme(palette) {
    if (!palette) {
      return;
    }
    $settings.background = palette[0];
    $settings.foreground = palette[1];
    const shuffled = palette.slice(2);
    shuffleArray(shuffled);
    $settings.selected = shuffled[0];
    $settings.highlight = shuffled[1];
    $settings.comment = shuffled[2];
    $settings.accentText = shuffled[3];
    $settings.colors = shuffled;
  }

  $: if (browsedFiles && browsedFiles.length > 0) {
    const f = browsedFiles[0];
    f.text().then((text) => {
      $settings = JSON.parse(text);
    });
  }

  function saveSettings() {
    window.localStorage.setItem("settings", JSON.stringify($settings));
  }
</script>

<input type="file" bind:this="{fileInput}" bind:files="{browsedFiles}" />

<div class="container">
  <p>Edit settings and save them below. Export them to share with friends.</p>
  <div class="vert-grow">
    <div class="inputs">
      <label>
        Foreground
        <input type="color" bind:value="{$settings.foreground}" />
      </label>
      <label>
        Background
        <input type="color" bind:value="{$settings.background}" />
      </label>
      <label>
        Highlight
        <input type="color" bind:value="{$settings.highlight}" />
      </label>
      <label>
        Selected
        <input type="color" bind:value="{$settings.selected}" />
      </label>
      <label>
        Comment
        <input type="color" bind:value="{$settings.comment}" />
      </label>
      <label>
        Text Accent
        <input type="color" bind:value="{$settings.accentText}" />
      </label>
      {#each $settings.colors as _, i}
        <label>
          Accent {i + 1}
          <input type="color" bind:value="{$settings.colors[i]}" />
        </label>
      {/each}
    </div>
    <div style:margin="2em 0">
      <button
        on:click="{() => {
          $settings.colors.push('#dddddd');
          $settings.colors = $settings.colors;
        }}">Add color</button
      >
      <button
        on:click="{() => {
          huemintDark().then(setTheme);
        }}"
      >
        {#if loadingDark}
          <Icon url="/icons/loading.svg" />
        {/if}
        AI Generate dark mode
      </button>
      <button
        on:click="{() => {
          huemintLight().then(setTheme);
        }}"
      >
        {#if loadingLight}
          <Icon url="/icons/loading.svg" />
        {/if}
        AI Generate light mode
      </button>
    </div>
    <div class="inputs">
      <Checkbox bind:checked={$settings.showDevSettings} leftbox={true} nomargin={true}>Show Developer Settings</Checkbox>
    </div>
    {#if $settings.showDevSettings}
    <div class="inputs" style:margin="1em 0">
      <label>
        Backend URL
        <input type="text" bind:value={$settings.backendUrl} />
      </label>
    </div>
    {/if}
    {#if errorMessage}
      <p class="error">
        Error:
        {errorMessage}
      </p>
    {/if}
  </div>
  <div class="actions">
    <button
      on:click="{() => {
        $settings = loadSettings(true);
      }}">Reset All to Default</button
    >
    <button
      on:click="{() => {
        fileInput?.click();
      }}">Import Settings</button
    >
    <button
      on:click="{() => {
        const blob = new Blob([window.localStorage.getItem('settings')], {
          type: 'application/json',
        });
        const blobUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = blobUrl;
        a.target = '_blank';
        a.download = 'ofrak_settings.json';
        a.click();
        URL.revokeObjectURL(blobUrl);
      }}">Export Settings</button
    >
    <button on:click="{saveSettings}">Save Settings</button>
    <button
      on:click="{() => {
        if (
          window.localStorage.getItem('settings') != JSON.stringify($settings)
        ) {
          $settings = originalSettings;
        }
        modifierView = undefined;
      }}">Close</button
    >
  </div>
</div>
