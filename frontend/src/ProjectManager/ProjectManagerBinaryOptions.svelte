<style>
  button {
    margin-bottom: 1em;
    margin-left: 1em;
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    border: 1px solid var(--main-fg-color);
    border-radius: 0;
    font-size: smaller;
    overflow: hidden;
    box-shadow: none;
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
</style>

<script>
  import { selectedProject, settings, selected } from "../stores";
  import Icon from "../Icon.svelte";

  export let name;

  async function deleteBinary() {
    await fetch(`${$settings.backendUrl}/delete_binary_from_project`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        id: $selectedProject.session_id,
        binary: name,
      }),
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      $selectedProject = await fetch(
        `${$settings.backendUrl}/get_project_by_id?id=${$selectedProject.session_id}`
      ).then((r) => {
        if (!r.ok) {
          throw Error(r.statusText);
        }
        return r.json();
      });
      return await r.json();
    });
  }
</script>

<div>
  <button on:click|stopPropagation="{deleteBinary}"
    ><Icon url="/icons/trash.svg" />Delete {name} from project.</button
  >
</div>
