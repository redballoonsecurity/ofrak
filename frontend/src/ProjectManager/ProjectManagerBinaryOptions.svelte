<script>
  import { selectedProject, settings, selected } from "../stores";
  import Icon from "../Icon.svelte";
  import Button from "../utils/Button.svelte"

  export let args, selectedBinaryName, forceRefreshProject;

  async function deleteBinary() {
    await fetch(`${$settings.backendUrl}/delete_binary_from_project`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        id: $selectedProject.session_id,
        binary: args.name,
      }),
    }).then(async (r) => {
      if (!r.ok) {
        throw Error(JSON.stringify(await r.json(), undefined, 2));
      }
      selectedBinaryName = undefined;
      forceRefreshProject = {};
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
  <Button
    on:click="{(e) => {
      e.stopPropagation();
      deleteBinary();
    }}"><Icon url="/icons/trash.svg" />Delete {args.name} from project.</Button
  >
</div>
