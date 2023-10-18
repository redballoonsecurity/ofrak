<script>
  import SerializerInputForm from "../utils/SerializerInputForm.svelte";
  import { selectedResource } from "../stores";

  export let patchInfo;

  // Should have some helpful hint about ARM vs. Thumb somewhere?

  async function getToolchainList() {
    let pfsm_config = await $selectedResource.get_config_for_component(
      "PatchFromSourceModifier"
    );

    return pfsm_config.fields;
  }

  let toolchain, toolchainConfig;

  $: {
    if (toolchain) {
      patchInfo.userInputs.toolchain = toolchain;
    }
    if (toolchainConfig) {
      patchInfo.userInputs.toolchain_config = toolchainConfig;
    }

    if (toolchain || toolchainConfig) {
      // Changes to toolchain config invalidate everything
      patchInfo.objectInfosValid = false;
      patchInfo.targetInfoValid = false;
    }
  }
</script>

{#await getToolchainList() then toolchain_config_structs}
  <SerializerInputForm
    node="{toolchain_config_structs[3]}"
    bind:element="{toolchain}"
  />
  <SerializerInputForm
    node="{toolchain_config_structs[2]}"
    bind:element="{toolchainConfig}"
  />
{/await}
