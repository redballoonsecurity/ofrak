<script>
  import { selectedResource } from "../stores";
  import BaseSerializerInputForm from "../utils/serializer_inputs/BaseSerializerInputForm.svelte";
  import Loading from "../utils/LoadingText.svelte";

  export let patchInfo;

  // Should have some helpful hint about ARM vs. Thumb somewhere?

  async function getToolchainList() {
    let pfsm_config = await $selectedResource.get_config_for_component(
      "PatchFromSourceModifier"
    );

    return pfsm_config.fields;
  }

  let toolchain, toolchainConfig;

  if (patchInfo.userInputs.toolchain !== null) {
    toolchain = patchInfo.userInputs.toolchain;
  }

  if (patchInfo.userInputs.toolchainConfig !== null) {
    toolchainConfig = patchInfo.userInputs.toolchainConfig;
  }

  $: {
    let invalidate = false;
    if (toolchain && toolchain !== patchInfo.userInputs.toolchain) {
      patchInfo.userInputs.toolchain = toolchain;
      invalidate = true;
    }
    // The worst, best way to do deep comparisons and deep copies :)
    if (
      toolchainConfig &&
      JSON.stringify(toolchainConfig) !==
        JSON.stringify(patchInfo.userInputs.toolchainConfig)
    ) {
      patchInfo.userInputs.toolchainConfig = JSON.parse(
        JSON.stringify(toolchainConfig)
      );
      invalidate = true;
    }

    if (invalidate) {
      // Changes to toolchain config invalidate everything
      patchInfo.objectInfosValid = false;
      patchInfo.targetInfoValid = false;
    }
  }
</script>

{#await getToolchainList()}
  <Loading />
{:then toolchainConfig_structs}
  <BaseSerializerInputForm
    node="{toolchainConfig_structs[3]}"
    bind:element="{toolchain}"
  />
  <BaseSerializerInputForm
    node="{toolchainConfig_structs[2]}"
    bind:element="{toolchainConfig}"
  />
{:catch err}
  Failed to fetch toolchain configuration structure!
{/await}
