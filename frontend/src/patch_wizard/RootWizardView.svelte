<script>
  import Split from "../utils/Split.svelte";
  import Pane from "../utils/Pane.svelte";
  import Button from "../utils/Button.svelte";

  import { selectedResource, viewCrumbs } from "../stores";
  import SerializerInputForm from "../utils/SerializerInputForm.svelte";
  import SourceMenuView from "./SourceMenuView.svelte";
  import SummaryView from "./SummaryView.svelte";

    const defaultSourceBody = [
    '#include "aes_inject.h"',
    '#include "thumb_defines.h"\n',
    "",
    "#ifdef USE_THUMB",
    '__attribute__((target("thumb")))',
    "#else",
    '__attribute__((target("arm")))',
    "#endif",
    "int encrypt(unsigned char *plaintext, int plaintext_len,",
    "            unsigned char *key,",
    "            unsigned char *iv,",
    "            unsigned char *ciphertext)",
    "{",
    "    EVP_CIPHER_CTX *ctx;",
    "",
    "    int len;",
    "    int ciphertext_len;",
    "",
    "    /* Create and initialise the context */",
    "    if(!(ctx = EVP_CIPHER_CTX_new()))",
    "        handleErrors();",
    "",
    "    /* Initialise the encryption operation. */",
    "    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))",
    "        handleErrors();",
    "",
    "    /*",
    "     * Provide the message to be encrypted, and obtain the encrypted output.",
    "     * EVP_EncryptUpdate can be called multiple times if necessary",
    "     */",
    "    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))",
    "        handleErrors();",
    "    ciphertext_len = len;",
    "",
    "    /*",
    "     * Finalise the encryption. Further ciphertext bytes may be written at",
    "     * this stage.",
    "     */",
    "    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))",
    "        handleErrors();",
    "    ciphertext_len += len;",
    "",
    "    /* Clean up */",
    "    EVP_CIPHER_CTX_free(ctx);",
    "",
    "    return ciphertext_len;",
  ];

  const patch_info = {
    name: "Example Patch",
    sourceInfos: [
    { name: "file1.c", body: defaultSourceBody },
    { name: "file2.c", body: defaultSourceBody },
    { name: "file3.h", body: defaultSourceBody },
  ],
  };

  let toolchain,
    toolchainConfig = null;

  let subMenu = undefined;

  async function getToolchainList() {
    let pfsm_config = await $selectedResource.get_config_for_component(
      "PatchFromSourceModifier"
    );
    // console.log(pfsm_config["fields"]);

    return pfsm_config.fields;
  }
</script>

<Split>
  <Split slot="first" vertical="{true}" percentOfFirstSplit="{66.666}">
    <Pane slot="first">
      {#if subMenu}
        <svelte:component this="{subMenu}" bind:subMenu="{subMenu}" bind:patchInfo="{patch_info}"/>
      {:else}
        <Button on:click="{() => viewCrumbs.set(['rootResource'])}">Back</Button
        >

        <Button>Free Space</Button>

        <Button on:click="{() => (subMenu = SourceMenuView)}"
          >Source Code</Button
        >
      {/if}
    </Pane>
    <Pane slot="second" paddingVertical="{'1em'}">
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
    </Pane>
  </Split>
  <Pane slot="second">
    <SummaryView></SummaryView>
  </Pane>
</Split>
