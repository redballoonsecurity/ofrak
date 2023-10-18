<script>
  import Split from "../utils/Split.svelte";
  import Pane from "../utils/Pane.svelte";
  import Button from "../utils/Button.svelte";

  import { selectedResource, settings, viewCrumbs } from "../stores";
  import SourceMenuView from "./SourceMenuView.svelte";
  import SummaryView from "./SummaryView.svelte";
  import ObjectMappingView from "./ObjectMappingView.svelte";
  import ToolchainSetupView from "./ToolchainSetupView.svelte";

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

  let patch_info = {
    name: "Example Patch",
    sourceInfos: [
      { name: "file1.c", body: defaultSourceBody, originalName: undefined },
      { name: "file2.c", body: defaultSourceBody, originalName: undefined },
      { name: "file3.h", body: defaultSourceBody, originalName: undefined },
    ],
    objectInfosValid: true,
    objectInfos: [
      {
        name: "file1.c",
        segments: [
          {
            name: ".text",
            size: 0x100,
            permissions: "rx",
            include: true,
            allocatedVaddr: null,
          },
          {
            name: ".data",
            size: 0x100,
            permissions: "rw",
            include: true,
            allocatedVaddr: null,
          },
          {
            name: ".rodata",
            size: 0x100,
            permissions: "r",
            include: false,
            allocatedVaddr: null,
          },
        ],
        strongSymbols: ["foo"],
        unresolvedSymbols: ["printf", "bar", "boogeyman"],
      },
      {
        name: "file2.c",
        segments: [
          {
            name: ".text",
            size: 0x100,
            permissions: "rx",
            include: true,
            allocatedVaddr: null,
          },
        ],
        strongSymbols: ["bar"],
        unresolvedSymbols: [],
      },
    ],
    targetInfo: {
      symbols: ["printf", "sprintf", "malloc", "calloc", "kalloc"],
    },
    targetInfoValid: true,
    userInputs: {
      symbols: { example: 0xfeed },
      toolchain: undefined,
      toolchain_config: undefined,
    },
    symbolRefMap: null,
  };

  let subMenu = undefined;

  function assignSegmentColors() {
    let idx = 0;
    for (const obj of patch_info.objectInfos) {
      for (const seg of obj.segments) {
        seg.color = $settings.colors[idx];
        if (idx++ >= $settings.colors.length) {
          idx = 0;
        }
      }
    }
  }

  function buildSymbolRefMap(patchInfo) {
    let refMap = { allSyms: new Set() };

    for (const objInfo of patchInfo.objectInfos) {
      for (const sym of objInfo.strongSymbols) {
        if (refMap.hasOwnProperty(sym)) {
          refMap[sym].providedBy.push(objInfo.name);
        } else {
          refMap[sym] = {
            name: sym,
            providedBy: [objInfo.name],
            requiredBy: [],
          };
        }
        refMap.allSyms.add(sym);
      }
      for (const sym of objInfo.unresolvedSymbols) {
        if (refMap.hasOwnProperty(sym)) {
          refMap[sym].requiredBy.push(objInfo.name);
        } else {
          refMap[sym] = {
            name: sym,
            providedBy: [],
            requiredBy: [objInfo.name],
          };
        }
        refMap.allSyms.add(sym);
      }
    }

    for (const sym of patchInfo.targetInfo.symbols) {
      if (refMap.hasOwnProperty(sym)) {
        refMap[sym].providedBy.push("target binary");
      } else {
        refMap[sym] = {
          name: sym,
          providedBy: ["target binary"],
          requiredBy: [],
        };
      }
      refMap.allSyms.add(sym);
    }

    return refMap;
  }

  assignSegmentColors();

  function updateObjectInfos(updatedObjectInfos) {
    // May mutate updatedObjectInfos

    // Keep track of when source files were renamed, but their object placements should still be preserved
    const currentObjNames = new Map();
    for (const sourceInfo of patch_info.sourceInfos) {
      if (sourceInfo.originalName) {
        currentObjNames.add(sourceInfo.originalName, sourceInfo.name);
      } else {
        currentObjNames.add(sourceInfo.name, sourceInfo.name);
      }
    }

    // Map from current object names -> old object mappings
    let previousObjectSegmentInfos = new Map();
    // Carry over segment mapping and inclusion info from previous configuration
    // Allows for iterative patch development without losing all patch situation work
    if (patch_info.objectInfos) {
      for (const objInfo of patch_info.objectInfos) {
        for (const segInfo of objInfo.segments) {
          previousObjectSegmentInfos.set(
            currentObjNames.get(objInfo.name) + segInfo.name,
            { include: segInfo.include, allocatedVaddr: segInfo.allocatedVaddr }
          );
        }
      }
    }

    for (const objInfo of updatedObjectInfos) {
      for (const segInfo of objInfo.segments) {
        const prevInfo = previousObjectSegmentInfos.get(
          objInfo.name + segInfo.name
        );
        if (prevInfo) {
          segInfo.allocatedVaddr = prevInfo.allocatedVaddr;
          segInfo.include = prevInfo.include;
        }
      }
    }

    patch_info.objectInfos = updatedObjectInfos;
    patch_info.objectInfosValid = true;
  }

  patch_info.symbolRefMap = buildSymbolRefMap(patch_info);
</script>

<Split>
  <Split slot="first" vertical="{true}" percentOfFirstSplit="{66.666}">
    <Pane slot="first">
      <SummaryView patchInfo="{patch_info}" bind:subMenu="{subMenu}" />
    </Pane>
    <Pane slot="second" paddingVertical="{'1em'}">
      TO-DO: Patchmaker error logs.
    </Pane>
  </Split>
  <Pane slot="second">
    {#if subMenu}
      <svelte:component
        this="{subMenu}"
        bind:subMenu="{subMenu}"
        bind:patchInfo="{patch_info}"
      />
    {/if}
  </Pane>
</Split>
