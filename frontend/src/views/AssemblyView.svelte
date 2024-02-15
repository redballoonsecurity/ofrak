<style>
  .hbox {
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    justify-content: flex-start;
    align-items: stretch;
    min-height: calc(100% - 6em);
    max-height: calc(100% - 6em);
    overflow: auto;
  }

  .horizontal-spacer {
    width: 2em;
    min-width: 2em;
  }

  .vertical-spacer {
    height: 1em;
  }

  .address,
  .hex,
  .instruction {
    white-space: nowrap;
  }
</style>

<script>
  import LoadingAnimation from "../utils/LoadingAnimation.svelte";
  import LoadingText from "../utils/LoadingText.svelte";

  import { chunkList, buf2hex } from "../helpers.js";
  import { selectedResource } from "../stores.js";
  export const searchFunction = asmSearch;
  let searchString = "";
  let blocksPromise = Promise.resolve([]),
    dataWordsPromise = Promise.resolve([]);
  $: if ($selectedResource !== undefined) {
    blocksPromise = getBlocks($selectedResource).then((blocks) => {
      // Sort basic blocks in order of the virtual address of the first instruction
      blocks.sort((a, b) => {
        const aAddress =
          a[0]?.attributes[
            "ofrak.model._auto_attributes.AttributesType[Addressable]"
          ]?.virtual_address;
        const bAddress =
          b[0]?.attributes[
            "ofrak.model._auto_attributes.AttributesType[Addressable]"
          ]?.virtual_address;
        return aAddress - bAddress;
      });
      return blocks;
    });
    dataWordsPromise = $selectedResource.has_tag("ofrak.core.data.DataWord")
      ? Promise.resolve([$selectedResource])
      : $selectedResource
          .get_children()
          .then((children) =>
            children.filter((child) =>
              child.has_tag("ofrak.core.data.DataWord")
            )
          );
  }

  async function getBlocks(resource) {
    let blocks = [];
    if (resource.has_tag("ofrak.core.instruction.Instruction")) {
      blocks = [[resource]];
    } else if (resource.has_tag("ofrak.core.basic_block.BasicBlock")) {
      blocks = [await resource.get_children()];
    } else if (resource.has_tag("ofrak.core.complex_block.ComplexBlock")) {
      blocks = [].concat(
        ...(await Promise.all((await resource.get_children()).map(getBlocks)))
      );
    }
    return blocks;
  }

  async function asmSearch(query) {
    searchString = query;
  }
</script>

{#await Promise.all([blocksPromise, dataWordsPromise])}
  <LoadingAnimation />
{:then [blocks, dataWords]}
  <div class="hbox">
    <div class="address">
      {#each blocks.concat([dataWords]) as block}
        {#each block as instructionOrDataWord}
          <div>
            {instructionOrDataWord
              .get_attributes()
              [
                "ofrak.model._auto_attributes.AttributesType[Addressable]"
              ].virtual_address.toString(16)
              .padStart(8, "0") + ":"}
          </div>
        {/each}
        <div class="vertical-spacer"></div>
      {/each}
    </div>

    <div class="horizontal-spacer"></div>

    <div class="hex">
      {#each blocks.concat([dataWords]) as block}
        {#each block as instruction}
          <div>
            {#await instruction.get_data()}
              <LoadingText />
            {:then data}
              {chunkList(buf2hex(data), 2).join(" ")}
            {/await}
          </div>
        {/each}
        <div class="vertical-spacer"></div>
      {/each}
    </div>

    <div class="horizontal-spacer"></div>

    <div class="instruction">
      {#each blocks as block, i}
        {#each block as instruction}
          <div>
            {instruction.get_attributes()[
              "ofrak.model._auto_attributes.AttributesType[Instruction]"
            ].mnemonic +
              " " +
              instruction.get_attributes()[
                "ofrak.model._auto_attributes.AttributesType[Instruction]"
              ].operands}
          </div>
        {:else}
          {#if i == 0}
            <p>I said "Unpack Recursively"</p>
          {/if}
        {/each}
        <div class="vertical-spacer"></div>
      {:else}
        <p>
          Press "Unpack Recursively" on the far left to unpack this resource
          into instructions.
        </p>
      {/each}
      {#each dataWords as dataWord}
        <div>
          <!--        unpacked data word value not yet available as attribute -->
          <!--          0x{dataWord-->
          <!--            .get_attributes()-->
          <!--            .AttributesType[DataWord].unpacked.toString(16)}-->
          [literal]
        </div>
      {/each}
    </div>
  </div>
{/await}
