<style>
.hbox {
    width: 100%;
    height: 100%;
    padding: 2em;
    overflow-y: hidden;
  }
.title {
    padding-bottom: .5em;
    text-align: center;
    font-size: xx-large;
    font-weight: bold;
    text-transform: uppercase;
}
.content-box {
    display: flex;
    outline: solid 2px var(--main-fg-color);
    border-radius: 5%;
    width: 100%;
    height: 80%;
    font-size: x-large;
    overflow: auto;
    overflow-y: hidden;
}
.content {
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100%;
    overflow:auto;
    overflow-y:  scroll;
}
.element {
    margin-block: 1em;
    margin-left: 1em;
    margin-top: 1em;
}
</style>

<script>
    import Checkbox from "../Checkbox.svelte";

    export let title, projectElementOptions, projectElementSelection;
</script>

<div class="hbox">
    <div class="title">"{title}"</div>
    <div class="content-box">
        <div class="content">
                {#each projectElementOptions as projectOption}
                    <div class="element">
                        <Checkbox bind:checked={projectElementSelection} leftbox="{true}">{projectOption}</Checkbox>
                    </div>
                {/each}
        </div>
    </div>
</div>
