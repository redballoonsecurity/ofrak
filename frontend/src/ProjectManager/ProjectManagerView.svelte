<style>
  .vbox {
    width: 100%;
    height: 100%;
  }

  .title {
    text-transform: uppercase;
    font-weight: bold;
    color: inherit;
    font-size: xxx-large;
    line-height: 1;
    margin: 0;
    padding-bottom: 1em;
    max-width: 100%;
    max-height: 100%;
    text-align: center;
  }

  .manager {
    display: flex;
    align-items: stretch;
    justify-content: space-around;
    flex-direction: row;
    width: 100%;
    height: 70%;
  }

  .options-box{
    display: flex;
    outline: solid 2px var(--main-fg-color);
    border-radius: 5%;
    width: 100%;
    height: 30%;
    font-size: x-large;
    overflow: auto;
    overflow-y: hidden;
    margin-top: 1em;
}
.options{
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 30100%;
    overflow:auto;
    overflow-y:  scroll;
}
</style>

<script>
    import ProjectManagerSelector from "./ProjectManagerSelector.svelte";


  export let project;
</script>

<div class="vbox">
  <div class="title">OFRAK Project Manager</div>
  <div class="manager">
    <ProjectManagerSelector title=Binaries projectElementOptions="{project.binaries}"/>
    <ProjectManagerSelector title=Scripts projectElementOptions="{project.scripts}"/>
    <ProjectManagerSelector title=Components projectElementOptions="{project.components}"/>
  </div>
</div>
<div class="options-box">
  <div class="options">
      
  </div>
</div>
