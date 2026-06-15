# Writing Ghidra Components

## Summary

To add a new OFRAK Ghidra component:

1. Create one or more Ghidra scripts to implement whatever logic you need from the handler. 
Get any inputs using ``getScriptArgs()``. Return any results using 
``storeHeadlessValue("OfrakResult_{script name}", {value})``.

2. Implement your component as a subclass of 
[OfrakGhidraMixin][ofrak_ghidra.ghidra_model.OfrakGhidraMixin].

3. Define an [OfrakGhidraScript][ofrak_ghidra.ghidra_model.OfrakGhidraScript] for each Ghidra script you will call from your component. Define these as class variables of the component.


4. In the body of your component, call the script(s) you defined with ``await self.my_script.call_script(resource, ...)``. See the [call_script][ofrak_ghidra.ghidra_model.OfrakGhidraScript.call_script] documentation for more info.

An example of all the above:

```java
public class MyGhidraScript extends HeadlessScript {

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        // Some logic in Ghidra
        ...
        // How to return results to OFRAK. We just return the same strings we were given.
        storeHeadlessValue("OfrakResult_MyGhidraScript.java", arguments);
    }
}
```

```python
class MyHappyGhidraAnalyzer(Analyzer, OfrakGhidraMixin):

    # define all the Ghidra scripts this component uses here, as class attributes
    my_script = OfrakGhidraScript("relative/path/to/MyGhidraScript.java")

    # define targets, output, etc. as normally for Analyzer    
    ...
    
    async def analyze(self, resource: Resource):
        some_argument = "main"
        result = await self.my_script.call_script(resource, some_argument)
        # the script just returns the same values we give it, so result == ["main"]
        ...

```

## Understanding the OFRAK-Ghidra Dataflow

At a high level, [OFRAK maintains a Ghidra server and repository running in the background](#ofrak-ghidra-service). When analyzing a resource with Ghidra, OFRAK starts a headless Ghidra process to import that resource into the repository, analyze, and then start [a server](#ghidra-server) from within the Ghidra process.
This server accepts requests from [Ghidra OFRAK components](#ofrak-ghidra-components) to run [Ghidra scripts](#ghidra-scripts).

When OFRAK is initialized with a Ghidra backend, the background Ghidra server will be started if it is not running.
This step can take a few minutes, but only needs to be done once per environment (for example, it will need to be rerun after a reboot).

When a component requests to run a Ghidra script, if the target resource (or one of its ancestors tagged as a [GhidraProject][ofrak_ghidra.ghidra_model.GhidraProject]) is not imported to Ghidra, this will be done automatically. Sometimes it is useful to import an existing Ghidra project rather than relying on the automatic Ghidra analysis; in this case, an existing .gzf file can be imported by running [GhidraProjectAnalyzer][ofrak_ghidra.components.ghidra_analyzer.GhidraProjectAnalyzer] manually:

```python
root_resource = await ofrak_context.create_root_resource_from_file(path)
root_resource.add_tag(GhidraProject)
await root_resource.save()
await root_resource.run(GhidraProjectAnalyzer, GhidraProjectConfig(gzf_path))

```

## OFRAK Ghidra Components

For the most part, writing an OFRAK Ghidra component is identical to [writing any OFRAK component](../getting-started.md), with the exception that the component should subclass the [OfrakGhidraMixin][ofrak_ghidra.ghidra_model.OfrakGhidraMixin] (in addition to the relevant component type) and define any Ghidra scripts it will call as class variables of the type [OfrakGhidraScript][ofrak_ghidra.ghidra_model.OfrakGhidraScript].
In the functional body of the component, each of these scripts can be invoked in Ghidra by calling its [call_script][ofrak_ghidra.ghidra_model.OfrakGhidraScript.call_script] method.


## Ghidra Server

The server defined by the class ``AnalysisServer``, found in `/disassemblers/ofrak_ghidra/ofrak_ghidra/ghidra_scripts/AnalysisServer.java` defines a server which listens for HTTP requests. Each request contains the name of a Ghidra script, and possibly some keyword arguments (the same keyword arguments passed to ``ghidra_request``). When the server receives a request, it [sets a Ghidra headless variable](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessScript.html#storeHeadlessValue(java.lang.String,java.lang.Object)) for each keyword argument (to make it available between scripts) then runs the given script.
It then tries to get any results of the script through another headless value (set by the script), then sends those results back as a text.

If an error is encountered during the above, the server will respond with a status of 500 and try to send back the error message.

## Ghidra scripts

Any Ghidra script that can be run in headless mode can be run by OFRAK Ghidra components. A Ghidra script is "registered" in OFRAK by creating an [OfrakGhidraScript][ofrak_ghidra.ghidra_model.OfrakGhidraScript] instance as a class member of an [OfrakGhidraMixin][ofrak_ghidra.ghidra_model.OfrakGhidraMixin] subclass.
An `OfrakGhidraScript` instance can then be called using its [call_script][ofrak_ghidra.ghidra_model.OfrakGhidraScript.call_script] method, has one required argument: a target resource, which is assumed to have an ancestor tagged as a [GhidraProject][ofrak_ghidra.ghidra_model.GhidraProject] (or itself be tagged as a ``GhidraProject``). Usually, this tag is just automatically added to all [Program][ofrak.core.program.Program] resources.

If the script requires some arguments, they can also be passed to ``call_script``. Any number of string arguments may be passed in, and they will be available to the script using the standard Ghidra script argument API: [getScriptArgs](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html#getScriptArgs()).

Often the OFRAK component needs to get some data back from the Ghidra script. This should be done by storing the data as a JSON string inside a [Ghidra headless variable](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessScript.html#storeHeadlessValue%28java.lang.String,java.lang.Object)
at the end of the script.
After running each script (e.g. `CustomScript`), the analysis server will get stored headless variable with the name `OfrakResult_<script name>` (e.g. `OfrakResult_CustomScript`) and send its data back to OFRAK. This data is then parsed as JSON and returned by the ``call_script`` method.

<div align="right">
<img src="../../assets/square_02.png" width="125" height="125">
</div>
