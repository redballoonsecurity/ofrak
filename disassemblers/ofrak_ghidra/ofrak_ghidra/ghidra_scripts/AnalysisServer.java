import com.google.common.base.Strings;
import com.google.common.base.Strings;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import java.math.BigInteger;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.math.BigInteger;

import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;

public class AnalysisServer extends HeadlessScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        int serverPort = Integer.parseInt(args[0]);
        HttpServer server = HttpServer.create(new InetSocketAddress(serverPort), 0);
        String scriptName;
        String scriptEndpoint;

        for (int i = 1; i < args.length; i += 1){
            scriptName = args[i];
            server.createContext(
                String.format("/%s", scriptName),
                new HandleOfrakRequest(scriptName)
            );
            println(String.format("Adding handler: /%s -> %s", scriptName, scriptName));
        }

        server.setExecutor(null); // creates a default executor
        server.start();
        System.out.println("OFRAK Ghidra server started");

        while (true) {  // Some things are de-initialized once this method returns... keep it around
            Thread.sleep(Long.MAX_VALUE);
        }
    }

    public Map<String, List<String>> splitQuery(URI url) {
        if (Strings.isNullOrEmpty(url.getQuery())) {
            return Collections.emptyMap();
        }
        return Arrays.stream(url.getQuery().split("&"))
                .map(this::splitQueryParameter)
                .collect(Collectors.groupingBy(AbstractMap.SimpleImmutableEntry::getKey, LinkedHashMap::new, mapping(Map.Entry::getValue, toList())));
    }

    public AbstractMap.SimpleImmutableEntry<String, String> splitQueryParameter(String it) {
        final int idx = it.indexOf("=");
        final String key = idx > 0 ? it.substring(0, idx) : it;
        final String value = idx > 0 && it.length() > idx + 1 ? it.substring(idx + 1) : null;
        try {
            return new AbstractMap.SimpleImmutableEntry<>(
                    URLDecoder.decode(key, "UTF-8"),
                    URLDecoder.decode(value, "UTF-8")
            );
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

    public class HandleOfrakRequest implements HttpHandler {
        private String scriptName;
        HandleOfrakRequest(String scriptName){
            this.scriptName = scriptName;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                Map<String, List<String>> params = splitQuery(exchange.getRequestURI());
                ArrayList<String> scriptArgs = new ArrayList<String>();

                for (Map.Entry<String, List<String>> param : params.entrySet()) {
                    String paramName = param.getKey();
                    String paramVal = param.getValue().get(0);
                    if (paramName.startsWith("__arg_")){
                        int argPosition = Integer.parseInt(paramName.substring("__arg_".length()));
                        if (argPosition >= scriptArgs.size()){
                            scriptArgs.ensureCapacity(argPosition + 1);
                        }
                        scriptArgs.add(argPosition, paramVal);
                    }
                }
                String resultValueName = String.format("OfrakResult_%s", scriptName);

                // Pre-store an empty result so we are guaranteed to get something
                storeHeadlessValue(resultValueName, "");
                println(String.format("Running %s", scriptName));
                runScript(scriptName, scriptArgs.toArray(new String[0]));
                println(String.format("Finished running %s", scriptName));
                String response = getStoredHeadlessValue(resultValueName).toString();

                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } catch(Exception e) {
                println(String.format("Encountered error in handler for %s!", scriptName));
                String errString = e.toString();
                println(errString);

                exchange.sendResponseHeaders(500, errString.length());
                OutputStream os = exchange.getResponseBody();
                os.write(errString.getBytes());
                os.close();
            }
        }
    }
}
