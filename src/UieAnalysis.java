import ghidra.app.util.headless.HeadlessScript;
import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/** Fast discovery profile. Deferred analyses can still be run explicitly later. */
public class UieAnalysis extends HeadlessScript {
    private static final String[] DEFERRED = {
        "Aggressive Instruction Finder", "ARM Aggressive Instruction Finder",
        "Stack", "Decompiler Parameter ID", "Decompiler Switch Analysis",
        "Subroutine References", "Shared Return Calls", "Non-Returning Functions - Discovered",
        "x86 Constant Reference Analyzer"
    };

    @Override public void run() throws Exception {
        Map<String,String> current=getCurrentAnalysisOptionsAndValues(currentProgram);
        Map<String,String> changed=new LinkedHashMap<>();
        List<String> unavailable=new ArrayList<>();
        for(String name:DEFERRED){
            if(current.containsKey(name))changed.put(name,"false");
            else unavailable.add(name);
        }
        for(String name:Arrays.asList("Function ID","Function ID.Create Analysis Bookmarks")){
            if(current.containsKey(name))changed.put(name,"true");
            else unavailable.add(name);
        }
        setAnalysisOptions(currentProgram,changed);
        Map<String,Object> report=new LinkedHashMap<>();
        report.put("profile","fast discovery");
        report.put("options",changed);
        report.put("unavailable_options",unavailable);
        report.put("time_limit_added",false);
        report.put("interpretation","Stack, switch and parameter inference are deferred; FID only identifies functions covered by installed signature databases.");
        Gson json=new Gson();
        if(getScriptArgs().length>0)Files.writeString(Paths.get(getScriptArgs()[0]),json.toJson(report),StandardCharsets.UTF_8);
        println("UIE analysis profile: "+json.toJson(report));
        Map<String,Object> event=new LinkedHashMap<>();
        event.put("kind","progress");event.put("phase","fast native analysis");
        event.put("file",currentProgram.getName());event.put("done",0);event.put("total",0);
        System.out.write(("UIE_EVENT "+json.toJson(event)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }
}
