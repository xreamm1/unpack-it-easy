import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class UieExport extends GhidraScript {
    private static final int TIMEOUT = FUNCTION_TIMEOUT;
    private static final int ENTROPY_WINDOW = 65536;
    private static final int WINDOWS_PER_SECTION = 8;
    private static final double ENTROPY_THRESHOLD = 7.2;
    private static final int MAX_XREFS = 2048;
    private static final String[] USER_NAMES = {"impl_", "modulecode_", "Nuitka_Function", "_create_compiled_function", "__pyx_pf", "__pyx_f"};
    private static final String[] INIT_NAMES = {"_initConstants", "createModuleConstants", "module_init", "PyInit_", "modulecode_"};
    private static final String[] CRT_PREFIXES = {"__scrt", "__acrt", "__vcrt", "__security_", "_RTC_", "_guard_", "__guard_", "_GSHandler", "__CxxFrameHandler", "_except_handler", "__std_", "std::", "__gnu_cxx::", "__stdio_", "__crt_", "__SEH_", "_Unwind_", "__mingw_", "__chkstk", "___chkstk", "__alloca_", "__except_", "__imp_"};
    private static final Set<String> CRT_NAMES = new HashSet<>(Arrays.asList("malloc","calloc","realloc","free","memcpy","memmove","memset","memcmp","strlen","strcmp","strncmp","strcpy","wcslen","_initterm","_initterm_e","atexit","__tmainCRTStartup","mainCRTStartup","WinMainCRTStartup","_DllMainCRTStartup"));
    private final Gson json = new GsonBuilder().disableHtmlEscaping().create();
    private int line = 1;
    private BufferedWriter writer;

    private boolean matches(String name, String[] markers) {
        for (String marker : markers) if (name.contains(marker)) return true;
        return false;
    }
    private boolean user(Function function) { return matches(function.getSymbol().getName(true),USER_NAMES); }
    private boolean initializer(Function function) { return matches(function.getSymbol().getName(true),INIT_NAMES); }
    private boolean runtime(Function function) {
        if (user(function) || initializer(function)) return false;
        if (function.isExternal() || function.isThunk()) return true;
        String name = function.getSymbol().getName(true);
        if (CRT_NAMES.contains(name)) return true;
        for (String prefix : CRT_PREFIXES) if (name.startsWith(prefix)) return true;
        return false;
    }
    private Map<String,Object> row(Object... fields) {
        Map<String,Object> result = new LinkedHashMap<>();
        for (int i=0; i<fields.length; i+=2) result.put(fields[i].toString(),fields[i+1]);
        return result;
    }
    private String rva(Address address) { return "0x" + Long.toHexString(address.subtract(currentProgram.getImageBase())); }
    private void write(String text) throws IOException {
        writer.write(text);
        for (int i=0;i<text.length();i++) if (text.charAt(i)=='\n') line++;
    }
    private double entropy(byte[] data, int count) {
        long[] bins = new long[256];
        for (int i=0;i<count;i++) bins[data[i]&255]++;
        double result=0;
        for (long bin : bins) if (bin!=0) { double p=(double)bin/count; result-=p*(Math.log(p)/Math.log(2)); }
        return result;
    }
    private int priority(Function function, Set<Address> candidates) {
        if (user(function)) return 0;
        if (initializer(function)) return 1;
        return candidates.contains(function.getEntryPoint()) ? 2 : 3;
    }

    @Override public void run() throws Exception {
        Path output = Paths.get(getScriptArgs()[0]);
        String source = getScriptArgs().length>1 ? getScriptArgs()[1] : output.getFileName().toString();
        List<Map<String,Object>> sections = new ArrayList<>();
        List<Map<String,Object>> highEntropy = new ArrayList<>();
        List<Map<String,Object>> references = new ArrayList<>();
        Set<Address> candidates = new HashSet<>();
        Memory memory = currentProgram.getMemory();
        ReferenceManager refs = currentProgram.getReferenceManager();
        boolean limited = false;
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || block.getSize()<256) continue;
            double maximum=0, sum=0; int samples=0;
            AddressSet highRanges = new AddressSet();
            int count=(int)Math.min(WINDOWS_PER_SECTION,Math.max(1,(block.getSize()+ENTROPY_WINDOW-1)/ENTROPY_WINDOW));
            for (int i=0;i<count;i++) {
                long offset=count==1 ? 0 : (block.getSize()-Math.min(block.getSize(),ENTROPY_WINDOW))*i/(count-1);
                int length=(int)Math.min(ENTROPY_WINDOW,block.getSize()-offset);
                byte[] data=new byte[length]; Address start=block.getStart().add(offset);
                int actual=memory.getBytes(start,data);
                if (actual<256) continue;
                double value=entropy(data,actual); maximum=Math.max(maximum,value); sum+=value; samples++;
                if (value>=ENTROPY_THRESHOLD && !block.isExecute()) highRanges.addRange(start,start.add(actual-1));
            }
            Map<String,Object> section=row("name",block.getName(),"address",block.getStart().toString(),"rva",rva(block.getStart()),"size",block.getSize(),"sample_windows",samples,"max_entropy",maximum,"mean_entropy",samples==0?0:sum/samples,"executable",block.isExecute());
            sections.add(section);
            if (!highRanges.isEmpty()) {
                highEntropy.add(section);
                AddressIterator destinations=refs.getReferenceDestinationIterator(highRanges,true);
                while (destinations.hasNext()) {
                    Address destination=destinations.next(); ReferenceIterator iterator=refs.getReferencesTo(destination);
                    while (iterator.hasNext()) {
                        Reference reference=iterator.next(); Function function=getFunctionContaining(reference.getFromAddress());
                        if (function==null) continue;
                        if (references.size()>=MAX_XREFS) { limited=true; break; }
                        candidates.add(function.getEntryPoint());
                        references.add(row("section",block.getName(),"from",reference.getFromAddress().toString(),"from_rva",rva(reference.getFromAddress()),"to",destination.toString(),"to_rva",rva(destination),"function",function.getSymbol().getName(true),"function_address",function.getEntryPoint().toString(),"function_rva",rva(function.getEntryPoint()),"reference_type",reference.getReferenceType().toString(),"interpretation","high-entropy data reference; not proof of a decryptor"));
                    }
                    if (limited) break;
                }
            }
            if (monitor.isCancelled()) break;
        }
        List<Function> queue=new ArrayList<>(); List<Map<String,Object>> skipped=new ArrayList<>();
        FunctionIterator all=currentProgram.getFunctionManager().getFunctions(true);
        while (all.hasNext()) {
            Function function=all.next();
            if (runtime(function) && !candidates.contains(function.getEntryPoint())) skipped.add(row("name",function.getSymbol().getName(true),"address",function.getEntryPoint().toString(),"reason",function.isExternal()||function.isThunk()?"external/system thunk":"CRT name heuristic"));
            else queue.add(function);
        }
        queue.sort(Comparator.comparingInt((Function f)->priority(f,candidates)).thenComparing(Function::getEntryPoint));
        List<Map<String,Object>> pythonStrings=new ArrayList<>();
        DataIterator defined=currentProgram.getListing().getDefinedData(true);
        while(defined.hasNext()&&pythonStrings.size()<1024&&!monitor.isCancelled()){
            Data data=defined.next();Object value=data.getValue();if(!(value instanceof String))continue;
            String text=(String)value;
            if(text.length()>512||!(text.contains("Nuitka")||text.contains("__pyx_")||text.endsWith(".py")||text.contains("__main__")||text.startsWith("modulecode_")||text.startsWith("impl_")))continue;
            List<Map<String,Object>> incoming=new ArrayList<>();ReferenceIterator refsTo=refs.getReferencesTo(data.getAddress());
            while(refsTo.hasNext()&&incoming.size()<64){Reference reference=refsTo.next();Function function=getFunctionContaining(reference.getFromAddress());
                if(function!=null){candidates.add(function.getEntryPoint());incoming.add(row("function",function.getSymbol().getName(true),"address",function.getEntryPoint().toString(),"rva",rva(function.getEntryPoint()),"from",reference.getFromAddress().toString()));}
            }
            pythonStrings.add(row("value",text,"address",data.getAddress().toString(),"rva",rva(data.getAddress()),"references",incoming));
        }
        queue.sort(Comparator.comparingInt((Function f)->priority(f,candidates)).thenComparing(Function::getEntryPoint));
        DecompInterface decompiler=new DecompInterface();
        List<Map<String,Object>> functions=new ArrayList<>(); List<Map<String,Object>> initializers=new ArrayList<>();
        int success=0,failed=0,processed=0;
        try (BufferedWriter opened=Files.newBufferedWriter(output,StandardCharsets.UTF_8)) {
            writer=opened;
            if (!decompiler.openProgram(currentProgram)) throw new IOException("Cannot open program");
            write("/* UIE / Ghidra pseudocode. Runtime filtering uses names and thunk metadata. */\n");
            for (Function function : queue) {
                if (monitor.isCancelled()) break;
                int firstLine=line+1;
                String name=function.getSymbol().getName(true);
                write("\n/* Function at "+function.getEntryPoint()+": "+name.replace("*/","* /")+" */\n");
                DecompileResults result=decompiler.decompileFunction(function,TIMEOUT,monitor);
                boolean good=result.decompileCompleted()&&result.getDecompiledFunction()!=null;
                boolean retried=false;
                if(!good&&!monitor.isCancelled()){
                    retried=true;DecompileOptions conservative=new DecompileOptions();conservative.setEliminateUnreachable(false);conservative.setRespectReadOnly(false);conservative.setPredicate(false);
                    decompiler.setOptions(conservative);decompiler.flushCache();
                    DecompileResults retry=decompiler.decompileFunction(function,TIMEOUT,monitor);
                    if(retry.decompileCompleted()&&retry.getDecompiledFunction()!=null){result=retry;good=true;}
                    decompiler.setOptions(new DecompileOptions());decompiler.flushCache();
                }
                if (good) { write(result.getDecompiledFunction().getC()); success++; }
                else {
                    write("/* decompilation failed: "+result.getErrorMessage().replace("*/","* /")+"\n");
                    ghidra.program.model.listing.InstructionIterator instructions=currentProgram.getListing().getInstructions(function.getBody(),true);
                    while(instructions.hasNext()&&!monitor.isCancelled()){
                        ghidra.program.model.listing.Instruction instruction=instructions.next();
                        write(instruction.getAddress()+"  "+instruction.toString().replace("*/","* /")+"\n");
                    }
                    write("*/\n"); failed++;
                    println("UIE_EVENT "+json.toJson(row("kind","problem","file",source,"symbol",name,"line",firstLine,"message",result.getErrorMessage())));
                }
                Map<String,Object> record=row("name",name,"address",function.getEntryPoint().toString(),"rva",rva(function.getEntryPoint()),"line",firstLine,"group",user(function)?"user":initializer(function)?"constants":"other","success",good,"retried",retried,"error",good?"":result.getErrorMessage(),"fallback",good?"":"disassembly");
                functions.add(record);
                if (initializer(function)) {
                    List<Map<String,Object>> callers=new ArrayList<>(); ReferenceIterator incoming=refs.getReferencesTo(function.getEntryPoint());
                    while (incoming.hasNext()&&callers.size()<128) { Reference reference=incoming.next(); Function caller=getFunctionContaining(reference.getFromAddress()); callers.add(row("from",reference.getFromAddress().toString(),"caller",caller==null?"":caller.getSymbol().getName(true))); }
                    initializers.add(row("function",name,"address",function.getEntryPoint().toString(),"rva",rva(function.getEntryPoint()),"line",firstLine,"callers",callers));
                }
                processed++;
                println("UIE_EVENT "+json.toJson(row("kind","progress","phase","декомпиляция функций","file",source,"done",processed,"total",queue.size())));
            }
        } finally { decompiler.dispose(); }
        Map<String,Object> report=row("source_file",output.getFileName().toString(),"decompiled",success,"failed",failed,"filtered_runtime",skipped.size(),"skipped_functions",skipped,"functions",functions,"constant_initializers",initializers,"sections",sections,"high_entropy_sections",highEntropy,"constant_data_xrefs",references,"python_string_references",pythonStrings,"xrefs_truncated",limited,"entropy_threshold",ENTROPY_THRESHOLD,"interpretation","Entropy and XREFs identify candidate constant/data-processing sites. Nuitka Commercial and encryption are not proven by entropy alone.");
        Files.write(output.resolveSibling("native-report.json"),new GsonBuilder().setPrettyPrinting().create().toJson(report).getBytes(StandardCharsets.UTF_8));
        println("UIE native result: "+success+" functions, "+failed+" failures, "+skipped.size()+" runtime functions filtered");
    }
}
