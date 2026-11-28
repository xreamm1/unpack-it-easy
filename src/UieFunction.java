import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class UieFunction extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if((args.length!=2&&args.length!=3)||!args[1].matches("[0-9a-fA-F]{1,16}"))throw new IllegalArgumentException("Expected output and function address");
        Address entry=toAddr(args[1]);
        Function function=getFunctionAt(entry);
        if(function==null&&args.length==3){
            if(!args[2].matches("[0-9a-fA-F]{1,16}"))throw new IllegalArgumentException("Invalid function end");
            Address end=toAddr(args[2]);
            if(end.compareTo(entry)<=0)throw new IllegalArgumentException("Empty function range");
            AddressSet body=new AddressSet(entry,end.subtract(1));
            DisassembleCommand command=new DisassembleCommand(entry,body,true);
            command.enableCodeAnalysis(false);
            if(!command.applyTo(currentProgram,monitor))throw new IllegalStateException("Cannot decode selected function: "+command.getStatusMsg());
            function=currentProgram.getFunctionManager().createFunction("FUN_"+args[1],entry,body,SourceType.ANALYSIS);
        }
        if(function==null)throw new IllegalArgumentException("Function not in saved index");
        ghidra.program.model.mem.MemoryBlock block=currentProgram.getMemory().getBlock(function.getEntryPoint());
        if(block==null||!block.isInitialized())throw new IllegalStateException("Function bytes are not present in this file; unpacked image is required");
        AddressSet runtimeBody=args.length==3?new AddressSet(entry,toAddr(args[2]).subtract(1)):new AddressSet(function.getBody());
        int runtimeFixups=UieNativeRuntime.apply(currentProgram,runtimeBody);
        if(runtimeFixups>0)println("UIE verified MSVC runtime fixups: "+runtimeFixups);
        DecompInterface decompiler=new DecompInterface();
        try {
            if(!decompiler.openProgram(currentProgram))throw new IllegalStateException("Cannot open saved program");
            DecompileResults result=decompiler.decompileFunction(function,FUNCTION_TIMEOUT,monitor);
            if(!result.decompileCompleted()||result.getDecompiledFunction()==null)throw new IllegalStateException(result.getErrorMessage());
            if(result.getDecompiledFunction().getC().contains("halt_baddata()"))throw new IllegalStateException("Invalid instruction data; native source body was not recovered");
            Path output=Paths.get(args[0]);
            String text="/* Function at "+function.getEntryPoint()+": "+function.getName().replace("*/","* /")+" */\n"+result.getDecompiledFunction().getC();
            Files.writeString(output,text,StandardCharsets.UTF_8);
            boolean python=false;
            for(String library:currentProgram.getExternalManager().getExternalLibraryNames()) {
                if(library.toLowerCase(java.util.Locale.ROOT).matches("python3[0-9]*(?:t|_d)?\\.dll"))python=true;
            }
            if(python&&result.getHighFunction()!=null) {
                try { UiePythonIR.export(currentProgram,result.getHighFunction(),output.resolveSibling(output.getFileName()+".python-ir.json")); }
                catch(Exception error) { printerr("UIE semantic IR export: "+error.getMessage()); }
            }
        } finally {decompiler.dispose();}
    }
}
