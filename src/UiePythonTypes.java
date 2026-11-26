import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import com.google.gson.GsonBuilder;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Public CPython Windows C-API types, never a recovered Python source signature. */
public class UiePythonTypes extends HeadlessScript {
    private DataType objectPointer;
    private final CategoryPath category=new CategoryPath("/UIE/CPython312Win64");
    private DataType callable(String name,DataType result,DataType...args){
        FunctionDefinitionDataType function=new FunctionDefinitionDataType(category,name,currentProgram.getDataTypeManager());
        ParameterDefinition[] parameters=new ParameterDefinition[args.length];
        for(int i=0;i<args.length;i++)parameters[i]=new ParameterDefinitionImpl("arg"+(i+1),args[i],null);
        function.setArguments(parameters);function.setReturnType(result);
        return new PointerDataType(function,currentProgram.getDataTypeManager());
    }
    private void objectLayout(){
        if(currentProgram.getDefaultPointerSize()!=8)return;
        boolean supported=false;
        for(String library:currentProgram.getExternalManager().getExternalLibraryNames())if(library.equalsIgnoreCase("python312.dll"))supported=true;
        if(!supported)return;
        DataTypeManager manager=currentProgram.getDataTypeManager();
        StructureDataType object=new StructureDataType(category,"PyObject312",16,manager);
        StructureDataType type=new StructureDataType(category,"PyTypeObject312Prefix",176,manager);
        StructureDataType numbers=new StructureDataType(category,"PyNumberMethods312Prefix",152,manager);
        objectPointer=new PointerDataType(object,manager);
        DataType opaque=new PointerDataType(VoidDataType.dataType,manager);
        DataType string=new PointerDataType(CharDataType.dataType,manager);
        DataType unary=callable("unaryfunc",objectPointer,objectPointer);
        DataType binary=callable("binaryfunc",objectPointer,objectPointer,objectPointer);
        DataType ternary=callable("ternaryfunc",objectPointer,objectPointer,objectPointer,objectPointer);
        object.replaceAtOffset(0,LongLongDataType.dataType,8,"ob_refcnt",null);
        object.replaceAtOffset(8,new PointerDataType(type,manager),8,"ob_type",null);
        type.replaceAtOffset(0,object,16,"ob_base",null);
        type.replaceAtOffset(16,LongLongDataType.dataType,8,"ob_size",null);
        type.replaceAtOffset(24,string,8,"tp_name",null);
        type.replaceAtOffset(32,LongLongDataType.dataType,8,"tp_basicsize",null);
        type.replaceAtOffset(40,LongLongDataType.dataType,8,"tp_itemsize",null);
        type.replaceAtOffset(48,callable("destructor",VoidDataType.dataType,objectPointer),8,"tp_dealloc",null);
        type.replaceAtOffset(56,LongLongDataType.dataType,8,"tp_vectorcall_offset",null);
        type.replaceAtOffset(64,callable("getattrfunc",objectPointer,objectPointer,string),8,"tp_getattr",null);
        type.replaceAtOffset(72,callable("setattrfunc",IntegerDataType.dataType,objectPointer,string,objectPointer),8,"tp_setattr",null);
        type.replaceAtOffset(80,opaque,8,"tp_as_async",null);
        type.replaceAtOffset(88,unary,8,"tp_repr",null);
        type.replaceAtOffset(96,new PointerDataType(numbers,manager),8,"tp_as_number",null);
        type.replaceAtOffset(104,opaque,8,"tp_as_sequence",null);
        type.replaceAtOffset(112,opaque,8,"tp_as_mapping",null);
        type.replaceAtOffset(120,callable("hashfunc",LongLongDataType.dataType,objectPointer),8,"tp_hash",null);
        type.replaceAtOffset(128,ternary,8,"tp_call",null);
        type.replaceAtOffset(136,unary,8,"tp_str",null);
        type.replaceAtOffset(144,binary,8,"tp_getattro",null);
        type.replaceAtOffset(152,callable("setattrofunc",IntegerDataType.dataType,objectPointer,objectPointer,objectPointer),8,"tp_setattro",null);
        type.replaceAtOffset(160,opaque,8,"tp_as_buffer",null);
        type.replaceAtOffset(168,UnsignedIntegerDataType.dataType,4,"tp_flags",null);
        String[] slots={"nb_add","nb_subtract","nb_multiply","nb_remainder","nb_divmod","nb_power","nb_negative","nb_positive","nb_absolute","nb_bool","nb_invert","nb_lshift","nb_rshift","nb_and","nb_xor","nb_or","nb_int","nb_reserved","nb_float"};
        for(int i=0;i<slots.length;i++){
            DataType slot=i==17?opaque:i==5?ternary:i==9?callable("inquiry",IntegerDataType.dataType,objectPointer):(i>=6&&i<=10)||i==16||i==18?unary:binary;
            numbers.replaceAtOffset(i*8,slot,8,slots[i],null);
        }
        type.setDescription("Verified CPython 3.12 Windows x64 prefix only; fields after tp_flags are intentionally unspecified.");
        numbers.setDescription("Verified CPython 3.12 Windows x64 prefix through nb_float only.");
        objectPointer=new PointerDataType(manager.resolve(object,DataTypeConflictHandler.KEEP_HANDLER),manager);
    }
    private DataType type(char code){
        switch(code){
            case 'o':return objectPointer==null?new PointerDataType(VoidDataType.dataType):objectPointer;
            case 'a':return new PointerDataType(type('o'));
            case 'c':return new PointerDataType(CharDataType.dataType);
            case 's':return currentProgram.getDefaultPointerSize()==8?LongLongDataType.dataType:IntegerDataType.dataType;
            case 'u':return currentProgram.getDefaultPointerSize()==8?UnsignedLongLongDataType.dataType:UnsignedIntegerDataType.dataType;
            case 'i':return IntegerDataType.dataType;
            case 'd':return DoubleDataType.dataType;
            case 'v':return VoidDataType.dataType;
            default:throw new IllegalArgumentException("Unsupported C-API type");
        }
    }
    @Override public void run() throws Exception {
        objectLayout();
        Map<String,String> signatures=new LinkedHashMap<>();
        for(String name:Arrays.asList("PyObject_GetAttr","PyObject_GetItem","PyNumber_Add","PyNumber_Subtract","PyNumber_Multiply","PyNumber_TrueDivide","PyNumber_FloorDivide","PyNumber_Remainder","PyNumber_And","PyNumber_Or","PyNumber_Xor","PyNumber_Lshift","PyNumber_Rshift"))signatures.put(name,"ooo");
        for(String name:Arrays.asList("PyNumber_Long","PyNumber_Float","PyNumber_Index"))signatures.put(name,"oo");
        signatures.put("PyObject_GetAttrString","ooc");
        signatures.put("PyObject_SetAttr","iooo");
        signatures.put("PyObject_SetAttrString","ioco");
        signatures.put("PyObject_Call","oooo");
        signatures.put("PyObject_CallObject","ooo");
        signatures.put("PyObject_Vectorcall","ooauo");
        signatures.put("PyObject_VectorcallMethod","ooauo");
        signatures.put("PyObject_RichCompare","oooi");
        signatures.put("PyObject_RichCompareBool","iooi");
        signatures.put("PyObject_IsTrue","io");
        signatures.put("PyObject_Hash","so");
        signatures.put("PyBytes_FromStringAndSize","ocs");
        signatures.put("PyUnicode_FromStringAndSize","ocs");
        signatures.put("PyUnicode_FromString","oc");
        signatures.put("PyUnicode_InternFromString","oc");
        signatures.put("PyUnicode_Decode","ocscc");
        signatures.put("PyUnicode_DecodeUTF8","ocsc");
        signatures.put("PyFloat_FromDouble","od");
        signatures.put("PyFloat_AsDouble","do");
        signatures.put("PyLong_FromLong","oi");
        signatures.put("PyLong_FromSsize_t","os");
        signatures.put("PyList_New","os");
        signatures.put("PyTuple_New","os");
        signatures.put("PyList_GetItem","oos");
        signatures.put("PyTuple_GetItem","oos");
        signatures.put("PyList_SetItem","ioso");
        signatures.put("PyTuple_SetItem","ioso");
        signatures.put("PyList_Append","ioo");
        signatures.put("PyCode_NewEmpty","occi");
        signatures.put("PyFrame_New","ooooo");
        signatures.put("PyTraceBack_Here","io");
        signatures.put("PyErr_Occurred","o");
        signatures.put("PyErr_Clear","v");
        signatures.put("PyErr_SetString","voc");
        signatures.put("PyErr_SetObject","voo");
        signatures.put("Py_IncRef","vo");
        signatures.put("Py_DecRef","vo");
        List<Map<String,Object>> applied=new ArrayList<>();
        for(String library:currentProgram.getExternalManager().getExternalLibraryNames()){
            if(!library.toLowerCase(Locale.ROOT).matches("python3[0-9]*(?:t|_d)?\\.dll"))continue;
            ExternalLocationIterator locations=currentProgram.getExternalManager().getExternalLocations(library);
            while(locations.hasNext()&&!monitor.isCancelled()){
                ExternalLocation location=locations.next();
                String signature=signatures.get(location.getLabel());
                if(signature==null)continue;
                Function function=location.getFunction();if(function==null)function=location.createFunction();
                if(function==null||function.getSignatureSource()==SourceType.USER_DEFINED)continue;
                List<ParameterImpl> parameters=new ArrayList<>();
                for(int index=1;index<signature.length();index++)parameters.add(new ParameterImpl("arg"+index,type(signature.charAt(index)),currentProgram));
                function.updateFunction(null,new ReturnParameterImpl(type(signature.charAt(0)),currentProgram),parameters,Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.ANALYSIS);
                function.setVarArgs(false);
                Map<String,Object> row=new LinkedHashMap<>();row.put("name",location.getLabel());row.put("library",library);row.put("parameters",parameters.size());row.put("signature",function.getPrototypeString(false,false));applied.add(row);
            }
        }
        Map<String,Object> report=new LinkedHashMap<>();report.put("applied",applied);report.put("object_layout",objectPointer==null?"opaque objects":"CPython 3.12 Windows x64 verified PyObject, PyTypeObject prefix, PyNumberMethods prefix");report.put("interpretation","Public CPython Windows C-API prototypes checked against installed Python headers; not recovered Python source signatures. User-defined function types are preserved.");
        if(getScriptArgs().length>0)Files.writeString(Paths.get(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(report),StandardCharsets.UTF_8);
        println("UIE CPython API signatures: "+applied.size());
    }
}
