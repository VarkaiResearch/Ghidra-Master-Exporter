// VarkaiMasterExporter.java
// @category VarkaiResearch
// @description Read-only Ghidra static analysis, indexed memory, and focused blob export.
// Copyright (c) 2026 Varkai Research. Provided as-is for defensive reverse engineering.
//
// Run with a PROGRAM open in Ghidra CodeBrowser (Script Manager).
// NEVER executes the program being analyzed. Does not write to the Ghidra program.
// Results reflect Ghidra's in-memory representation, NOT necessarily original file bytes.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

public class VarkaiMasterExporter extends GhidraScript {

    private static final String VERSION = "2.0.0-beta.1";
    private static final int HEX_ROW_BYTES = 64;
    private static final int BLOB_CHUNK_BYTES = 65536;
    private static final int MAX_FOCUSED_BYTES = 128 * 1024 * 1024; // 128 MiB
    private static final int DECOMPILE_TIMEOUT_SECONDS = 90;
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private static final String MODE_COMPLETE = "Complete: static analysis + raw memory";
    private static final String MODE_COMPLETE_BLOB = "Complete + focused binary region";
    private static final String MODE_STATIC = "Static analysis only";
    private static final String MODE_MEMORY = "All initialized memory only";
    private static final String MODE_FOCUSED = "Focused region(s): hex CSV + binary";

    // Scores are triage hints, not probabilities of malware or verified capabilities.
    private static final class Feature {
        String name;
        String entry;
        long bodyBytes;
        long instructions;
        long branches;
        long calls;
        long indirectFlows;
        long trapInstructions;
        long gsAccesses;
        long syscalls;
        long inboundCalls;
        long outboundCalls;
        long apiHits;
        StringBuilder evidence = new StringBuilder();
        Set<String> tags = new HashSet<String>();
        MessageDigest codeHash;
        Feature(String n, String e, long b) throws Exception {
            name=n; entry=e; bodyBytes=b;
            codeHash=MessageDigest.getInstance("SHA-256");
        }
        void record(String address, String rule, String observed) {
            if (evidence.length() < 3200) {
                if (evidence.length()>0) evidence.append(" ; ");
                evidence.append(address).append(":").append(rule).append("=").append(observed);
            }
        }
        int score() {
            // Bounded weights keep a single long obfuscated routine from dominating solely by size.
            return Math.min(18, (int) indirectFlows * 3)
                + Math.min(12, (int) trapInstructions * 2)
                + Math.min(12, (int) gsAccesses * 4)
                + Math.min(15, (int) syscalls * 5)
                + Math.min(24, (int) apiHits * 3)
                + Math.min(12, (int) Math.max(0, inboundCalls - 3))
                + (instructions > 2500 ? 3 : 0);
        }
        String tags() {
            List<String> ordered = new ArrayList<String>(tags);
            java.util.Collections.sort(ordered);
            return String.join("|", ordered);
        }
        String digest() { return hex(codeHash.digest(), 32).toLowerCase(); }
    }
    private final Map<String, Feature> features = new LinkedHashMap<String, Feature>();
    private final AddressSet decodedInstructionBytes = new AddressSet();
    private long outsideFunctionInstructions;
    private long undecodedExecutableBytes;
    private long observedCallEdges;
    private long indicatorMatches;

    private static final String[][] API_RULES = {
        {"ntqueryinformationprocess", "process_query"},
        {"zwqueryinformationprocess", "process_query"},
        {"isdebuggerpresent", "debugger_check_api"},
        {"checkremotedebuggerpresent", "debugger_check_api"},
        {"ntsetinformationthread", "thread_information"},
        {"virtualalloc", "memory_allocation"},
        {"virtualprotect", "memory_protection"},
        {"writeprocessmemory", "cross_process_memory_write"},
        {"createremotethread", "remote_thread_api"},
        {"ntqueueapcthread", "apc_api"},
        {"queueuserapc", "apc_api"},
        {"regsetvalue", "registry_write_api"},
        {"regcreatekey", "registry_write_api"},
        {"winhttp", "winhttp_api"},
        {"internetconnect", "wininet_api"},
        {"httpsendrequest", "http_api"},
        {"cryptunprotectdata", "dpapi_decrypt_api"},
        {"bcryptdecrypt", "crypto_api"}
    };

    private static final class FocusedRange {
        Address start;
        int length;
        FocusedRange(Address a, int n) { start=a; length=n; }
    }


    private File exportDirectory;
    private int decompileAttempted;
    private int decompileSucceeded;
    private long instructionsExported;
    private long referencesExported;
    private long memoryBytesExported;
    private long memoryReadErrors;

    private static String csv(Object input) {
        String value = input == null ? "" : input.toString();
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static String hex(byte[] data, int length) {
        char[] chars = new char[length * 2];
        for (int i = 0; i < length; i++) {
            int b = data[i] & 255;
            chars[i * 2] = HEX[b >>> 4];
            chars[i * 2 + 1] = HEX[b & 15];
        }
        return new String(chars);
    }

    private static String shortName(String value) {
        String result = value.replaceAll("[^a-zA-Z0-9._-]", "_");
        if (result.length() > 90) result = result.substring(0, 90);
        return result.isEmpty() ? "untitled" : result;
    }

    private BufferedWriter writer(String filename) throws IOException {
        return Files.newBufferedWriter(new File(exportDirectory, filename).toPath(), StandardCharsets.UTF_8);
    }

    private static void csvLine(BufferedWriter out, Object... fields) throws IOException {
        for (int i = 0; i < fields.length; i++) {
            if (i != 0) out.write(',');
            out.write(csv(fields[i]));
        }
        out.newLine();
    }

    private File createUniqueFolder(File parent) throws IOException {
        Files.createDirectories(parent.toPath());
        String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String base = shortName(currentProgram.getName()) + "_Varkai_" + stamp;
        File candidate = new File(parent, base);
        int n = 2;
        while (candidate.exists()) candidate = new File(parent, base + "_" + (n++));
        Files.createDirectory(candidate.toPath());
        return candidate;
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open a Ghidra program before running this script.");
            return;
        }

        String mode = askChoice("Varkai Master Exporter", "Select export profile",
            Arrays.asList(MODE_COMPLETE, MODE_COMPLETE_BLOB, MODE_STATIC, MODE_MEMORY, MODE_FOCUSED),
            MODE_COMPLETE);

        boolean doStatic = MODE_COMPLETE.equals(mode) || MODE_COMPLETE_BLOB.equals(mode) || MODE_STATIC.equals(mode);
        boolean doFullMemory = MODE_COMPLETE.equals(mode) || MODE_COMPLETE_BLOB.equals(mode) || MODE_MEMORY.equals(mode);
        boolean doFocused = MODE_COMPLETE_BLOB.equals(mode) || MODE_FOCUSED.equals(mode);

        List<FocusedRange> focus = new ArrayList<FocusedRange>();
        if (doFocused) {
            String input = askString("Focused memory ranges",
                "Enter address:length;address:length (length decimal; e.g. 140384B70:64;1400FFA5A:128)");
            for (String item : input.split(";")) {
                item = item.trim();
                if (item.isEmpty()) continue;
                int separator = item.lastIndexOf(':');
                if (separator < 1) throw new IllegalArgumentException("Bad range: " + item);
                String a = item.substring(0, separator).trim().replaceFirst("(?i)^0x", "");
                Address addr = currentProgram.getAddressFactory().getAddress(a);
                if (addr == null) throw new IllegalArgumentException("Invalid address: " + a);
                int length = Integer.parseInt(item.substring(separator + 1).trim());
                if (length < 1 || length > MAX_FOCUSED_BYTES)
                    throw new IllegalArgumentException("Focused length must be 1-" + MAX_FOCUSED_BYTES);
                addr.addNoWrap((long)length-1);
                focus.add(new FocusedRange(addr, length));
            }
            if (focus.isEmpty()) throw new IllegalArgumentException("No focused ranges entered.");
        }

        File parent = askDirectory("Choose parent directory for Varkai export", "Export");
        if (parent == null) return;
        exportDirectory = createUniqueFolder(parent);
        File incompleteMarker = new File(exportDirectory, "EXPORT_INCOMPLETE.txt");
        Files.write(incompleteMarker.toPath(), Arrays.asList(
            "This export is INCOMPLETE until this marker is removed.",
            "If Ghidra or this script was interrupted, treat every output as partial."),
            StandardCharsets.UTF_8);

        println("Varkai export: " + currentProgram.getName());
        println("Output: " + exportDirectory.getAbsolutePath());
        boolean ok = false;
        try {
            exportMetadata(mode);
            exportBlockMap();
            if (doStatic) {
                exportStaticAnalysis();
                exportTriage();
            }
            if (doFullMemory) exportMemoryBytes();
            if (doFocused) for (FocusedRange range : focus)
                exportFocusedRange(range.start, range.length);
            exportSummary(mode);
            exportManifest(mode);
            ok = true;
        } finally {
            if (ok) Files.deleteIfExists(incompleteMarker.toPath());
            if (!ok) printerr("Export incomplete. Check " + incompleteMarker.getAbsolutePath());
        }
        println("VARKAI MASTER EXPORT COMPLETE: " + exportDirectory.getAbsolutePath());
    }

    private void exportMetadata(String mode) throws IOException {
        try (BufferedWriter out = writer("program_metadata.txt")) {
            out.write("Varkai Master Exporter version: " + VERSION + "\n");
            out.write("Export timestamp (local): " + new Date() + "\n");
            out.write("Export mode: " + mode + "\n");
            out.write("Program name: " + currentProgram.getName() + "\n");
            out.write("Language: " + currentProgram.getLanguage().getLanguageID() + "\n");
            out.write("CompilerSpec: " + currentProgram.getCompilerSpec().getCompilerSpecID() + "\n");
            out.write("Image base: " + currentProgram.getImageBase() + "\n");
            out.write("Minimum address: " + currentProgram.getMinAddress() + "\n");
            out.write("Maximum address: " + currentProgram.getMaxAddress() + "\n");
            out.write("Function count (includes externals): " + currentProgram.getFunctionManager().getFunctionCount() + "\n");
            out.write("Executable SHA-256 (Ghidra loader metadata; may be unavailable): " +
                currentProgram.getExecutableSHA256() + "\n");
            out.write("Executable format: " + currentProgram.getExecutableFormat() + "\n");
            out.write("Original executable path: intentionally omitted for analyst privacy\n");
            out.write("WARNING: static analysis only; no target executable was run.\n");
            out.write("WARNING: exported memory is Ghidra's program memory, possibly relocated/patched.\n");
            out.write("WARNING: a hash of an exported region is NOT the hash of the original executable.\n");
        }
    }

    private void exportBlockMap() throws Exception {
        Memory memory = currentProgram.getMemory();
        AddressSetView initialized = memory.getAllInitializedAddressSet();
        try (BufferedWriter out = writer("memory_blocks.csv")) {
            out.write("block,start,end,size,read,write,execute,initialized,mapped,loaded,type,source,initialized_address_count\n");
            for (MemoryBlock block : memory.getBlocks()) {
                monitor.checkCancelled();
                AddressSet intersected = new AddressSet(block.getStart(), block.getEnd());
                long initializedCount = intersected.intersect(initialized).getNumAddresses();
                csvLine(out, block.getName(), block.getStart(), block.getEnd(), block.getSize(),
                    block.isRead(), block.isWrite(), block.isExecute(), block.isInitialized(),
                    block.isMapped(), block.isLoaded(), block.getType(), block.getSourceName(),
                    initializedCount);
            }
        }
    }

    private void exportStaticAnalysis() throws Exception {
        Listing listing = currentProgram.getListing();
        SymbolTable symbols = currentProgram.getSymbolTable();
        FunctionManager functions = currentProgram.getFunctionManager();
        println("[1/5] Exporting symbols ...");
        try (BufferedWriter out = writer("all_symbols.csv")) {
            out.write("address,name,kind,source,is_primary,is_external\n");
            SymbolIterator si = symbols.getAllSymbols(true);
            while (si.hasNext()) {
                monitor.checkCancelled();
                Symbol s = si.next();
                csvLine(out, s.getAddress(), s.getName(), s.getSymbolType(),
                    s.getSource(), s.isPrimary(), s.isExternal());
            }
        }

        println("[2/5] Exporting defined strings ...");
        try (BufferedWriter out = writer("defined_strings.csv")) {
            out.write("address,data_type,value\n");
            DataIterator iterator = listing.getDefinedData(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Data data = iterator.next();
                try {
                    Object value = data.getValue();
                    if (value instanceof String) csvLine(out, data.getAddress(), data.getDataType().getName(), value);
                } catch (Exception ignored) {
                    // Some Ghidra data values cannot be rendered as strings.
                }
            }
        }

        println("[3/5] Exporting annotations ...");
        final int[] commentKinds = {
            CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT,
            CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT
        };
        final String[] commentNames = {"EOL", "PRE", "POST", "PLATE", "REPEATABLE"};
        try (BufferedWriter out = writer("all_code_comments.csv")) {
            out.write("address,comment_type,comment\n");
            CodeUnitIterator iterator = listing.getCodeUnits(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                CodeUnit codeUnit = iterator.next();
                for (int i = 0; i < commentKinds.length; i++) {
                    String comment = codeUnit.getComment(commentKinds[i]);
                    if (comment != null && !comment.isEmpty()) {
                        csvLine(out, codeUnit.getAddress(), commentNames[i], comment);
                    }
                }
            }
        }

        println("[4/5] Exporting function index and decompiled C ...");
        Files.createDirectories(new File(exportDirectory, "decompiled_functions").toPath());
        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        try (BufferedWriter index = writer("functions.csv");
             BufferedWriter code = writer("ALL_FUNCTIONS_DECOMPILED.c");
             BufferedWriter errors = writer("decompile_errors.csv")) {
            index.write("name,entry,signature,is_thunk,is_external,body_bytes\n");
            errors.write("name,entry,error_message\n");
            if (!decomp.openProgram(currentProgram)) {
                throw new IOException("Cannot open Ghidra decompiler: " + decomp.getLastMessage());
            }
            // FunctionManager.getFunctions() intentionally excludes external functions.
            // Export non-external and external indexes separately to avoid the old count mismatch.
            FunctionIterator fi = functions.getFunctions(true);
            while (fi.hasNext()) {
                monitor.checkCancelled();
                Function function = fi.next();
                csvLine(index, function.getName(), function.getEntryPoint(),
                    function.getSignature(), function.isThunk(), function.isExternal(),
                    function.getBody().getNumAddresses());
                features.put(function.getEntryPoint().toString(),
                    new Feature(function.getName(), function.getEntryPoint().toString(),
                        function.getBody().getNumAddresses()));
                code.write("\n/* ===== " + function.getName() + " at " + function.getEntryPoint() + " ===== */\n");
                if (function.isExternal()) continue;
                decompileAttempted++;
                try {
                    DecompileResults result = decomp.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
                    if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        String decompiled = result.getDecompiledFunction().getC();
                        code.write(decompiled);
                        code.write("\n");
                        // One file per function enables targeted review and source-control diffs.
                        Path perFunction = new File(new File(exportDirectory, "decompiled_functions"),
                            shortName(function.getEntryPoint().toString()) + ".c").toPath();
                        Files.write(perFunction, decompiled.getBytes(StandardCharsets.UTF_8));
                        decompileSucceeded++;
                    } else {
                        String message = result == null ? "Null result" : result.getErrorMessage();
                        csvLine(errors, function.getName(), function.getEntryPoint(), message);
                        code.write("/* DECOMPILATION FAILED: " + message + " */\n");
                    }
                } catch (Exception e) {
                    monitor.checkCancelled();
                    csvLine(errors, function.getName(), function.getEntryPoint(), e.toString());
                    code.write("/* DECOMPILATION EXCEPTION: " + e + " */\n");
                }
                if (decompileAttempted % 25 == 0) {
                    println("Decompiler: " + decompileSucceeded + "/" + decompileAttempted + " succeeded");
                    code.flush();
                }
            }
            FunctionIterator externals = functions.getExternalFunctions();
            while (externals.hasNext()) {
                monitor.checkCancelled();
                Function external = externals.next();
                csvLine(index, external.getName(), external.getEntryPoint(),
                    external.getSignature(), external.isThunk(), true, 0);
                code.write("\n/* EXTERNAL FUNCTION: " + external.getName() +
                    " at " + external.getEntryPoint() + " */\n");
            }
        } finally {
            decomp.dispose();
        }

        println("[5/5] Exporting ALL indexed instructions and ALL source references ...");
        try (BufferedWriter disasm = writer("all_disassembly.csv");
             BufferedWriter refs = writer("all_code_references.csv");
             BufferedWriter edges = writer("call_edges.csv");
             BufferedWriter hits = writer("indicator_evidence.csv")) {
            // Leading columns stay compatible with the older exporter.
            disasm.write("function,virtual_address,instruction,machine_bytes,mnemonic,outside_function\n");
            refs.write("function,from,to,reference_type,external_target_name,operand_index,source_kind\n");
            edges.write("caller_entry,caller_name,site_address,target_address,callee_entry,callee_name,reference_type,warning\n");
            hits.write("function_entry,function_name,instruction_address,signal,observed_text,confidence\n");

            InstructionIterator ii = listing.getInstructions(true);
            while (ii.hasNext()) {
                monitor.checkCancelled();
                Instruction insn = ii.next();
                Function owner = functions.getFunctionContaining(insn.getAddress());
                String functionName = owner == null ? "" : owner.getName();
                String bytes;
                try {
                    byte[] raw = insn.getBytes();
                    bytes = hex(raw, raw.length);
                } catch (MemoryAccessException err) {
                    bytes = "UNREADABLE: " + err.getMessage();
                }
                csvLine(disasm, functionName, insn.getAddress(), insn.toString(),
                    bytes, insn.getMnemonicString(), owner == null);
                decodedInstructionBytes.add(insn.getMinAddress(), insn.getMaxAddress());
                if (owner == null) outsideFunctionInstructions++;
                Feature ft = owner == null ? null : features.get(owner.getEntryPoint().toString());
                if (ft != null) {
                    ft.instructions++;
                    ft.codeHash.update((insn.getAddress().toString() + "|" + bytes + "\n").getBytes(StandardCharsets.UTF_8));
                    String mnemonic = insn.getMnemonicString().toUpperCase(java.util.Locale.ROOT);
                    String statement = insn.toString().toUpperCase(java.util.Locale.ROOT);
                    if (insn.getFlowType().isJump()) ft.branches++;
                    if (insn.getFlowType().isCall()) ft.calls++;
                    if (insn.getFlowType().isComputed()) {
                        ft.indirectFlows++;
                        ft.record(insn.getAddress().toString(), "indirect_flow", mnemonic);
                        csvLine(hits, ft.entry, ft.name, insn.getAddress(), "indirect_flow", insn.toString(), "observed");
                        indicatorMatches++;
                    }
                    if (mnemonic.equals("UD2") || mnemonic.equals("INT3") || mnemonic.equals("HLT")) {
                        ft.trapInstructions++;
                        ft.record(insn.getAddress().toString(), "trap_opcode", mnemonic);
                        csvLine(hits, ft.entry, ft.name, insn.getAddress(), "trap_opcode", mnemonic, "observed");
                        indicatorMatches++;
                    }
                    if (statement.contains("GS:[") || statement.contains("GS:")) {
                        ft.gsAccesses++;
                        ft.record(insn.getAddress().toString(), "gs_segment", statement);
                        csvLine(hits, ft.entry, ft.name, insn.getAddress(), "gs_segment", insn.toString(), "observed");
                        indicatorMatches++;
                    }
                    if (mnemonic.equals("SYSCALL") || mnemonic.equals("SYSENTER")) {
                        ft.syscalls++;
                        ft.record(insn.getAddress().toString(), "syscall_opcode", mnemonic);
                        csvLine(hits, ft.entry, ft.name, insn.getAddress(), "syscall_opcode", mnemonic, "observed");
                        indicatorMatches++;
                    }
                }
                instructionsExported++;
            }

            // This includes references FROM code and defined data, even outside functions.
            ReferenceManager manager = currentProgram.getReferenceManager();
            AddressIterator fromIterator = manager.getReferenceSourceIterator((AddressSetView) null, true);
            while (fromIterator.hasNext()) {
                monitor.checkCancelled();
                Address from = fromIterator.next();
                Function owner = functions.getFunctionContaining(from);
                CodeUnit unit = listing.getCodeUnitContaining(from);
                String kind = unit instanceof Instruction ? "instruction" :
                    unit instanceof Data ? "data" : "unknown";
                for (Reference ref : manager.getReferencesFrom(from)) {
                    Address destination = ref.getToAddress();
                    Symbol target = symbols.getPrimarySymbol(destination);
                    csvLine(refs, owner == null ? "" : owner.getName(), ref.getFromAddress(),
                        destination, ref.getReferenceType(), target == null ? "" : target.getName(),
                        ref.getOperandIndex(), kind);
                    referencesExported++;
                    if (ref.getReferenceType().isCall()) {
                        Function callee = functions.getFunctionAt(destination);
                        if (callee == null) callee = functions.getFunctionContaining(destination);
                        Feature source = owner == null ? null : features.get(owner.getEntryPoint().toString());
                        Feature dest = callee == null ? null : features.get(callee.getEntryPoint().toString());
                        if (source != null) source.outboundCalls++;
                        if (dest != null) dest.inboundCalls++;
                        String warning = callee == null ? "unresolved destination" :
                            (!callee.getEntryPoint().equals(destination) ? "call target inside function" : "");
                        csvLine(edges, owner == null ? "" : owner.getEntryPoint(),
                            owner == null ? "" : owner.getName(), from, destination,
                            callee == null ? "" : callee.getEntryPoint(),
                            callee == null ? "" : callee.getName(), ref.getReferenceType(), warning);
                        observedCallEdges++;
                        if (source != null) {
                            String targetName = (target == null ? "" : target.getName()).toLowerCase(java.util.Locale.ROOT);
                            if (callee != null) targetName += " " + callee.getName().toLowerCase(java.util.Locale.ROOT);
                            for (String[] rule : API_RULES) {
                                if (targetName.contains(rule[0])) {
                                    source.apiHits++;
                                    source.tags.add(rule[1]);
                                    source.record(from.toString(), rule[1], targetName.trim());
                                    csvLine(hits, source.entry, source.name, from,
                                        rule[1], targetName.trim(), "name_match_only");
                                    indicatorMatches++;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private void exportMemoryBytes() throws Exception {
        println("Exporting address-indexed initialized memory bytes ...");
        Memory memory = currentProgram.getMemory();
        AddressSetView initialized = memory.getAllInitializedAddressSet();
        byte[] buffer = new byte[HEX_ROW_BYTES];
        try (BufferedWriter bytes = writer("memory_bytes.csv");
             BufferedWriter errors = writer("read_errors.csv")) {
            bytes.write("block_name,virtual_address,byte_count,hex_bytes\n");
            errors.write("block_name,virtual_address,requested_bytes,error\n");
            for (MemoryBlock block : memory.getBlocks()) {
                monitor.checkCancelled();
                AddressSet blockSet = new AddressSet(block.getStart(), block.getEnd());
                AddressSetView readable = blockSet.intersect(initialized);
                AddressRangeIterator ranges = readable.getAddressRanges(true);
                while (ranges.hasNext()) {
                    AddressRange range = ranges.next();
                    long rangeLength = range.getLength();
                    long offset = 0;
                    while (offset < rangeLength) {
                        monitor.checkCancelled();
                        Address pos = range.getMinAddress().addNoWrap(offset);
                        int n = (int) Math.min((long) HEX_ROW_BYTES, rangeLength - offset);
                        int got;
                        try {
                            got = memory.getBytes(pos, buffer, 0, n);
                        } catch (MemoryAccessException e) {
                            got = 0;
                        }
                        if (got <= 0) {
                            memoryReadErrors++;
                            csvLine(errors, block.getName(), pos, n, "Memory read failed");
                            // Skip exactly this row; the error log identifies the missing span.
                            offset += n;
                            continue;
                        }
                        csvLine(bytes, block.getName(), pos, got, hex(buffer, got));
                        memoryBytesExported += got;
                        offset += got;
                    }
                }
            }
        }
    }

    private void exportFocusedRange(Address start, int byteCount) throws Exception {
        Memory memory = currentProgram.getMemory();
        Address end = start.addNoWrap((long) byteCount - 1);
        if (!memory.getAllInitializedAddressSet().contains(start, end)) {
            throw new IOException("Focused range " + start + " through " + end +
                " is not fully initialized. No binary will be written. " +
                "Choose an initialized range or use full-memory export to inspect gaps.");
        }

        String baseName = "focused_" + shortName(start.toString()) + "_" + byteCount;
        Path temporary = new File(exportDirectory, baseName + ".bin.part").toPath();
        Path destination = new File(exportDirectory, baseName + ".bin").toPath();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[BLOB_CHUNK_BYTES];
        long done = 0;

        println("Exporting focused binary: " + start + " + " + byteCount + " bytes");
        try (OutputStream raw = new BufferedOutputStream(new FileOutputStream(temporary.toFile()));
             BufferedWriter hexRows = writer(baseName + "_memory_bytes.csv")) {
            hexRows.write("block_name,virtual_address,byte_count,hex_bytes\n");
            while (done < byteCount) {
                monitor.checkCancelled();
                Address position = start.addNoWrap(done);
                MemoryBlock block = memory.getBlock(position);
                if (block == null) throw new IOException("Unmapped address: " + position);
                long blockRemaining = block.getEnd().subtract(position) + 1;
                int requested = (int) Math.min((long) BLOB_CHUNK_BYTES,
                    Math.min((long) byteCount - done, blockRemaining));
                int read = memory.getBytes(position, buffer, 0, requested);
                if (read != requested) {
                    throw new IOException("Short read at " + position + ": " + read + "/" + requested);
                }
                raw.write(buffer, 0, read);
                sha.update(buffer, 0, read);
                for (int off = 0; off < read; off += HEX_ROW_BYTES) {
                    int length = Math.min(HEX_ROW_BYTES, read - off);
                    byte[] row = Arrays.copyOfRange(buffer, off, off + length);
                    csvLine(hexRows, block.getName(), position.addNoWrap(off), length, hex(row, length));
                }
                done += read;
            }
        } finally {
            if (done != byteCount) Files.deleteIfExists(temporary);
        }
        Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING);
        try (BufferedWriter manifest = writer(baseName + "_manifest.txt")) {
            manifest.write("Program: " + currentProgram.getName() + "\n");
            manifest.write("Start virtual address: " + start + "\n");
            manifest.write("End virtual address: " + end + "\n");
            manifest.write("Byte count: " + done + "\n");
            manifest.write("SHA-256 of extracted region: " + hex(sha.digest(), 32).toLowerCase() + "\n");
            manifest.write("Binary filename: " + destination.getFileName() + "\n");
            manifest.write("WARNING: untrusted static program bytes; never execute extracted .bin data.\n");
        }
        println("Focused binary saved: " + destination);
    }

    private void exportSummary(String mode) throws IOException {
        try (BufferedWriter out = writer("export_summary.txt")) {
            out.write("Varkai Master Exporter completed successfully\n");
            out.write("Mode: " + mode + "\n");
            out.write("Program: " + currentProgram.getName() + "\n");
            out.write("Functions decompiled: " + decompileSucceeded + " / " + decompileAttempted + " attempted\n");
            out.write("Indexed instructions: " + instructionsExported + "\n");
            out.write("References (all sources): " + referencesExported + "\n");
            out.write("Initialized memory bytes exported: " + memoryBytesExported + "\n");
            out.write("Memory read errors: " + memoryReadErrors + "\n");
            out.write("Call references (not guaranteed executed): " + observedCallEdges + "\n");
            out.write("Decoded instructions outside recognized functions: " + outsideFunctionInstructions + "\n");
            out.write("Initialized executable bytes without decoded instructions: " + undecodedExecutableBytes + "\n");
            out.write("Recorded heuristic indicators: " + indicatorMatches + "\n");
            out.write("Note: the full raw memory CSV may contain reconstructable malicious code.\n");
            out.write("Note: memory dump reflects Ghidra imported/possibly patched bytes.\n");
        }
    }

    private void exportTriage() throws Exception {
        println("Generating reproducible function triage, evidence and code-coverage gaps ...");
        List<Feature> ranked = new ArrayList<Feature>(features.values());
        ranked.sort(Comparator.comparingInt(Feature::score).reversed().thenComparing(x -> x.entry));
        try (BufferedWriter out = writer("function_features.csv")) {
            out.write("entry,name,score,body_bytes,instructions,branches,calls,indirect_flows,trap_opcodes,gs_accesses,syscall_opcodes,incoming_call_refs,outgoing_call_refs,named_api_hits,api_tags,instruction_fingerprint_sha256,evidence_samples\n");
            for (Feature f : ranked) {
                monitor.checkCancelled();
                csvLine(out, f.entry, f.name, f.score(), f.bodyBytes, f.instructions, f.branches,
                    f.calls, f.indirectFlows, f.trapInstructions, f.gsAccesses, f.syscalls,
                    f.inboundCalls, f.outboundCalls, f.apiHits, f.tags(), f.digest(), f.evidence);
            }
        }
        Memory memory = currentProgram.getMemory();
        AddressSet executable = memory.getExecuteSet().intersect(memory.getLoadedAndInitializedAddressSet());
        AddressSet unclassified = executable.subtract(decodedInstructionBytes);
        try (BufferedWriter out = writer("undecoded_executable_ranges.csv")) {
            out.write("start,end,byte_count,block_name,note\n");
            AddressRangeIterator it = unclassified.getAddressRanges(true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                AddressRange r = it.next();
                long count = r.getLength();
                undecodedExecutableBytes += count;
                MemoryBlock block = memory.getBlock(r.getMinAddress());
                csvLine(out, r.getMinAddress(), r.getMaxAddress(), count,
                    block == null ? "" : block.getName(),
                    "Ghidra has not decoded these executable bytes; may be padding, data, or unrecognized code");
            }
        }
        try (BufferedWriter report = writer("TRIAGE_REPORT.md")) {
            report.write("# Varkai Master Exporter — hypothesis queue\n\n");
            report.write("Program: `" + currentProgram.getName().replace("`", "") + "`\n\n");
            report.write("**This is heuristic triage, NOT a malware verdict or proof of execution.** Scores are deterministic weights on observed static patterns.\n\n");
            report.write("| Rank | Entry | Function | Score | Indirect | Traps | GS | Syscalls | Named API hits |\n");
            report.write("|---:|---|---|---:|---:|---:|---:|---:|---:|\n");
            int limit = Math.min(ranked.size(), 40);
            for (int i=0; i<limit; i++) {
                Feature f = ranked.get(i);
                report.write("| " + (i+1) + " | `" + f.entry + "` | `" + f.name.replace("|","_") + "` | " +
                    f.score() + " | " + f.indirectFlows + " | " + f.trapInstructions + " | " +
                    f.gsAccesses + " | " + f.syscalls + " | " + f.apiHits + " |\n");
            }
            report.write("\n## Evidence sources\n\n- `function_features.csv`: feature counts and sampled addresses.\n- `indicator_evidence.csv`: individual opcode/API-name observation records.\n- `call_edges.csv`: Ghidra's recorded call references, NOT a runtime call graph.\n- `undecoded_executable_ranges.csv`: executable bytes without decoded instructions (includes padding/data).\n- `decompiled_functions/`: one C file per decompiled function.\n\n");
            report.write("## Interpretation safeguards\n\n");
            report.write("- API matches reflect names at referenced targets only; indirect calls may be unresolved.\n");
            report.write("- `GS` segment access, `UD2`, and computed branches are individually ambiguous.\n");
            report.write("- References can be misleading under obfuscation and need control-flow verification.\n");
            report.write("- File names and decompilation are derived from Ghidra's current analysis state.\n");
        }
    }

    private static String jsonString(String input) {
        if (input == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i=0;i<input.length();i++) {
            char c = input.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    private static String sha256File(Path file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (FileInputStream in = new FileInputStream(file.toFile())) {
            byte[] buf = new byte[65536];
            int count;
            while ((count = in.read(buf)) != -1) md.update(buf, 0, count);
        }
        return hex(md.digest(),32).toLowerCase();
    }

    private void exportManifest(String mode) throws Exception {
        println("Hashing all exported artifacts for integrity manifest ...");
        List<Path> entries = new ArrayList<Path>();
        Path base = exportDirectory.toPath();
        try (java.util.stream.Stream<Path> paths = Files.walk(base)) {
            paths.filter(Files::isRegularFile).forEach(entries::add);
        }
        entries.sort(Comparator.comparing(p -> base.relativize(p).toString()));
        try (BufferedWriter out = writer("manifest.json")) {
            out.write("{\n  \"schema_version\": \"1\",\n  \"tool_version\": " + jsonString(VERSION) + ",\n");
            out.write("  \"source_program\": " + jsonString(currentProgram.getName()) + ",\n");
            out.write("  \"mode\": " + jsonString(mode) + ",\n  \"integrity\": \"SHA-256\",\n");
            out.write("  \"complete_only_when_marker_absent\": true,\n  \"artifacts\": [\n");
            boolean first=true;
            for (Path file : entries) {
                monitor.checkCancelled();
                if (file.getFileName().toString().equals("EXPORT_INCOMPLETE.txt")) continue;
                if (!first) out.write(",\n");
                first=false;
                out.write("    {\"path\": " + jsonString(base.relativize(file).toString().replace(File.separatorChar,'/')) +
                    ", \"bytes\": " + Files.size(file) + ", \"sha256\": " + jsonString(sha256File(file)) + "}");
            }
            out.write("\n  ]\n}\n");
        }
    }

}
