// Ekspor hasil analisis Ghidra untuk analyzer reverse-apk (tahap native_deep).
//
// Dijalankan headless oleh analyzer/ghidra.py:
//   analyzeHeadless <projdir> <nama> -import <lib.so> -scriptPath <dir-analyzer>
//       -postScript GhidraExport.java <keluaran.json> <keluaran.c> <maks-dekompilasi>
//       -deleteProject
//
// Keluaran JSON: bahasa prosesor + image base, daftar fungsi (alamat, ukuran, pemanggil/
// dipanggil, penanda JNI & operasi FP vektor), fungsi impor, string beserta xref-nya,
// dan kecocokan konstanta kripto dikenal. Berkas .c berisi dekompilasi per fungsi
// (prioritas: JNI, lalu fungsi FP vektor, lalu terbesar) dengan penanda alamat.
//
// Semua isi berasal dari .so yang TIDAK TEPERCAYA: skrip ini hanya MEMBACA program
// hasil auto-analysis; tidak mengeksekusi apa pun dari berkas target.

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class GhidraExport extends GhidraScript {

    private static final int MAX_FUNCTIONS = 5000;
    private static final int MAX_STRINGS = 2000;
    private static final int MAX_EDGES = 50;
    private static final int MAX_XREFS = 20;
    private static final Set<String> FP_MNEMONICS = new HashSet<>(Arrays.asList(
        "FMUL", "FADD", "FSUB", "FDIV", "FSQRT", "FMADD", "FMSUB", "FNMADD", "FNMSUB",
        "FMLA", "FMLS", "SQRT", "MUL", "ADD", "SQRDMULH", "UMLAL", "SMLAL"));

    private static String esc(String s) {
        StringBuilder b = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    private static String q(String s) {
        return "\"" + esc(s == null ? "" : s) + "\"";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            println("GhidraExport: argumen <json> <c> <maks-dekompilasi> wajib");
            return;
        }
        String jsonPath = args[0];
        String cPath = args[1];
        int maxDecompile = Integer.parseInt(args[2]);

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();

        // --- kumpulkan fungsi + penanda
        List<Function> funcs = new ArrayList<>();
        List<Boolean> vecFlags = new ArrayList<>();
        FunctionIterator fit = fm.getFunctions(true);
        while (fit.hasNext() && funcs.size() <= MAX_FUNCTIONS) {
            Function f = fit.next();
            funcs.add(f);
            vecFlags.add(hasVectorFp(f));
        }
        boolean funcsTruncated = fit.hasNext();

        // --- impor (fungsi eksternal)
        List<String> imports = new ArrayList<>();
        FunctionIterator eit = fm.getExternalFunctions();
        while (eit.hasNext()) {
            imports.add(eit.next().getName());
        }

        // --- konstanta kripto dikenal (pencarian byte di memori program)
        List<String> crypto = findCryptoConstants();

        try (Writer jw = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(jsonPath), StandardCharsets.UTF_8))) {
            StringBuilder j = new StringBuilder();
            j.append("{\n");
            j.append(" \"program\": ").append(q(currentProgram.getName())).append(",\n");
            j.append(" \"language\": ").append(q(currentProgram.getLanguageID().toString())).append(",\n");
            j.append(" \"compiler\": ").append(q(currentProgram.getCompilerSpec().getCompilerSpecID().toString())).append(",\n");
            j.append(" \"image_base\": ").append(q(currentProgram.getImageBase().toString())).append(",\n");
            j.append(" \"functions_truncated\": ").append(funcsTruncated).append(",\n");

            j.append(" \"imports\": [");
            for (int i = 0; i < imports.size(); i++) {
                if (i > 0) j.append(", ");
                j.append(q(imports.get(i)));
            }
            j.append("],\n");

            j.append(" \"crypto_constants\": [");
            for (int i = 0; i < crypto.size(); i++) {
                if (i > 0) j.append(", ");
                j.append(q(crypto.get(i)));
            }
            j.append("],\n");

            // --- fungsi
            j.append(" \"functions\": [\n");
            for (int i = 0; i < funcs.size(); i++) {
                Function f = funcs.get(i);
                if (i > 0) j.append(",\n");
                j.append("  {\"name\": ").append(q(f.getName()));
                j.append(", \"addr\": ").append(q(f.getEntryPoint().toString()));
                j.append(", \"size\": ").append(f.getBody().getNumAddresses());
                j.append(", \"thunk\": ").append(f.isThunk());
                j.append(", \"jni\": ").append(isJni(f.getName()));
                j.append(", \"vector_fp\": ").append(vecFlags.get(i));
                j.append(", \"callers\": ").append(nameList(f.getCallingFunctions(monitor)));
                j.append(", \"callees\": ").append(nameList(f.getCalledFunctions(monitor)));
                j.append("}");
            }
            j.append("\n ],\n");

            // --- string + xref
            j.append(" \"strings\": [\n");
            DataIterator dit = currentProgram.getListing().getDefinedData(true);
            int nStr = 0;
            boolean strTruncated = false;
            while (dit.hasNext()) {
                Data d = dit.next();
                Object v = d.getValue();
                if (!(v instanceof String)) continue;
                String sval = (String) v;
                if (sval.length() < 4) continue;
                // Buang derau tabel simbol/section: string analitis tinggal di .rodata/.data.
                String block = currentProgram.getMemory().getBlock(d.getAddress()) == null
                    ? "" : currentProgram.getMemory().getBlock(d.getAddress()).getName();
                if (block.startsWith(".dyn") || block.startsWith(".strtab")
                        || block.startsWith(".shstrtab") || block.startsWith(".symtab")
                        || block.startsWith(".comment") || block.startsWith(".note")) continue;
                if (nStr >= MAX_STRINGS) { strTruncated = true; break; }
                if (nStr > 0) j.append(",\n");
                j.append("  {\"addr\": ").append(q(d.getAddress().toString()));
                j.append(", \"value\": ").append(q(v.toString()));
                j.append(", \"xrefs\": [");
                Iterator<Reference> refs = rm.getReferencesTo(d.getAddress());
                int nRef = 0;
                while (refs.hasNext() && nRef < MAX_XREFS) {
                    Reference r = refs.next();
                    if (nRef > 0) j.append(", ");
                    Address from = r.getFromAddress();
                    Function holder = fm.getFunctionContaining(from);
                    j.append("{\"from\": ").append(q(from.toString()));
                    j.append(", \"in\": ").append(q(holder == null ? "" : holder.getName())).append("}");
                    nRef++;
                }
                j.append("]}");
                nStr++;
            }
            j.append("\n ],\n");
            j.append(" \"strings_truncated\": ").append(strTruncated).append("\n");
            j.append("}\n");
            jw.write(j.toString());
        }

        // --- dekompilasi (prioritas JNI > vektor FP > ukuran)
        List<Function> order = new ArrayList<>(funcs);
        order.sort(Comparator
            .comparingInt((Function f) -> isJni(f.getName()) ? 0 : 1)
            .thenComparingInt(f -> vecFlags.get(funcs.indexOf(f)) ? 0 : 1)
            .thenComparingLong(f -> -f.getBody().getNumAddresses()));
        int done = 0;
        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(false);
        decomp.setSimplificationStyle("decompile");
        try (Writer cw = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(cPath), StandardCharsets.UTF_8))) {
            cw.write("/* Dekompilasi Ghidra untuk " + currentProgram.getName()
                + " (" + currentProgram.getLanguageID() + ") */\n");
            if (decomp.openProgram(currentProgram)) {
                for (Function f : order) {
                    if (done >= maxDecompile) break;
                    if (f.isExternal() || f.isThunk()) continue;
                    DecompileResults res = decomp.decompileFunction(f, 30, monitor);
                    if (res == null || !res.decompileCompleted()
                            || res.getDecompiledFunction() == null) {
                        continue;
                    }
                    cw.write("\n/* ==== " + f.getEntryPoint() + " " + f.getName()
                        + (isJni(f.getName()) ? " [JNI]" : "")
                        + (vecFlags.get(funcs.indexOf(f)) ? " [vektor-fp]" : "") + " ==== */\n");
                    cw.write(res.getDecompiledFunction().getC());
                    done++;
                }
            }
            cw.write("\n/* total didekompilasi: " + done + " */\n");
        } finally {
            decomp.dispose();
        }
        println("GhidraExport: " + funcs.size() + " fungsi, " + imports.size()
            + " impor, " + done + " didekompilasi");
    }

    private boolean isJni(String name) {
        return name.startsWith("Java_") || name.equals("JNI_OnLoad") || name.equals("JNI_OnUnload")
            || name.contains("JNI_OnLoad");
    }

    private String nameList(Set<Function> set) {
        StringBuilder b = new StringBuilder("[");
        int i = 0;
        for (Function f : set) {
            if (i >= MAX_EDGES) break;
            if (i > 0) b.append(", ");
            b.append(q(f.getName()));
            i++;
        }
        return b.append("]").toString();
    }

    private boolean hasVectorFp(Function f) {
        InstructionIterator iit = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (iit.hasNext()) {
            Instruction ins = iit.next();
            String mnem = ins.getMnemonicString().toUpperCase();
            if (!FP_MNEMONICS.contains(mnem)) continue;
            String text = ins.toString();
            // Operan vektor AARCH64: register vN/qN atau penentu susunan .4S/.2D/.8H/.16B dst.
            if (text.contains(".4S") || text.contains(".2D") || text.contains(".8H")
                    || text.contains(".16B") || text.contains(".4s") || text.contains(".2d")
                    || text.contains(".8h") || text.contains(".16b")
                    || text.matches(".*\\b[vq][0-9]{1,2}\\b.*")) {
                return true;
            }
        }
        return false;
    }

    private List<String> findCryptoConstants() {
        List<String> found = new ArrayList<>();
        Memory mem = currentProgram.getMemory();
        byte[][] patterns = {
            // AES S-box, 16 byte pertama
            {0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5,
             0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, 0x76},
            // SHA-256 H(0) kata pertama 0x6a09e667 tersimpan little-endian
            {0x67, (byte) 0xe6, 0x09, 0x6a},
            // SHA-256 K[0] 0x428a2f98 tersimpan little-endian
            {(byte) 0x98, 0x2f, (byte) 0x8a, 0x42},
        };
        String[] names = {"aes_sbox", "sha256_h_init", "sha256_k_table"};
        Address start = currentProgram.getMinAddress();
        for (int i = 0; i < patterns.length; i++) {
            try {
                Address hit = mem.findBytes(start, patterns[i], null, true, monitor);
                if (hit != null) found.add(names[i] + "@" + hit);
            } catch (Exception ignored) {
                // pencarian konstanta bersifat tambahan; kegagalannya tidak menggagalkan ekspor
            }
        }
        return found;
    }
}
