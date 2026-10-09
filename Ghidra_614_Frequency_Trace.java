import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/*
 * Ghidra_614_Frequency_Trace
 *
 * TRACE_BUILD = 614-FREQ-FIELD-LOCATOR-02
 *
 * IMPORTANT CORRECTION:
 *   The C919xxxx/C508xxxx addresses from earlier STRUCTURE-14/15 logs were
 *   obtained while PROGRAM=qdsp6sw.mbn. They must not be assumed to exist in
 *   614_0_0.mbn. This build has no hard-coded field/table addresses.
 *
 *   It searches the currently loaded program for the literal field strings,
 *   finds pointer-looking words and Ghidra references to the discovered
 *   addresses, and scans already-decoded instructions for exact and low-16-bit
 *   candidates. Results are static leads, not proof of a live RX tune path.
 *
 * READ ONLY. No modem access, DIAG/RF command generation, transmit, or
 * program data/symbol/structure modification.
 */

public class Ghidra_614_Frequency_Trace extends GhidraScript {

    private static final String TRACE_BUILD = "614-FREQ-FIELD-LOCATOR-02";
    private static final int MAX_LINES = 5800;
    private static final int CHUNK = 0x4000;
    private static final int MAX_STRING_HITS_PER_LABEL = 32;
    private static final int MAX_POINTER_HITS_TOTAL = 24;
    private static final int MAX_EXACT_CODE_HITS = 120;
    private static final int MAX_CONTEXTS = 30;

    private static final String[] SEARCH_LABELS = {
        "CENTER_FREQ",
        "BWP_CENTER_FREQ",
        "RX_CARRIER",
        "TX_CARRIER",
        "FREQUENCY",
        "RADIO_CONFIG",
        "ftm_rf_test_radio_config.c"
    };

    private int lines = 0;
    private int contextWindows = 0;
    private long executableInstructions = 0L;
    private long allDecodedInstructions = 0L;
    private long dataWordsScanned = 0L;
    private int exactCodeHits = 0;
    private int low16Hits = 0;

    private final List<StringHit> stringHits = new ArrayList<StringHit>();
    private final List<PointerHit> pointerHits = new ArrayList<PointerHit>();
    private final Map<Long, String> codeExactTargets = new HashMap<Long, String>();
    private final Map<Long, Integer> low16HitCounts = new HashMap<Long, Integer>();
    private final Map<Long, String> low16TargetNames = new HashMap<Long, String>();

    private static class StringHit {
        long address;
        String label;
        String actual;
        String block;
        StringHit(long a, String l, String v, String b) {
            address = a; label = l; actual = v; block = b;
        }
    }

    private static class PointerHit {
        long slot;
        long target;
        String label;
        String block;
        PointerHit(long s, long t, String l, String b) {
            slot = s; target = t; label = l; block = b;
        }
    }

    private void p(String value) {
        if (lines < MAX_LINES) {
            println(value);
            lines++;
        }
    }

    private Address addr(long offset) {
        return currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(offset);
    }

    private Memory memory() { return currentProgram.getMemory(); }
    private Listing listing() { return currentProgram.getListing(); }

    private String hex(long value) {
        return String.format("0x%08X", value & 0xffffffffL);
    }

    private MemoryBlock block(long offset) {
        try { return memory().getBlock(addr(offset)); }
        catch (Exception e) { return null; }
    }

    private String blockName(MemoryBlock b) {
        return b == null ? "<none>" : b.getName();
    }

    private String asciiAt(long offset, int maxLen) {
        try {
            MemoryBlock b = block(offset);
            if (b == null || !b.isInitialized()
                    || offset < b.getStart().getOffset()
                    || offset > b.getEnd().getOffset()) return null;

            int want = (int)Math.min((long)maxLen,
                b.getEnd().getOffset() - offset + 1L);
            if (want <= 0) return null;

            byte[] buf = new byte[want];
            memory().getBytes(addr(offset), buf, 0, want);
            StringBuilder out = new StringBuilder();

            for (int i = 0; i < buf.length; i++) {
                int c = buf[i] & 0xff;
                if (c == 0) return out.length() == 0 ? null : out.toString();
                if (c < 0x20 || c > 0x7e) return null;
                out.append((char)c);
            }
            return out.length() == 0 ? null : out.toString();
        }
        catch (Exception e) { return null; }
    }

    private long u32(long offset) throws Exception {
        return memory().getInt(addr(offset)) & 0xffffffffL;
    }

    private long readU32(byte[] buf, int i) {
        return ((long)(buf[i] & 0xff))
            | ((long)(buf[i + 1] & 0xff) << 8)
            | ((long)(buf[i + 2] & 0xff) << 16)
            | ((long)(buf[i + 3] & 0xff) << 24);
    }

    private String functionName(Address a) {
        try {
            Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
            return f == null ? "<no-function>"
                : f.getName() + "@" + f.getEntryPoint();
        }
        catch (Exception e) { return "<function-error>"; }
    }

    private void printWindow(Instruction center, int before, int after) {
        if (center == null || contextWindows >= MAX_CONTEXTS) return;
        contextWindows++;

        Function owner = currentProgram.getFunctionManager()
            .getFunctionContaining(center.getAddress());
        Address entry = owner == null ? null : owner.getEntryPoint();

        List<Instruction> prior = new ArrayList<Instruction>();
        Address cursor = center.getAddress();
        for (int i = 0; i < before; i++) {
            Instruction ins = listing().getInstructionBefore(cursor);
            if (ins == null) break;
            Function f = currentProgram.getFunctionManager()
                .getFunctionContaining(ins.getAddress());
            if (entry != null && (f == null || !entry.equals(f.getEntryPoint()))) break;
            prior.add(ins);
            cursor = ins.getAddress();
        }
        Collections.reverse(prior);

        p("      CONTEXT_BEGIN");
        for (Instruction ins : prior) p("        " + ins.getAddress() + "  " + ins);
        p("      >>> " + center.getAddress() + "  " + center);

        cursor = center.getAddress();
        for (int i = 0; i < after; i++) {
            Instruction ins = listing().getInstructionAfter(cursor);
            if (ins == null) break;
            Function f = currentProgram.getFunctionManager()
                .getFunctionContaining(ins.getAddress());
            if (entry != null && (f == null || !entry.equals(f.getEntryPoint()))) break;
            p("        " + ins.getAddress() + "  " + ins);
            cursor = ins.getAddress();
        }
        p("      CONTEXT_END");
    }

    private void dumpRefs(long target, String label, int limit) {
        p("  XREFS target=" + hex(target) + " label=" + label);
        try {
            ReferenceIterator it = currentProgram.getReferenceManager()
                .getReferencesTo(addr(target));
            int shown = 0;
            long total = 0;
            while (it.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                Reference ref = it.next();
                total++;
                if (shown >= limit) continue;
                Address from = ref.getFromAddress();
                MemoryBlock fb = from.getAddressSpace().isMemorySpace()
                    ? block(from.getOffset()) : null;
                Instruction ins = listing().getInstructionAt(from);
                p("    REF[" + shown + "] from=" + from
                    + " type=" + ref.getReferenceType()
                    + " block=" + blockName(fb)
                    + " function=" + functionName(from));
                if (ins != null) p("      instruction=" + ins);
                shown++;
            }
            p("    REFS_TOTAL=" + total + " REFS_SHOWN=" + shown);
        }
        catch (Exception e) {
            p("    XREF_ERROR=" + e.getMessage());
        }
    }

    private boolean isExactFieldLabel(String label, String actual) {
        if (actual == null) return false;
        if ("ftm_rf_test_radio_config.c".equals(label)) {
            return actual.toLowerCase().contains(label.toLowerCase());
        }
        if ("RADIO_CONFIG".equals(label)) {
            return actual.equalsIgnoreCase(label);
        }
        return actual.equalsIgnoreCase(label);
    }

    private void searchOneLabel(MemoryBlock b, String label) {
        byte[] pattern = label.getBytes(StandardCharsets.US_ASCII);
        long start = b.getStart().getOffset();
        long end = b.getEnd().getOffset();
        long pos = start;
        int shown = 0;
        long found = 0;

        while (pos <= end && !monitor.isCancelled() && lines < MAX_LINES) {
            long remaining = end - pos + 1L;
            int want = (int)Math.min((long)CHUNK, remaining);
            if (want < pattern.length) break;

            byte[] buf = new byte[want];
            try { memory().getBytes(addr(pos), buf, 0, want); }
            catch (Exception e) {
                p("  STRING_SCAN_READ_ERROR label=" + label + " at=" + hex(pos)
                    + " block=" + b.getName() + " error=" + e.getMessage());
                break;
            }

            for (int i = 0; i <= want - pattern.length; i++) {
                boolean same = true;
                for (int j = 0; j < pattern.length; j++) {
                    if (buf[i + j] != pattern[j]) { same = false; break; }
                }
                if (!same) continue;

                long at = pos + i;
                String actual = asciiAt(at, 180);
                if (!isExactFieldLabel(label, actual)) continue;

                found++;
                if (shown < MAX_STRING_HITS_PER_LABEL) {
                    StringHit hit = new StringHit(at, label, actual, b.getName());
                    boolean duplicate = false;
                    for (StringHit old : stringHits) {
                        if (old.address == at && old.label.equals(label)) {
                            duplicate = true; break;
                        }
                    }
                    if (!duplicate) stringHits.add(hit);

                    codeExactTargets.put(at,
                        "STRING_" + label + (stringHits.size() > 1 ? "_DUP" : ""));
                    long low = at & 0xffffL;
                    if (low != 0L) low16TargetNames.put(low, "STRING_" + label);

                    p("  STRING_HIT label=" + label
                        + " address=" + hex(at)
                        + " block=" + b.getName()
                        + " actual=\"" + actual + "\"");
                    shown++;
                }
            }

            // Advance to the first not-yet-tested starting offset.
            long advance = (long)want - pattern.length + 1L;
            if (advance <= 0L) break;
            pos += advance;
        }

        if (found > 0) {
            p("  STRING_LABEL_SUMMARY label=" + label
                + " total_matches=" + found + " printed=" + shown);
        }
    }

    private void inventoryBlocksAndFindStrings() {
        p("");
        p("============================================================");
        p("PROGRAM / MEMORY BLOCK INVENTORY");
        p("No C919xxxx/C508xxxx address is assumed. Actual ranges are read from this program.");
        p("============================================================");

        p("PROGRAM=" + currentProgram.getName());
        p("IMAGE_BASE=" + currentProgram.getImageBase());

        MemoryBlock[] blocks = memory().getBlocks();
        p("MEMORY_BLOCK_COUNT=" + blocks.length);
        int shown = 0;
        for (MemoryBlock b : blocks) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (shown < 220) {
                long size = b.getEnd().getOffset() - b.getStart().getOffset() + 1L;
                p("  BLOCK name=" + b.getName()
                    + " start=" + b.getStart()
                    + " end=" + b.getEnd()
                    + " size=" + size
                    + " initialized=" + b.isInitialized()
                    + " read=" + b.isRead()
                    + " write=" + b.isWrite()
                    + " execute=" + b.isExecute());
            }
            shown++;
        }

        p("");
        p("============================================================");
        p("RAW MEMORY STRING LOCATOR");
        p("Searches bytes directly; does not require strings to be defined in Ghidra.");
        p("Field names must match the whole C string (prevents CENTER_FREQ matching BWP_CENTER_FREQ).");
        p("============================================================");

        for (MemoryBlock b : blocks) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized()) continue;
            for (String label : SEARCH_LABELS) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                searchOneLabel(b, label);
            }
        }

        p("STRING_SEARCH_LABELS=" + SEARCH_LABELS.length);
        p("UNIQUE_STRING_HITS_RECORDED=" + stringHits.size());

        Set<Long> listed = new HashSet<Long>();
        for (StringHit hit : stringHits) {
            if (listed.add(hit.address)) {
                dumpRefs(hit.address, hit.label + "@" + hex(hit.address), 20);
            }
        }
    }

    private void printPointerNeighborhood(long slot) {
        long start = Math.max(0L, slot - 0x20L);
        long end = slot + 0x24L;
        MemoryBlock b = block(slot);
        if (b == null || !b.isInitialized()) return;
        start = Math.max(start, b.getStart().getOffset());
        end = Math.min(end, b.getEnd().getOffset());

        p("      POINTER_NEIGHBORHOOD " + hex(start) + ".." + hex(end));
        long first = (start + 3L) & ~3L;
        for (long at = first; at + 3L <= end && lines < MAX_LINES; at += 4L) {
            try {
                long v = u32(at);
                String s = v == 0L ? null : asciiAt(v, 100);
                p("        slot=" + hex(at) + " value=" + hex(v)
                    + (s == null ? "" : " text=\"" + s + "\""));
            }
            catch (Exception e) {
                p("        slot=" + hex(at) + " read_error=" + e.getMessage());
            }
        }
    }

    private void scanPointerWords() {
        p("");
        p("============================================================");
        p("DYNAMIC STRING-POINTER SLOT SCAN");
        p("Targets are the actual string addresses found in this image, not addresses copied from qdsp6sw.mbn.");
        p("Scans aligned 32-bit words in initialized non-executable blocks.");
        p("============================================================");

        List<StringHit> targets = new ArrayList<StringHit>(stringHits);
        int printed = 0;

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || b.isExecute()) continue;

            long start = (b.getStart().getOffset() + 3L) & ~3L;
            long end = b.getEnd().getOffset();
            long pos = start;
            byte[] buf = new byte[CHUNK];

            while (pos + 3L <= end && !monitor.isCancelled() && lines < MAX_LINES) {
                int want = (int)Math.min((long)CHUNK, end - pos + 1L);
                want -= want % 4;
                if (want < 4) break;

                try { memory().getBytes(addr(pos), buf, 0, want); }
                catch (Exception e) {
                    p("  POINTER_SCAN_READ_ERROR block=" + b.getName()
                        + " at=" + hex(pos) + " error=" + e.getMessage());
                    break;
                }

                for (int i = 0; i + 4 <= want; i += 4) {
                    dataWordsScanned++;
                    long value = readU32(buf, i);
                    for (StringHit target : targets) {
                        if (value != (target.address & 0xffffffffL)) continue;
                        long slot = pos + i;
                        pointerHits.add(new PointerHit(slot, value, target.label, b.getName()));
                        codeExactTargets.put(slot, "POINTER_SLOT_" + target.label);
                        long low = slot & 0xffffL;
                        if (low != 0L) low16TargetNames.put(low,
                            "POINTER_SLOT_" + target.label);

                        if (printed < MAX_POINTER_HITS_TOTAL) {
                            p("  POINTER_SLOT_HIT target=" + target.label
                                + " string=" + hex(value)
                                + " slot=" + hex(slot)
                                + " block=" + b.getName()
                                + " string_value=\"" + target.actual + "\"");
                            printPointerNeighborhood(slot);
                            dumpRefs(slot, "POINTER_SLOT_" + hex(slot), 12);
                            printed++;
                        }
                    }
                }
                pos += want;
            }
        }

        p("  ALIGNED_DATA_WORDS_SCANNED=" + dataWordsScanned);
        p("  POINTER_SLOT_HITS_TOTAL=" + pointerHits.size());
        p("  POINTER_SLOT_HITS_PRINTED=" + printed);
        if (pointerHits.isEmpty()) {
            p("  NOTE=No aligned absolute pointers found. This does not rule out split addresses, relative tables, or register-based references.");
        }
    }

    private void scanDecodedInstructions() {
        p("");
        p("============================================================");
        p("DECODED INSTRUCTION XREF CANDIDATES");
        p("Walks instructions already present in Ghidra across all initialized blocks, even if a block is not flagged executable.");
        p("Exact full-address hits are separate from low-16-bit immediate candidates.");
        p("============================================================");

        int exactShown = 0;
        int low16Shown = 0;

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized()) continue;

            long end = b.getEnd().getOffset();
            InstructionIterator it = listing().getInstructions(b.getStart(), true);
            long perBlock = 0;

            while (it.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                Instruction ins = it.next();
                long off = ins.getAddress().getOffset();
                if (off > end) break;

                allDecodedInstructions++;
                perBlock++;
                if (b.isExecute()) executableInstructions++;

                for (int op = 0; op < ins.getNumOperands(); op++) {
                    Object[] items = ins.getOpObjects(op);
                    for (Object item : items) {
                        boolean scalar = item instanceof Scalar;
                        long value;
                        if (scalar) {
                            value = ((Scalar)item).getUnsignedValue() & 0xffffffffL;
                        }
                        else if (item instanceof Address) {
                            value = ((Address)item).getOffset() & 0xffffffffL;
                        }
                        else continue;

                        String exactName = codeExactTargets.get(value);
                        if (exactName != null) {
                            exactCodeHits++;
                            if (exactShown < MAX_EXACT_CODE_HITS && lines < MAX_LINES) {
                                p("  CODE_EXACT_HIT target=" + exactName
                                    + " value=" + hex(value)
                                    + " at=" + ins.getAddress()
                                    + " operand=" + op
                                    + " function=" + functionName(ins.getAddress())
                                    + " instruction=" + ins);
                                if (contextWindows < MAX_CONTEXTS) printWindow(ins, 3, 5);
                                exactShown++;
                            }
                        }

                        if (!scalar) continue;
                        long low = value & 0xffffL;
                        String lowName = low16TargetNames.get(low);
                        if (lowName == null || low == 0L || low < 0x1000L) continue;

                        low16Hits++;
                        int already = low16HitCounts.containsKey(low)
                            ? low16HitCounts.get(low).intValue() : 0;
                        low16HitCounts.put(low, Integer.valueOf(already + 1));

                        if (already < 4 && low16Shown < 140 && lines < MAX_LINES) {
                            p("  CODE_LOW16_CANDIDATE target=" + lowName
                                + " low16=" + hex(low)
                                + " immediate=" + hex(value)
                                + " at=" + ins.getAddress()
                                + " operand=" + op
                                + " function=" + functionName(ins.getAddress())
                                + " instruction=" + ins);
                            low16Shown++;
                        }
                    }
                }
            }

            p("  BLOCK_DECODED_INSTRUCTIONS name=" + b.getName()
                + " execute_flag=" + b.isExecute()
                + " instructions=" + perBlock);
        }

        p("  DECODED_INSTRUCTIONS_ALL_BLOCKS=" + allDecodedInstructions);
        p("  DECODED_INSTRUCTIONS_IN_EXECUTABLE_BLOCKS=" + executableInstructions);
        p("  CODE_EXACT_HITS_TOTAL=" + exactCodeHits);
        p("  CODE_EXACT_HITS_PRINTED=" + exactShown);
        p("  CODE_LOW16_HITS_TOTAL=" + low16Hits);
        p("  CODE_LOW16_CANDIDATES_PRINTED=" + low16Shown);
        p("  CONTEXT_WINDOWS_PRINTED=" + contextWindows);
        if (allDecodedInstructions == 0L) {
            p("  WARNING=No decoded instructions exist in any initialized block. Import/disassembly or target-binary selection must be checked before drawing code-path conclusions.");
        }
    }

    @Override
    public void run() throws Exception {
        p("============================================================");
        p(" Ghidra_614_Frequency_Trace");
        p(" TRACE_BUILD=" + TRACE_BUILD);
        p(" PURPOSE=Locate frequency fields within the currently loaded 614_0_0.mbn image");
        p(" MODE=static/read-only");
        p("============================================================");

        p("PROGRAM=" + currentProgram.getName());
        p("IMAGE_BASE=" + currentProgram.getImageBase());
        if (!currentProgram.getName().toLowerCase().contains("614_0_0")) {
            p("WARNING_PROGRAM_NAME_DOES_NOT_CONTAIN_614_0_0");
        }

        inventoryBlocksAndFindStrings();
        scanPointerWords();
        scanDecodedInstructions();

        p("");
        p("============================================================");
        p("EXECUTION SUMMARY");
        p("TRACE_BUILD=" + TRACE_BUILD);
        p("PROGRAM=" + currentProgram.getName());
        p("STRING_HITS=" + stringHits.size());
        p("POINTER_SLOT_HITS=" + pointerHits.size());
        p("ALIGNED_DATA_WORDS_SCANNED=" + dataWordsScanned);
        p("DECODED_INSTRUCTIONS_ALL_BLOCKS=" + allDecodedInstructions);
        p("DECODED_INSTRUCTIONS_IN_EXECUTABLE_BLOCKS=" + executableInstructions);
        p("CODE_EXACT_HITS=" + exactCodeHits);
        p("CODE_LOW16_HITS=" + low16Hits);
        p("No matches are not proof the fields are absent; only currently mapped bytes and already-decoded instructions were examined.");
        p("DONE");
        p("No program data or structures modified.");
    }
}
