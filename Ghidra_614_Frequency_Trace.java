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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/*
 * Ghidra_614_Frequency_Trace
 *
 * TRACE_BUILD = 614-FREQ-STRUCTURE-01
 *
 * Purpose:
 *   Static, read-only tracing around the previously identified RF frequency
 *   field-name table in 614_0_0.mbn. This script checks:
 *     - the table and known field slots;
 *     - direct references to field strings and slots;
 *     - literal pointer copies in initialized non-executable blocks;
 *     - every decoded instruction in every initialized executable block for
 *       exact address operands and low-16-bit offset candidates.
 *
 * Important:
 *   Exact-address hits and low-16-bit matches are only leads. Neither proves
 *   a live RX tuning path without examining the containing function and its
 *   callers/data flow. This script performs no modem access, command creation,
 *   firmware writes, transmit actions, or program modifications.
 */

public class Ghidra_614_Frequency_Trace extends GhidraScript {

    private static final String TRACE_BUILD = "614-FREQ-STRUCTURE-01";
    private static final int MAX_LINES = 6500;
    private static final int MAX_CODE_HITS_PRINTED = 140;
    private static final int MAX_POINTER_HITS_PRINTED = 120;
    private static final int MAX_CONTEXT_WINDOWS = 36;
    private static final int RAW_CHUNK = 0x4000;

    private static final long FIELD_TABLE = 0xC9199798L;
    private static final int FIELD_TABLE_COUNT = 54;

    private static final long SLOT_RX_CARRIER = 0xC919979CL;       // index 1
    private static final long SLOT_TX_CARRIER = 0xC91997A0L;       // index 2
    private static final long SLOT_CENTER_FREQ_A = 0xC91997C8L;    // index 12
    private static final long SLOT_CENTER_FREQ_B = 0xC91997ECL;    // index 21
    private static final long SLOT_BWP_CENTER_FREQ = 0xC9199858L;   // index 48

    private static final long STR_RX_CARRIER = 0xC5082337L;
    private static final long STR_TX_CARRIER = 0xC5082342L;
    private static final long STR_CENTER_FREQ = 0xC508237BL;
    private static final long STR_BWP_CENTER_FREQ = 0xC5082513L;

    private static final String[] FIELD_LABELS = {
        "UNASSIGNED", "RX_CARRIER", "TX_CARRIER", "RFM_DEVICE",
        "DEPRECATED", "BAND", "CHANNEL", "BANDWIDTH", "CONT_MODE",
        "SIG_PATH", "ANT_PATH", "USER_ADJ", "CENTER_FREQ", "ENABLE_XO",
        "TOTAL_ADJ", "BURST_PATTERN", "BEAM_ID", "SUB_FRAME_CONFIG",
        "PLL_ID", "TIME_US", "INTER_FREQ", "CENTER_FREQ", "SUB_TECH",
        "BWP_START_LOC", "PATH_FILTER_TYPE", "TECH_MODE", "SCS",
        "LOAD_CODEBOOK", "NDR_STATE", "TECHNOLOGY", "NETWORK_SIGNAL",
        "RESERVED2", "SELFTEST_TYPE", "UE_POWER_CLASS", "RESERVED3",
        "NB_ID", "LANE_ID", "TX_GAIN_ADJUSTMENT", "SRS_CS_TYPE",
        "SRS_SOURCE_CARRIER", "IF_PLL_UNLOCK_STATUS", "RF_PLL_UNLOCK_STATUS",
        "SUBSCRIPTION_INDEX", "TX_SHARING", "TX_PRORITY", "BWP_ID",
        "BWP_BW", "TARGET_BWP_ID", "BWP_CENTER_FREQ", "BWP_PRIORITY",
        "BWP_CUSTOM", "SUB_CFG_ID", "TARGET_SUB_CFG", "ANT_NUM"
    };

    private static final long[] EXACT_TARGETS = {
        FIELD_TABLE,
        SLOT_RX_CARRIER, SLOT_TX_CARRIER,
        SLOT_CENTER_FREQ_A, SLOT_CENTER_FREQ_B, SLOT_BWP_CENTER_FREQ,
        STR_RX_CARRIER, STR_TX_CARRIER, STR_CENTER_FREQ, STR_BWP_CENTER_FREQ
    };

    private static final String[] EXACT_TARGET_NAMES = {
        "FIELD_TABLE_BASE",
        "RX_CARRIER_SLOT", "TX_CARRIER_SLOT",
        "CENTER_FREQ_SLOT_INDEX12", "CENTER_FREQ_SLOT_INDEX21",
        "BWP_CENTER_FREQ_SLOT_INDEX48",
        "STR_RX_CARRIER", "STR_TX_CARRIER", "STR_CENTER_FREQ",
        "STR_BWP_CENTER_FREQ"
    };

    /*
     * Low-16-bit scalar hits are kept separate from exact-address hits.
     * They may represent split/global-base addressing, but may also be noise.
     */
    private static final long[] LOW16_TARGETS = {
        0x9798L, 0x979CL, 0x97A0L, 0x97C8L, 0x97ECL, 0x9858L,
        0x2337L, 0x2342L, 0x237BL, 0x2513L
    };

    private static final String[] LOW16_NAMES = {
        "TABLE_BASE_LOW16", "RX_SLOT_LOW16", "TX_SLOT_LOW16",
        "CENTER_SLOT12_LOW16", "CENTER_SLOT21_LOW16", "BWP_SLOT48_LOW16",
        "RX_CARRIER_STRING_LOW16", "TX_CARRIER_STRING_LOW16",
        "CENTER_FREQ_STRING_LOW16", "BWP_CENTER_FREQ_STRING_LOW16"
    };

    private int lines = 0;
    private int contextsPrinted = 0;

    private long codeInsnsScanned = 0L;
    private long pointerWordsScanned = 0L;
    private int exactCodeHitsTotal = 0;
    private int low16CodeHitsTotal = 0;
    private int pointerHitsTotal = 0;

    private final long[] exactCodeCounts = new long[EXACT_TARGETS.length];
    private final long[] low16CodeCounts = new long[LOW16_TARGETS.length];
    private final long[] rawPointerCounts = new long[EXACT_TARGETS.length];

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

    private Memory memory() {
        return currentProgram.getMemory();
    }

    private Listing listing() {
        return currentProgram.getListing();
    }

    private String hex(long value) {
        return String.format("0x%08X", value & 0xffffffffL);
    }

    private MemoryBlock block(long offset) {
        try {
            return memory().getBlock(addr(offset));
        }
        catch (Exception e) {
            return null;
        }
    }

    private boolean mapped(long offset, int size) {
        try {
            MemoryBlock b = block(offset);
            if (b == null || !b.isInitialized()) return false;
            long end = offset + (long)size - 1L;
            return end >= offset
                && offset >= b.getStart().getOffset()
                && end <= b.getEnd().getOffset();
        }
        catch (Exception e) {
            return false;
        }
    }

    private long u32(long offset) throws Exception {
        return memory().getInt(addr(offset)) & 0xffffffffL;
    }

    private long readU32Bytes(byte[] buf, int i) {
        return ((long)(buf[i] & 0xff))
            | ((long)(buf[i + 1] & 0xff) << 8)
            | ((long)(buf[i + 2] & 0xff) << 16)
            | ((long)(buf[i + 3] & 0xff) << 24);
    }

    private String asciiAt(long offset, int maxLen) {
        try {
            MemoryBlock b = block(offset);
            if (b == null || !b.isInitialized() || b.isExecute()) return null;
            if (offset < b.getStart().getOffset()
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
        catch (Exception e) {
            return null;
        }
    }

    private String functionName(Address from) {
        try {
            Function f = currentProgram.getFunctionManager().getFunctionContaining(from);
            return f == null ? "<no-function>"
                : f.getName() + "@" + f.getEntryPoint();
        }
        catch (Exception e) {
            return "<function-error>";
        }
    }

    private void printInstructionWindow(Instruction center, int before, int after) {
        if (center == null || contextsPrinted >= MAX_CONTEXT_WINDOWS) return;
        contextsPrinted++;

        Function f = currentProgram.getFunctionManager()
            .getFunctionContaining(center.getAddress());
        Address functionEntry = f == null ? null : f.getEntryPoint();

        List<Instruction> prev = new ArrayList<Instruction>();
        Address cursor = center.getAddress();
        for (int i = 0; i < before; i++) {
            Instruction item = listing().getInstructionBefore(cursor);
            if (item == null) break;

            Function prevFunction = currentProgram.getFunctionManager()
                .getFunctionContaining(item.getAddress());
            if (functionEntry != null
                    && (prevFunction == null
                        || !functionEntry.equals(prevFunction.getEntryPoint()))) break;

            prev.add(item);
            cursor = item.getAddress();
        }
        Collections.reverse(prev);

        p("      CONTEXT_BEGIN");
        for (Instruction item : prev) {
            p("        " + item.getAddress() + "  " + item);
        }
        p("      >>> " + center.getAddress() + "  " + center);
        cursor = center.getAddress();

        for (int i = 0; i < after; i++) {
            Instruction item = listing().getInstructionAfter(cursor);
            if (item == null) break;

            Function nextFunction = currentProgram.getFunctionManager()
                .getFunctionContaining(item.getAddress());
            if (functionEntry != null
                    && (nextFunction == null
                        || !functionEntry.equals(nextFunction.getEntryPoint()))) break;

            p("        " + item.getAddress() + "  " + item);
            cursor = item.getAddress();
        }
        p("      CONTEXT_END");
    }

    private void dumpReferenceList(long target, String label, int limit) {
        p("  REFS_TO " + label + " target=" + hex(target));
        try {
            ReferenceIterator refs = currentProgram.getReferenceManager()
                .getReferencesTo(addr(target));
            int shown = 0;
            long total = 0;

            while (refs.hasNext()) {
                if (monitor.isCancelled()) return;
                Reference ref = refs.next();
                total++;

                if (shown < limit && lines < MAX_LINES) {
                    Address from = ref.getFromAddress();
                    MemoryBlock fromBlock = from.getAddressSpace().isMemorySpace()
                        ? block(from.getOffset()) : null;
                    Instruction ins = (fromBlock != null && fromBlock.isExecute())
                        ? listing().getInstructionAt(from) : null;

                    p("    REF[" + shown + "] from=" + from
                        + " type=" + ref.getReferenceType()
                        + " block=" + (fromBlock == null ? "<none>" : fromBlock.getName())
                        + " function=" + functionName(from));
                    if (ins != null) p("      instruction=" + ins);
                    shown++;
                }
            }
            p("    REFS_TOTAL=" + total + " REFS_SHOWN=" + shown);
        }
        catch (Exception e) {
            p("    REF_ERROR=" + e.getMessage());
        }
    }

    private void dumpKnownFieldTable() {
        p("");
        p("============================================================");
        p("KNOWN FIELD TABLE / SLOT VALIDATION");
        p("Base=" + hex(FIELD_TABLE) + " entries=" + FIELD_TABLE_COUNT
            + " (previously identified table candidate; validate against live image)");
        p("============================================================");

        MemoryBlock tableBlock = block(FIELD_TABLE);
        p("PROGRAM=" + currentProgram.getName());
        p("IMAGE_BASE=" + currentProgram.getImageBase());
        p("TABLE_MAPPED=" + mapped(FIELD_TABLE, FIELD_TABLE_COUNT * 4)
            + " block=" + (tableBlock == null ? "<none>" : tableBlock.getName()));

        for (int i = 0; i < FIELD_TABLE_COUNT; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            long slot = FIELD_TABLE + (long)i * 4L;
            try {
                long ptr = u32(slot);
                String actual = ptr == 0L ? null : asciiAt(ptr, 100);
                String label = i < FIELD_LABELS.length ? FIELD_LABELS[i] : "<no-label>";
                boolean key = i == 1 || i == 2 || i == 12 || i == 21
                    || i == 48 || i == 53;

                if (key || actual != null || ptr == 0L) {
                    p(String.format("  FIELD[%02d] slot=%s ptr=%s actual=%s reference_label=%s",
                        i, hex(slot), hex(ptr),
                        ptr == 0L ? "<NULL>" : actual == null ? "<unreadable>" : actual,
                        label));
                }
            }
            catch (Exception e) {
                p("  FIELD[" + i + "] ERROR=" + e.getMessage());
            }
        }

        dumpReferenceList(FIELD_TABLE, "FIELD_TABLE_BASE", 16);
        dumpReferenceList(SLOT_RX_CARRIER, "RX_CARRIER_SLOT", 16);
        dumpReferenceList(SLOT_TX_CARRIER, "TX_CARRIER_SLOT", 16);
        dumpReferenceList(SLOT_CENTER_FREQ_A, "CENTER_FREQ_SLOT_INDEX12", 16);
        dumpReferenceList(SLOT_CENTER_FREQ_B, "CENTER_FREQ_SLOT_INDEX21", 16);
        dumpReferenceList(SLOT_BWP_CENTER_FREQ, "BWP_CENTER_FREQ_SLOT_INDEX48", 16);

        p("");
        p("============================================================");
        p("KNOWN FIELD STRING VALIDATION");
        p("============================================================");
        dumpStringAndRefs(STR_RX_CARRIER, "RX_CARRIER");
        dumpStringAndRefs(STR_TX_CARRIER, "TX_CARRIER");
        dumpStringAndRefs(STR_CENTER_FREQ, "CENTER_FREQ");
        dumpStringAndRefs(STR_BWP_CENTER_FREQ, "BWP_CENTER_FREQ");
    }

    private void dumpStringAndRefs(long address, String label) {
        p("  STRING " + label + " address=" + hex(address)
            + " mapped=" + mapped(address, 1)
            + " content=\"" + String.valueOf(asciiAt(address, 100)) + "\"");
        dumpReferenceList(address, "STRING_" + label, 24);
    }

    private void scanRawPointerWords() {
        p("");
        p("============================================================");
        p("RAW STATIC POINTER-WORD SCAN");
        p("Scans initialized, non-executable blocks for exact 32-bit copies of known targets.");
        p("Pointer locations are leads; the reference graph may still be incomplete.");
        p("============================================================");

        long[] counts = new long[EXACT_TARGETS.length];
        int printed = 0;

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || b.isExecute()) continue;
            if (b.getStart().getOffset() < 0x1000L) continue;

            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset();
            long pos = (start + 3L) & ~3L;
            byte[] buf = new byte[RAW_CHUNK];

            while (pos <= end - 3L) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                int want = (int)Math.min((long)RAW_CHUNK, end - pos + 1L);
                want -= want % 4;
                if (want < 4) break;

                try {
                    memory().getBytes(addr(pos), buf, 0, want);
                }
                catch (Exception e) {
                    p("  RAW_SCAN_READ_ERROR block=" + b.getName()
                        + " at=" + hex(pos) + " error=" + e.getMessage());
                    break;
                }

                for (int i = 0; i + 4 <= want; i += 4) {
                    long here = pos + i;
                    long value = readU32Bytes(buf, i);
                    pointerWordsScanned++;

                    for (int t = 0; t < EXACT_TARGETS.length; t++) {
                        if (value != EXACT_TARGETS[t]) continue;
                        counts[t]++;
                        rawPointerCounts[t]++;

                        if (printed < MAX_POINTER_HITS_PRINTED) {
                            p("  RAW_POINTER target=" + EXACT_TARGET_NAMES[t]
                                + " value=" + hex(value)
                                + " stored_at=" + hex(here)
                                + " block=" + b.getName());
                            dumpReferenceList(here, "POINTER_SLOT_" + hex(here), 8);
                            printed++;
                        }
                    }
                }
                pos += want;
            }
        }

        pointerHitsTotal = printed;
        p("  RAW_POINTER_WORDS_SCANNED=" + pointerWordsScanned);
        for (int i = 0; i < counts.length; i++) {
            p("  RAW_POINTER_MATCHES " + EXACT_TARGET_NAMES[i] + "=" + counts[i]);
        }
        p("  RAW_POINTER_MATCHES_PRINTED=" + printed);
    }

    private void scanExecutableInstructions() {
        p("");
        p("============================================================");
        p("FULL EXECUTABLE INSTRUCTION SCAN");
        p("All decoded instructions in initialized executable blocks; no three-zone sampling.");
        p("Exact full-address operands and low-16-bit scalar fragments are reported separately.");
        p("Low-16-bit hits are candidates only; inspect the printed context before inferring a base+offset access.");
        p("============================================================");

        int exactShown = 0;
        int low16Shown = 0;
        int printedContexts = 0;

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || !b.isExecute()) continue;

            long end = b.getEnd().getOffset();
            InstructionIterator it = listing().getInstructions(b.getStart(), true);

            while (it.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                Instruction ins = it.next();
                long off = ins.getAddress().getOffset();
                if (off > end) break;

                codeInsnsScanned++;
                boolean matchedExactThisInsn = false;
                boolean matchedLow16ThisInsn = false;

                for (int op = 0; op < ins.getNumOperands(); op++) {
                    Object[] objects = ins.getOpObjects(op);
                    for (int oi = 0; oi < objects.length; oi++) {
                        Object object = objects[oi];
                        long value;
                        boolean isScalar = false;

                        if (object instanceof Scalar) {
                            value = ((Scalar)object).getUnsignedValue() & 0xffffffffL;
                            isScalar = true;
                        }
                        else if (object instanceof Address) {
                            value = ((Address)object).getOffset() & 0xffffffffL;
                        }
                        else {
                            continue;
                        }

                        for (int t = 0; t < EXACT_TARGETS.length; t++) {
                            if (value != EXACT_TARGETS[t]) continue;
                            exactCodeCounts[t]++;
                            exactCodeHitsTotal++;
                            matchedExactThisInsn = true;

                            if (exactShown < MAX_CODE_HITS_PRINTED && lines < MAX_LINES) {
                                p("  CODE_EXACT_HIT target=" + EXACT_TARGET_NAMES[t]
                                    + " value=" + hex(value)
                                    + " instruction_address=" + ins.getAddress()
                                    + " operand=" + op
                                    + " function=" + functionName(ins.getAddress())
                                    + " instruction=" + ins);
                                if (printedContexts < MAX_CONTEXT_WINDOWS) {
                                    printInstructionWindow(ins, 3, 5);
                                    printedContexts++;
                                }
                                exactShown++;
                            }
                        }

                        if (isScalar && value <= 0xffffL) {
                            for (int t = 0; t < LOW16_TARGETS.length; t++) {
                                if (value != LOW16_TARGETS[t]) continue;
                                low16CodeCounts[t]++;
                                low16CodeHitsTotal++;
                                matchedLow16ThisInsn = true;

                                if (low16Shown < MAX_CODE_HITS_PRINTED
                                        && lines < MAX_LINES
                                        && low16CodeCounts[t] <= 16L) {
                                    p("  CODE_LOW16_CANDIDATE target=" + LOW16_NAMES[t]
                                        + " immediate=" + hex(value)
                                        + " instruction_address=" + ins.getAddress()
                                        + " operand=" + op
                                        + " function=" + functionName(ins.getAddress())
                                        + " instruction=" + ins);
                                    if (printedContexts < MAX_CONTEXT_WINDOWS) {
                                        printInstructionWindow(ins, 3, 5);
                                        printedContexts++;
                                    }
                                    low16Shown++;
                                }
                            }
                        }
                    }
                }

                // No per-instruction output when the instruction had no target hit.
                if (matchedExactThisInsn || matchedLow16ThisInsn) {
                    // Counters are updated at operand level above.
                }
            }
        }

        p("  EXECUTABLE_BLOCKS_SCANNED=all initialized executable blocks");
        p("  EXECUTABLE_INSTRUCTIONS_SCANNED=" + codeInsnsScanned);
        p("  EXACT_ADDRESS_OPERAND_HITS_TOTAL=" + exactCodeHitsTotal);
        for (int i = 0; i < exactCodeCounts.length; i++) {
            p("  EXACT_ADDRESS_HITS " + EXACT_TARGET_NAMES[i] + "=" + exactCodeCounts[i]);
        }
        p("  LOW16_SCALAR_HITS_TOTAL=" + low16CodeHitsTotal);
        for (int i = 0; i < low16CodeCounts.length; i++) {
            p("  LOW16_HITS " + LOW16_NAMES[i] + "=" + low16CodeCounts[i]);
        }
        p("  EXACT_HITS_PRINTED=" + exactShown);
        p("  LOW16_CANDIDATES_PRINTED=" + low16Shown);
        p("  CONTEXT_WINDOWS_PRINTED=" + contextsPrinted);
    }

    @Override
    public void run() throws Exception {
        p("============================================================");
        p(" Ghidra_614_Frequency_Trace");
        p(" TRACE_BUILD=" + TRACE_BUILD);
        p(" PURPOSE=614_0_0.mbn frequency-field consumer tracing");
        p(" MODE=static/read-only; no modem commands; no program modifications");
        p("============================================================");

        p("PROGRAM=" + currentProgram.getName());
        p("IMAGE_BASE=" + currentProgram.getImageBase());
        if (!currentProgram.getName().toLowerCase().contains("614_0_0")) {
            p("WARNING_PROGRAM_NAME_DOES_NOT_CONTAIN_614_0_0");
            p("Confirm this program is the intended 614_0_0.mbn image before interpreting address results.");
        }

        dumpKnownFieldTable();
        scanRawPointerWords();
        scanExecutableInstructions();

        p("");
        p("============================================================");
        p("EXECUTION SUMMARY");
        p("TRACE_BUILD=" + TRACE_BUILD);
        p("PROGRAM=" + currentProgram.getName());
        p("TABLE_BASE=" + hex(FIELD_TABLE));
        p("TABLE_MAPPED=" + mapped(FIELD_TABLE, FIELD_TABLE_COUNT * 4));
        p("RAW_POINTER_WORDS_SCANNED=" + pointerWordsScanned);
        p("RAW_POINTER_MATCHES_PRINTED=" + pointerHitsTotal);
        p("EXECUTABLE_INSTRUCTIONS_SCANNED=" + codeInsnsScanned);
        p("EXACT_ADDRESS_OPERAND_HITS_TOTAL=" + exactCodeHitsTotal);
        p("LOW16_SCALAR_HITS_TOTAL=" + low16CodeHitsTotal);
        p("Negative/zero results do not prove the path is absent; addressing may use relocation, literal-pool, or register-based calculations.");
        p("DONE");
        p("No program data or structures modified.");
    }
}
