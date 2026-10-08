import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.List;

/*
 * Ghidra_RFDEBUG_Trace
 *
 * TRACE_BUILD = DIAG-FTM-TARGET-DUMP-2
 *
 * Phase 2:
 *   1) Directly inspect the externally-derived reference addresses.
 *   2) Dump raw bytes around:
 *        0xC8DC3B54  (DIAG master candidate)
 *        0xC37BD1E8  (FTM table candidate)
 *   3) Print defined Ghidra data and all direct references.
 *   4) Look for raw little-endian pointer copies only in segment_19/21.
 *   5) Do NOT assume a master/table layout before seeing the bytes.
 *
 * IMPORTANT:
 *   - READ ONLY.
 *   - No memory, symbol, comment, or program-structure modifications.
 *   - No modem access.
 *   - No FTM/RF command transmission.
 */

public class Ghidra_RFDEBUG_Trace extends GhidraScript {

    private static final String TRACE_BUILD = "DIAG-FTM-TARGET-DUMP-2";

    private static final long REF_MASTER = 0xC8DC3B54L;
    private static final long REF_TABLE  = 0xC37BD1E8L;
    private static final long REF_DISP   = 0xD8150ED8L;
    private static final long REF_TABLE2 = 0xC37BD1A8L;
    private static final long REF_DISP2  = 0xD8150E24L;
    private static final long REF_DISP3  = 0xD815056CL;

    private static final int DUMP_MASTER_RADIUS = 0x100;
    private static final int DUMP_TABLE_RADIUS  = 0x200;

    private static final int MAX_LINES = 8000;
    private static final int MAX_REFS = 128;
    private static final long MAX_RAW_SCAN_BYTES = 0x800000L;
    private static final int RAW_CHUNK = 0x4000;
    private static final int LOCAL_ZERO_RADIUS = 0x10000;
    private static final int LOCAL_CHUNK = 0x4000;

    private int lines = 0;

    private Address addr(long off) {
        return currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(off);
    }

    private Memory memory() {
        return currentProgram.getMemory();
    }

    private Listing listing() {
        return currentProgram.getListing();
    }

    private String hex(long v) {
        return String.format("0x%08X", v & 0xffffffffL);
    }

    private String hex64(long v) {
        return String.format("0x%016X", v);
    }

    private MemoryBlock block(long off) {
        try {
            Address a = addr(off);
            return memory().getBlock(a);
        }
        catch (Exception e) {
            return null;
        }
    }

    private boolean initialized(long off, int len) {
        MemoryBlock b = block(off);
        if (b == null || !b.isInitialized()) return false;

        long end = off + (long)len - 1L;
        if (end < off) return false;

        return off >= b.getStart().getOffset()
            && end <= b.getEnd().getOffset();
    }

    private int u8(long off) throws Exception {
        return memory().getByte(addr(off)) & 0xff;
    }

    private int u16(long off) throws Exception {
        return memory().getShort(addr(off)) & 0xffff;
    }

    private long u32(long off) throws Exception {
        return memory().getInt(addr(off)) & 0xffffffffL;
    }

    private long u64(long off) throws Exception {
        return memory().getLong(addr(off));
    }

    private String byteString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02X", b[i] & 0xff));
        }
        return sb.toString();
    }

    private String asciiPreview(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            int c = x & 0xff;
            sb.append(c >= 0x20 && c <= 0x7e ? (char)c : '.');
        }
        return sb.toString();
    }

    private void p(String s) {
        if (lines >= MAX_LINES) return;
        println(s);
        lines++;
    }

    private String functionInfo(long off) {
        try {
            Function f = currentProgram.getFunctionManager()
                .getFunctionContaining(addr(off));
            return f == null ? "<no-function>" :
                f.getName() + " @ " + f.getEntryPoint();
        }
        catch (Exception e) {
            return "<function-error>";
        }
    }

    private String instructionInfo(long off) {
        try {
            Instruction ins = listing().getInstructionAt(addr(off));
            if (ins == null) return "<no-instruction>";
            return ins.toString();
        }
        catch (Exception e) {
            return "<instruction-error>";
        }
    }

    private void printDataInfo(long off) {
        try {
            Address a = addr(off);
            Data d = listing().getDataContaining(a);
            if (d == null) {
                p("  DATA: <none>");
                return;
            }

            p("  DATA: " + d.getAddress()
                + " len=" + d.getLength()
                + " type=" + d.getDataType()
                + " value=" + String.valueOf(d.getValue()));
        }
        catch (Exception e) {
            p("  DATA: <error> " + e.getMessage());
        }
    }

    private void printBlockDetails(MemoryBlock b) {
        if (b == null) {
            p("  BLOCK_DETAILS: <none>");
            return;
        }

        try {
            p("  block_type=" + b.getType());
            p("  flags=0x" + Integer.toHexString(b.getFlags()));
            p("  read=" + b.isRead()
                + " write=" + b.isWrite()
                + " exec=" + b.isExecute()
                + " volatile=" + b.isVolatile()
                + " artificial=" + b.isArtificial());
            p("  loaded=" + b.isLoaded()
                + " mapped=" + b.isMapped()
                + " overlay=" + b.isOverlay()
                + " initialized=" + b.isInitialized());
            p("  source_name=" + String.valueOf(b.getSourceName()));
            try {
                p("  source_infos=" + b.getSourceInfos().size());
            }
            catch (Exception ignored) {
                p("  source_infos=<error>");
            }
            try {
                p("  block_data_stream=" + (b.getData() == null ? "<null>" : "<present>"));
            }
            catch (Exception ignored) {
                p("  block_data_stream=<error>");
            }
        }
        catch (Exception e) {
            p("  BLOCK_DETAILS ERROR: " + e.getMessage());
        }
    }

    private void localNonZeroScan(long center, int radius, String name) {
        p("");
        p("LOCAL BYTE ACTIVITY: " + name);
        p("RANGE " + hex(center - radius) + " .. " + hex(center + radius));

        long start = center - (long)radius;
        long end = center + (long)radius;
        MemoryBlock b = block(center);

        if (b == null) {
            p("  CENTER_BLOCK=<none>");
            return;
        }

        long bs = b.getStart().getOffset();
        long be = b.getEnd().getOffset();
        if (start < bs) start = bs;
        if (end > be) end = be;

        byte[] buf = new byte[LOCAL_CHUNK];
        long pos = start;
        long total = 0;
        long nonZero = 0;
        long first = -1;
        long last = -1;
        int runs = 0;
        long runStart = -1;
        long runEnd = -1;

        try {
            while (pos <= end) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                int want = (int)Math.min((long)LOCAL_CHUNK, end - pos + 1L);
                memory().getBytes(addr(pos), buf, 0, want);

                for (int i = 0; i < want; i++) {
                    long a = pos + i;
                    int v = buf[i] & 0xff;
                    total++;

                    if (v != 0) {
                        nonZero++;
                        if (first < 0) first = a;
                        last = a;

                        if (runStart < 0) runStart = a;
                        runEnd = a;
                    }
                    else if (runStart >= 0) {
                        runs++;
                        if (runs <= 24) {
                            p("  NONZERO_RUN[" + runs + "] "
                                + hex(runStart) + " .. " + hex(runEnd)
                                + " len=" + (runEnd - runStart + 1L));
                        }
                        runStart = -1;
                        runEnd = -1;
                    }
                }

                if (want <= 0) break;
                pos += want;
            }

            if (runStart >= 0) {
                runs++;
                if (runs <= 24) {
                    p("  NONZERO_RUN[" + runs + "] "
                        + hex(runStart) + " .. " + hex(runEnd)
                        + " len=" + (runEnd - runStart + 1L));
                }
            }

            p("  TOTAL_BYTES=" + total);
            p("  NONZERO_BYTES=" + nonZero);
            p("  ZERO_BYTES=" + (total - nonZero));
            p("  NONZERO_RUNS=" + runs);
            p("  FIRST_NONZERO=" + (first < 0 ? "<none>" : hex(first)));
            p("  LAST_NONZERO=" + (last < 0 ? "<none>" : hex(last)));
        }
        catch (Exception e) {
            p("  LOCAL SCAN ERROR: " + e.getMessage());
        }
    }

    private static final String[] FTM_LOCATOR_TERMS = {
        "ftm", "rfa", "pdm", "diag", "factory", "calibration",
        "ara", "rfdebug", "radio_configure", "rf_test"
    };

    private boolean containsIgnoreCase(String s, String needle) {
        return s != null && needle != null
            && s.toLowerCase().contains(needle.toLowerCase());
    }

    private String matchedTerms(String s) {
        StringBuilder out = new StringBuilder();

        for (String term : FTM_LOCATOR_TERMS) {
            if (containsIgnoreCase(s, term)) {
                if (out.length() > 0) out.append(",");
                out.append(term);
            }
        }

        return out.toString();
    }

    private void printDataStringXrefs(Data d, int maxRefs) {
        try {
            ReferenceIterator it =
                currentProgram.getReferenceManager().getReferencesTo(d.getAddress());

            int n = 0;

            while (it.hasNext() && n < maxRefs && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;

                Reference r = it.next();
                Address from = r.getFromAddress();

                p(String.format(
                    "      XREF[%02d] from=%s type=%s primary=%s",
                    n, from, r.getReferenceType(), r.isPrimary()));

                if (from.getAddressSpace().isMemorySpace()) {
                    p("             function=" + functionInfo(from.getOffset()));
                    p("             instruction=" + instructionInfo(from.getOffset()));
                }

                n++;
            }

            p("      XREF_COUNT_SHOWN=" + n);
        }
        catch (Exception e) {
            p("      STRING XREF ERROR: " + e.getMessage());
        }
    }

    private void scanFtmLocatorStrings() {
        p("");
        p("============================================================");
        p("FTM / RFA / DIAG STRING LOCATOR");
        p("Static string census with code-reference reporting");
        p("READ ONLY");
        p("============================================================");

        int inspected = 0;
        int hits = 0;

        try {
            ghidra.program.model.listing.DataIterator it =
                currentProgram.getListing().getDefinedData(true);

            while (it.hasNext()
                    && inspected < 250000
                    && hits < 96
                    && lines < MAX_LINES) {

                if (monitor.isCancelled()) return;

                Data d = it.next();
                inspected++;

                String typeName =
                    String.valueOf(d.getDataType()).toLowerCase();

                if (!typeName.contains("string")) continue;

                String value = String.valueOf(d.getValue());
                if (value == null || value.length() == 0) continue;

                String matched = matchedTerms(value);
                if (matched.length() == 0) continue;

                p("");
                p("LOCATOR HIT #" + (++hits));
                p("  address=" + d.getAddress());
                p("  type=" + d.getDataType());
                p("  terms=" + matched);
                p("  value=" + value);

                printDataStringXrefs(d, 24);
            }

            p("");
            p("STRING DATA ITEMS INSPECTED=" + inspected);
            p("LOCATOR HITS SHOWN=" + hits);
        }
        catch (Exception e) {
            p("STRING LOCATOR ERROR: " + e.getMessage());
        }
    }

    private static final String[] HIGH_VALUE_STRINGS = {
        "ftm_common_dispatch.c:",
        "ftm_rf_test_radio_config.c:",
        "ftm_rf_test_control.c:",
        "ftm_lte_rf_debug.c:",
        "ftm_lte_common_dispatch.c:",
        "ftm_nr5g_rf_test.c:",
        "ftm_nr5g_rf_debug",
        "rf_cmd_interface.c:",
        "rf_lte_cmd_proc.c:",
        "rflte_mc.c:",
        "RFA_RF_LTE_FDD_RX_CONFIG",
        "RFA_RF_LTE_TDD_RX_CONFIG",
        "ftm_common_dispatch",
        "FTM_PRI_ORDER"
    };

    private void inspectCodeXref(Address from, String context) {
        try {
            Function f = currentProgram.getFunctionManager()
                .getFunctionContaining(from);

            p("      CODE_XREF_CONTEXT=" + context);
            p("      FROM=" + from);
            p("      FUNCTION=" + (f == null ? "<no-function>" :
                f.getName() + " @ " + f.getEntryPoint()));
            p("      INSTRUCTION=" + instructionInfo(from.getOffset()));

            if (f != null) {
                ReferenceIterator it =
                    currentProgram.getReferenceManager()
                        .getReferencesTo(f.getEntryPoint());

                int callers = 0;
                while (it.hasNext() && callers < 16 && lines < MAX_LINES) {
                    if (monitor.isCancelled()) return;
                    Reference r = it.next();
                    if (r.getReferenceType().isCall()) {
                        p("      CALLER[" + callers + "]=" + r.getFromAddress()
                            + " " + instructionInfo(r.getFromAddress().getOffset()));
                        callers++;
                    }
                }
                p("      CALLERS_SHOWN=" + callers);
            }
        }
        catch (Exception e) {
            p("      CODE_XREF INSPECT ERROR: " + e.getMessage());
        }
    }

    private void inspectDataXrefNeighborhood(Address from, String context) {
        try {
            MemoryBlock b = block(from.getOffset());
            p("      DATA_XREF_CONTEXT=" + context);
            p("      FROM=" + from);
            p("      BLOCK=" + (b == null ? "<none>" : b.getName()));

            Data d = listing().getDataContaining(from);
            if (d != null) {
                p("      CONTAINING_DATA=" + d.getAddress()
                    + " len=" + d.getLength()
                    + " type=" + d.getDataType()
                    + " value=" + String.valueOf(d.getValue()));
            } else {
                p("      CONTAINING_DATA=<none>");
            }

            long center = from.getOffset();
            long start = center - 0x30L;
            long end = center + 0x50L;

            if (b != null) {
                if (start < b.getStart().getOffset()) start = b.getStart().getOffset();
                if (end > b.getEnd().getOffset()) end = b.getEnd().getOffset();
            } else {
                return;
            }

            p("      RAW_NEIGHBORHOOD=" + hex(start) + ".." + hex(end));

            for (long off = start; off <= end; off += 4L) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                if (!initialized(off, 4)) continue;

                long v = u32(off);
                String tag = "";

                MemoryBlock vb = block(v);
                if (vb != null) {
                    tag = vb.isExecute() ? " <EXEC_TARGET>" : " <MEM_TARGET>";
                }

                p(String.format("        %s -> %s%s",
                    hex(off), hex(v), tag));
            }
        }
        catch (Exception e) {
            p("      DATA_NEIGHBORHOOD ERROR: " + e.getMessage());
        }
    }

    private void scanHighValueStrings() {
        p("");
        p("============================================================");
        p("HIGH-VALUE FTM / RFA STRING TRACE");
        p("Exact module/function/RFA anchors from public Qualcomm material");
        p("Static only / READ ONLY");
        p("============================================================");

        int inspected = 0;
        int hits = 0;

        try {
            ghidra.program.model.listing.DataIterator it =
                currentProgram.getListing().getDefinedData(true);

            while (it.hasNext()
                    && inspected < 250000
                    && hits < 160
                    && lines < MAX_LINES) {

                if (monitor.isCancelled()) return;

                Data d = it.next();
                inspected++;

                String typeName =
                    String.valueOf(d.getDataType()).toLowerCase();
                if (!typeName.contains("string")) continue;

                String value = String.valueOf(d.getValue());
                if (value == null || value.length() == 0) continue;

                String matched = null;
                for (String term : HIGH_VALUE_STRINGS) {
                    if (containsIgnoreCase(value, term)) {
                        matched = term;
                        break;
                    }
                }

                if (matched == null) continue;

                hits++;

                p("");
                p("HIGH-VALUE HIT #" + hits);
                p("  address=" + d.getAddress());
                p("  matched=" + matched);
                p("  value=" + value);

                ReferenceIterator rit =
                    currentProgram.getReferenceManager()
                        .getReferencesTo(d.getAddress());

                int n = 0;
                while (rit.hasNext() && n < 32 && lines < MAX_LINES) {
                    if (monitor.isCancelled()) return;

                    Reference r = rit.next();
                    Address from = r.getFromAddress();

                    p(String.format(
                        "  XREF[%02d] from=%s type=%s primary=%s",
                        n, from, r.getReferenceType(), r.isPrimary()));

                    if (r.getReferenceType().isCall()
                            || r.getReferenceType().isRead()
                            || r.getReferenceType().isWrite()
                            || r.getReferenceType().isData()) {
                        if (from.getAddressSpace().isMemorySpace()) {
                            Function ff =
                                currentProgram.getFunctionManager()
                                    .getFunctionContaining(from);

                            if (ff != null) {
                                inspectCodeXref(from, value);
                            } else {
                                inspectDataXrefNeighborhood(from, value);
                            }
                        }
                    }

                    n++;
                }

                p("  XREFS_SHOWN=" + n);
            }

            p("");
            p("HIGH-VALUE DATA ITEMS INSPECTED=" + inspected);
            p("HIGH-VALUE HITS SHOWN=" + hits);
        }
        catch (Exception e) {
            p("HIGH-VALUE SCAN ERROR: " + e.getMessage());
        }
    }

    private void scanNamedFunctions() {
        p("");
        p("============================================================");
        p("FUNCTION NAME CENSUS: FTM / RFA / RFDEBUG / DIAG");
        p("============================================================");

        int inspected = 0;
        int hits = 0;

        try {
            FunctionIterator fit =
                currentProgram.getFunctionManager().getFunctions(true);

            while (fit.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                if (inspected++ >= 250000 || hits >= 320) return;

                Function f = fit.next();
                String n = f.getName();
                String low = n.toLowerCase();

                boolean match =
                    low.contains("ftm")
                    || low.contains("rfa")
                    || low.contains("rfdebug")
                    || low.contains("radio_config")
                    || low.contains("diag");

                if (!match) continue;

                p("  FUNC HIT #" + (++hits)
                    + " " + f.getName()
                    + " @ " + f.getEntryPoint());

                ReferenceIterator rit =
                    currentProgram.getReferenceManager()
                        .getReferencesTo(f.getEntryPoint());

                int callers = 0;
                while (rit.hasNext() && callers < 8 && lines < MAX_LINES) {
                    if (monitor.isCancelled()) return;
                    Reference r = rit.next();
                    if (r.getReferenceType().isCall()) {
                        p("      caller=" + r.getFromAddress());
                        callers++;
                    }
                }
            }

            p("FUNCTIONS INSPECTED=" + inspected);
            p("FUNCTION NAME HITS=" + hits);
        }
        catch (Exception e) {
            p("FUNCTION CENSUS ERROR: " + e.getMessage());
        }
    }

    private static final long[] SOURCE_ANCHOR_ADDRS = {
        0xC4736634L,  // ftm_common_dispatch.c
        0xC4737608L,  // ftm_nr5g_rf_debug_codebook_override.cpp
        0xC4737630L,  // ftm_nr5g_rf_debug_mpe_test.cpp
        0xC473764FL,  // ftm_nr5g_rf_debug_therm_read.cpp
        0xC4745B65L,  // FTM_PRI_ORDER
        0xC4952735L,  // ftm_common_dispatch.c (alternate string copy)
        0xC49CBF0AL   // ftm_nr5g_rf_debug_tx_override.c
    };

    private static final long[] TLV_NAME_ADDR_HINTS = {
        0xC414B5AEL,  // IQ_CAPTURE (from previous static report)
        0xC414B959L,  // FETCH_IQ
        0xC414BAEAL,  // IQ_CAPTURE_TYPE
        0xC414C000L   // range hint only; validated before use
    };

    private String anchorLabel(long target) {
        switch ((int)target) {
        case (int)0xC4736634L:
            return "ftm_common_dispatch.c";
        case (int)0xC4737608L:
            return "ftm_nr5g_rf_debug_codebook_override.cpp";
        case (int)0xC4737630L:
            return "ftm_nr5g_rf_debug_mpe_test.cpp";
        case (int)0xC473764FL:
            return "ftm_nr5g_rf_debug_therm_read.cpp";
        case (int)0xC4745B65L:
            return "FTM_PRI_ORDER";
        case (int)0xC4952735L:
            return "ftm_common_dispatch.c (copy)";
        case (int)0xC49CBF0AL:
            return "ftm_nr5g_rf_debug_tx_override.c";
        default:
            return hex(target);
        }
    }

    private void printMsgConstCandidate(long holder, long expectedFileNamePtr) {
        try {
            if (!initialized(holder, 16)) return;

            long fmtPtr = u32(holder);
            long filePtr = u32(holder + 4L);
            long packed = u32(holder + 8L);
            long argc = u32(holder + 12L);

            MemoryBlock fmtBlock = block(fmtPtr);
            MemoryBlock fileBlock = block(filePtr);

            boolean fileMatch = filePtr == expectedFileNamePtr;
            boolean fmtPlausible = fmtBlock != null && !fmtBlock.isExecute();
            boolean filePlausible = fileBlock != null && !fileBlock.isExecute();
            int ssid = (int)((packed >>> 16) & 0xffffL);
            int line = (int)(packed & 0xffffL);

            if (!fileMatch && !(fmtPlausible && filePlausible
                    && ssid >= 0 && ssid < 8192
                    && argc <= 64)) {
                return;
            }

            p("    MSG_CONST_CANDIDATE holder=" + hex(holder));
            p("      fmt_ptr=" + hex(fmtPtr)
                + " block=" + (fmtBlock == null ? "<none>" : fmtBlock.getName()));
            p("      fname_ptr=" + hex(filePtr)
                + " expected=" + hex(expectedFileNamePtr)
                + " match=" + fileMatch);
            p(String.format(
                "      packed=%s ssid=%d (0x%X) line=%d argc=%d",
                hex(packed), ssid, ssid, line, argc));

            if (fmtPtr != 0 && initialized(fmtPtr, 1)) {
                Data fd = listing().getDataContaining(addr(fmtPtr));
                if (fd != null) {
                    p("      fmt_data=" + String.valueOf(fd.getValue()));
                }
            }
        }
        catch (Exception e) {
            p("    MSG_CONST_CANDIDATE ERROR: " + e.getMessage());
        }
    }

    private int scanPointersInBlock(MemoryBlock b, long target, int maxMatches) {
        if (b == null || !b.isInitialized() || b.isExecute()) return 0;

        long start = b.getStart().getOffset();
        long end = b.getEnd().getOffset();

        byte[] buf = new byte[RAW_CHUNK];
        long pos = start;
        int matches = 0;

        try {
            while (pos <= end && matches < maxMatches) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return matches;

                int want = (int)Math.min((long)RAW_CHUNK, end - pos + 1L);
                memory().getBytes(addr(pos), buf, 0, want);

                for (int i = 0; i + 4 <= want && matches < maxMatches; i++) {
                    long v = ((long)(buf[i] & 0xff))
                        | ((long)(buf[i + 1] & 0xff) << 8)
                        | ((long)(buf[i + 2] & 0xff) << 16)
                        | ((long)(buf[i + 3] & 0xff) << 24);

                    if (v != target) continue;

                    long hit = pos + i;

                    p("  PTR_HIT target=" + hex(target)
                        + " (" + anchorLabel(target) + ")"
                        + " @ " + hex(hit)
                        + " aligned4=" + ((hit & 3L) == 0L));

                    long holderA = hit - 4L;
                    long holderB = hit - 8L;

                    p("    around(-4) u32/u32/u32/u32:");
                    for (long off = holderA; off <= holderA + 12L; off += 4L) {
                        if (!initialized(off, 4)) continue;
                        p("      " + hex(off) + " = " + hex(u32(off)));
                    }

                    printMsgConstCandidate(holderA, target);
                    printMsgConstCandidate(holderB, target);

                    matches++;
                }

                if (want <= 3) break;
                pos += (long)(want - 3);
            }
        }
        catch (Exception e) {
            p("  PTR SCAN ERROR block=" + b.getName()
                + " target=" + hex(target) + ": " + e.getMessage());
        }

        return matches;
    }

    private void scanSourceAnchorPointers() {
        p("");
        p("============================================================");
        p("SOURCE / MSG_CONST POINTER TRACE");
        p("Uses source-file strings as anchors; checks Qualcomm 16-byte msg_const shape");
        p("Expected shape: fmt_ptr, fname_ptr, (ssid<<16)|line, argc");
        p("READ ONLY / HARD LIMITED");
        p("============================================================");

        int totalTargets = 0;
        int totalMatches = 0;

        for (long target : SOURCE_ANCHOR_ADDRS) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            MemoryBlock tb = block(target);
            if (tb == null || !tb.isInitialized()) {
                p("TARGET " + hex(target) + " (" + anchorLabel(target)
                    + ") block=<none>");
                continue;
            }

            p("");
            p("TARGET STRING " + hex(target) + " " + anchorLabel(target));
            p("  block=" + tb.getName()
                + " range=" + tb.getStart() + ".." + tb.getEnd());

            int m = scanPointersInBlock(tb, target, 96);
            totalMatches += m;
            totalTargets++;

            if (m == 0) {
                p("  No local-block pointers. Skipping global fallback.");
            }
        }

        p("");
        p("SOURCE TARGETS INSPECTED=" + totalTargets);
        p("SOURCE POINTER MATCHES=" + totalMatches);
    }

    private void scanExactRfConstants() {
        p("");
        p("============================================================");
        p("EXACT RF CONSTANT TRACE");
        p("Read-only search for 821237500 Hz and related static constants");
        p("No command generation");
        p("============================================================");

        long[] vals = {
            821237500L,
            0x30F316FCL,
            821222652L,
            0x30F2DCDCL
        };

        String[] names = {
            "TARGET_HZ",
            "TARGET_HEX",
            "NEARBY_HISTORICAL_HZ",
            "NEARBY_HISTORICAL_HEX"
        };

        int hits = 0;

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || b.isExecute()) continue;

            byte[] buf = new byte[RAW_CHUNK];
            long pos = b.getStart().getOffset();
            long end = b.getEnd().getOffset();

            try {
                while (pos <= end && hits < 128) {
                    if (monitor.isCancelled() || lines >= MAX_LINES) return;

                    int want = (int)Math.min((long)RAW_CHUNK, end - pos + 1L);
                    memory().getBytes(addr(pos), buf, 0, want);

                    for (int i = 0; i + 4 <= want && hits < 128; i++) {
                        long v = ((long)(buf[i] & 0xff))
                            | ((long)(buf[i + 1] & 0xff) << 8)
                            | ((long)(buf[i + 2] & 0xff) << 16)
                            | ((long)(buf[i + 3] & 0xff) << 24);

                        for (int k = 0; k < vals.length; k++) {
                            if (v != vals[k]) continue;

                            long hit = pos + i;
                            p("  RF_CONSTANT_HIT @ " + hex(hit)
                                + " block=" + b.getName()
                                + " kind=" + names[k]
                                + " value=" + hex(v)
                                + " aligned4=" + ((hit & 3L) == 0L));
                            p("      function=" + functionInfo(hit));

                            hits++;
                        }
                    }

                    if (want <= 3) break;
                    pos += (long)(want - 3);
                }
            }
            catch (Exception e) {
                p("  RF CONSTANT SCAN ERROR block=" + b.getName()
                    + " " + e.getMessage());
            }
        }

        p("RF CONSTANT HITS=" + hits);
    }

    private void printReferences(long target, int maxRefs) {
        p("");
        p("REFERENCES TO " + hex(target));

        try {
            ReferenceManager rm = currentProgram.getReferenceManager();
            ReferenceIterator it = rm.getReferencesTo(addr(target));

            int n = 0;
            while (it.hasNext() && n < maxRefs && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;

                Reference r = it.next();
                Address from = r.getFromAddress();

                String kind = r.getReferenceType().toString();
                String srcType = from.getAddressSpace().isMemorySpace()
                    ? "MEM" : from.getAddressSpace().getName();

                p(String.format(
                    "  #%03d from=%s type=%s source=%s primary=%s",
                    n, from, kind, srcType, r.isPrimary()));

                if (r.getReferenceType().isCall()) {
                    p("       caller=" + functionInfo(from.getOffset()));
                }
                else if (from.getAddressSpace().isMemorySpace()) {
                    p("       ins=" + instructionInfo(from.getOffset()));
                }

                n++;
            }

            p("  TOTAL_SHOWN=" + n + " (limit=" + maxRefs + ")");
        }
        catch (Exception e) {
            p("  REFS ERROR: " + e.getMessage());
        }
    }

    private void dumpWindow(long center, int radius, String name) {
        p("");
        p("============================================================");
        p("RAW WINDOW: " + name + " @ " + hex(center));
        p("RANGE " + hex(center - radius) + " .. " + hex(center + radius));
        p("============================================================");

        long start = center - radius;
        long end = center + radius;

        if (!initialized(start, (int)(end - start + 1L))) {
            MemoryBlock b = block(center);
            p("WINDOW NOT FULLY INITIALIZED");
            p("CENTER BLOCK=" + (b == null ? "<none>" : b.getName()));
            if (b != null) {
                p("BLOCK RANGE=" + b.getStart() + " .. " + b.getEnd());
                p("BLOCK EXEC=" + b.isExecute() + " INIT=" + b.isInitialized());
            }
            return;
        }

        p("BLOCK=" + block(center).getName());
        p("CENTER DATA:");
        printDataInfo(center);

        byte[] row = new byte[16];

        for (long line = start; line <= end; line += 16L) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            int want = (int)Math.min(16L, end - line + 1L);
            try {
                byte[] tmp = new byte[want];
                memory().getBytes(addr(line), tmp);

                StringBuilder b = new StringBuilder();
                b.append(String.format("%s  ", hex(line)));
                b.append(String.format("%-47s", byteString(tmp)));
                b.append("  |").append(asciiPreview(tmp)).append("|");
                p(b.toString());

                if (line + 16L <= end && (line & 0xfL) == 0) {
                    try {
                        long v32 = u32(line);
                        p(String.format("       +00 u32=%s", hex(v32)));
                    }
                    catch (Exception ignored) {
                    }
                }
            }
            catch (Exception e) {
                p("  DUMP ERROR @" + hex(line) + ": " + e.getMessage());
                return;
            }
        }

        p("");
        p("ALIGNED 16-BIT / 32-BIT / 64-BIT VIEW");

        long a16 = (start + 1L) & ~1L;
        int shown16 = 0;
        for (long off = a16; off + 1L <= end && shown16 < 64; off += 2L) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            try {
                p(String.format("  %s u16=%s", hex(off), hex(u16(off))));
                shown16++;
            }
            catch (Exception ignored) {
            }
        }

        long a32 = (start + 3L) & ~3L;
        int shown32 = 0;
        for (long off = a32; off + 3L <= end && shown32 < 64; off += 4L) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            try {
                p(String.format("  %s u32=%s", hex(off), hex(u32(off))));
                shown32++;
            }
            catch (Exception ignored) {
            }
        }

        long a64 = (start + 7L) & ~7L;
        int shown64 = 0;
        for (long off = a64; off + 7L <= end && shown64 < 32; off += 8L) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            try {
                p(String.format("  %s u64=%s", hex(off), hex64(u64(off))));
                shown64++;
            }
            catch (Exception ignored) {
            }
        }
    }

    private boolean fourBytesEqual(byte[] buf, int i, long value) {
        if (i + 4 > buf.length) return false;

        return (buf[i]     & 0xff) == (int)(value & 0xff)
            && (buf[i + 1] & 0xff) == (int)((value >>> 8) & 0xff)
            && (buf[i + 2] & 0xff) == (int)((value >>> 16) & 0xff)
            && (buf[i + 3] & 0xff) == (int)((value >>> 24) & 0xff);
    }

    private String refName(long value) {
        if (value == REF_MASTER) return "MASTER";
        if (value == REF_TABLE) return "FTM_TABLE";
        if (value == REF_DISP) return "COMMON_DISPATCH";
        if (value == REF_TABLE2) return "FTM_TABLE_CMD08";
        if (value == REF_DISP2) return "COMMON_DISPATCH_CMD08";
        if (value == REF_DISP3) return "COMMON_DISPATCH_ALT";
        return null;
    }

    private void rawPointerScan(String blockName, long target, long maxBytes) {
        MemoryBlock b = currentProgram.getMemory().getBlock(blockName);
        if (b == null || !b.isInitialized() || b.isExecute()) {
            p("RAW SCAN SKIP " + blockName + " target=" + hex(target));
            return;
        }

        long start = b.getStart().getOffset();
        long end = b.getEnd().getOffset();
        long total = end - start + 1L;
        if (total > maxBytes) {
            total = maxBytes;
            end = start + total - 1L;
        }

        p("");
        p("RAW POINTER SCAN block=" + blockName
            + " target=" + hex(target)
            + " bytes=" + total);

        byte[] buf = new byte[RAW_CHUNK];
        long pos = start;
        long matches = 0;

        try {
            while (pos <= end && matches < 128) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                int want = (int)Math.min((long)RAW_CHUNK, end - pos + 1L);
                memory().getBytes(addr(pos), buf, 0, want);

                for (int i = 0; i + 4 <= want; i++) {
                    if ((matches >= 128) || monitor.isCancelled() || lines >= MAX_LINES) return;

                    if (fourBytesEqual(buf, i, target)) {
                        long hit = pos + i;
                        p(String.format(
                            "  HIT %s @%s block=%s aligned4=%s function=%s",
                            hex(target), hex(hit), blockName,
                            ((hit & 3L) == 0L),
                            functionInfo(hit)));
                        matches++;
                    }
                }

                // 3-byte overlap prevents missing a little-endian 4-byte value
                // crossing a chunk boundary.
                if (want <= 3) break;
                pos += (long)(want - 3);
            }

            p("RAW SCAN MATCHES=" + matches);
        }
        catch (Exception e) {
            p("RAW SCAN ERROR: " + e.getMessage());
        }
    }

    private void scanReferencePointers() {
        String[] blocks = { "segment_19", "segment_21" };
        long[] targets = {
            REF_MASTER, REF_TABLE, REF_DISP,
            REF_TABLE2, REF_DISP2, REF_DISP3
        };

        p("");
        p("============================================================");
        p("LOCAL RAW POINTER SCAN");
        p("Only segment_19 / segment_21; bounded; little-endian 32-bit");
        p("============================================================");

        for (String b : blocks) {
            for (long t : targets) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                rawPointerScan(b, t, MAX_RAW_SCAN_BYTES);
            }
        }
    }

    private void inspectAddress(long off, String label) {
        p("");
        p("------------------------------------------------------------");
        p(label + " " + hex(off));
        MemoryBlock b = block(off);
        p("mapped=" + (b != null)
            + " block=" + (b == null ? "<none>" : b.getName())
            + " exec=" + (b != null && b.isExecute())
            + " init=" + (b != null && b.isInitialized()));
        if (b != null) {
            p("block_range=" + b.getStart() + " .. " + b.getEnd());
            printBlockDetails(b);
        }

        try {
            p("function=" + functionInfo(off));
            p("instruction=" + instructionInfo(off));
        }
        catch (Exception ignored) {
        }

        printDataInfo(off);
        printReferences(off, MAX_REFS);
    }

    @Override
    public void run() throws Exception {
        p("============================================================");
        p(" Ghidra_RFDEBUG_Trace");
        p(" TRACE_BUILD=" + TRACE_BUILD);
        p(" DIAG -> FTM TARGET ADDRESS INSPECTOR / READ ONLY");
        p("============================================================");

        p("PROGRAM=" + currentProgram.getName());
        p("IMAGE_BASE=" + currentProgram.getImageBase());
        p("REFERENCE MASTER=" + hex(REF_MASTER));
        p("REFERENCE FTM_TABLE=" + hex(REF_TABLE));
        p("REFERENCE COMMON_DISPATCH=" + hex(REF_DISP));

        inspectAddress(REF_MASTER, "MASTER");
        inspectAddress(REF_TABLE, "FTM_TABLE");
        inspectAddress(REF_DISP, "COMMON_DISPATCH");
        inspectAddress(REF_TABLE2, "FTM_TABLE_CMD08");
        inspectAddress(REF_DISP2, "COMMON_DISPATCH_CMD08");
        inspectAddress(REF_DISP3, "COMMON_DISPATCH_ALT");

        dumpWindow(REF_MASTER, DUMP_MASTER_RADIUS, "DIAG MASTER CANDIDATE");
        dumpWindow(REF_TABLE, DUMP_TABLE_RADIUS, "FTM TABLE CANDIDATE");

        localNonZeroScan(REF_MASTER, LOCAL_ZERO_RADIUS, "MASTER 0xC8DC3B54");
        localNonZeroScan(REF_TABLE, LOCAL_ZERO_RADIUS, "FTM_TABLE 0xC37BD1E8");

        scanHighValueStrings();

        scanNamedFunctions();

        scanSourceAnchorPointers();

        scanExactRfConstants();

                scanFtmLocatorStrings();

        scanReferencePointers();

        p("");
        p("============================================================");
        p("INTERPRETATION GUIDE");
        p("============================================================");
        p("1. First determine whether C8DC3B54/C37BD1E8 are real structures.");
        p("2. Prefer actual XREFs over guessed table layouts.");
        p("3. If D8150ED8 occurs as a raw pointer in segment_19/21,");
        p("   record the exact slot and surrounding bytes.");
        p("4. If it does not, treat the published address as build/image-");
        p("   dependent until another image is identified.");
        p("5. A code XREF from a function into C37BD1E8 is the key next step.");
        p("6. FTM/RFA/DIAG strings with code XREFs are now the primary locator evidence.");
        p("7. Source-string pointer hits with a plausible msg_const shape are the strongest current-build anchor.");
        p("8. Exact RF constants are corroborative only; absence does not exclude runtime frequency handling.");
        p("9. If localNonZeroScan is entirely zero, inspect block metadata/source info.");
        p("");
        p("DONE");
        p("No program data or structures modified.");
    }
}
