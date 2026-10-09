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

    private static final String TRACE_BUILD = "DIAG-FTM-STRUCTURE-6";

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
        "CENTER_FREQ",
        "RX_CARRIER",
        "TX_CARRIER",
        "TECH_MODE",
        "SUB_TECH",
        "TECHNOLOGY",
        "RFM_DEVICE",
        "BANDWIDTH",
        "SIG_PATH",
        "ANT_PATH",
        "RX_TUNE",
        "RFA_RF_LTE_FDD_RX_CONFIG",
        "RFA_RF_LTE_TDD_RX_CONFIG",
        "ftm_rf_test_radio_config.c:",
        "ftm_rf_test_rx_measure.c:",
        "ftm_rf_test_control.c:",
        "ftm_rf_test_tx_control.c:",
        "ftm_lte_rf_debug.c:",
        "ftm_lte_common_dispatch.c:",
        "ftm_lte_rf_test.c:",
        "ftm_nr5g_rf_test.c:",
        "ftm_nr5g_rf_debug",
        "rf_cmd_interface.c:",
        "rf_lte_cmd_proc.c:",
        "rflte_mc.c:",
        "RADIO_CONFIG",
        "ftm_common_dispatch.c:",
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



    // Decode little-endian values directly from a chunk buffer.
    private long bufferU32(byte[] buf, int i) {
        return ((long)(buf[i] & 0xff))
            | ((long)(buf[i + 1] & 0xff) << 8)
            | ((long)(buf[i + 2] & 0xff) << 16)
            | ((long)(buf[i + 3] & 0xff) << 24);
    }

    private String readAsciiAt(long off, int maxLen) {
        try {
            MemoryBlock b = block(off);
            if (b == null || !b.isInitialized() || b.isExecute()) return null;
            if (off < b.getStart().getOffset() || off > b.getEnd().getOffset()) return null;

            int want = (int)Math.min((long)maxLen, b.getEnd().getOffset() - off + 1L);
            if (want <= 0) return null;

            byte[] buf = new byte[want];
            memory().getBytes(addr(off), buf, 0, want);

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

    private boolean isRelevantRfSourceName(String source) {
        if (source == null) return false;

        String s = source.toLowerCase();
        if (!s.endsWith(".c") && !s.endsWith(".cpp")) return false;

        return s.contains("ftm_common_dispatch")
            || s.contains("ftm_rf_test")
            || s.contains("ftm_lte")
            || s.contains("ftm_nr5g_rf")
            || s.contains("ftm_rfnv")
            || s.contains("ftm_multi_tech")
            || s.contains("rflte")
            || s.contains("rf_cmd_interface");
    }

    private boolean isScanableStaticBlock(MemoryBlock b) {
        if (b == null || !b.isInitialized()) return false;
        if (b.getStart().getOffset() < 0x1000L) return false;

        String name = b.getName();
        if (name == null) return true;

        return !name.startsWith("_elf") && !name.startsWith("unallocated_");
    }



    private static final String[] EXACT_RF_FIELD_NAMES = {
        "CENTER_FREQ", "RX_CARRIER", "TX_CARRIER", "TECH_MODE",
        "SUB_TECH", "TECHNOLOGY", "RFM_DEVICE", "BANDWIDTH",
        "CHANNEL", "SIG_PATH", "ANT_PATH", "USER_ADJ", "TOTAL_ADJ",
        "ENABLE_XO", "SAMP_FREQ", "FREQ_ADJUST", "FREQADJUST",
        "RADIO_CONFIG", "RX_TUNE", "BAND"
    };

    private boolean isExactRfFieldName(String value) {
        if (value == null) return false;
        String normalized = value.trim().toUpperCase();
        for (String name : EXACT_RF_FIELD_NAMES) {
            if (normalized.equals(name)) return true;
        }
        return false;
    }

    private boolean isRfFrequencyContext(String value) {
        if (value == null || value.length() > 320) return false;
        String low = value.toLowerCase();
        return low.contains("center_freq")
            || low.contains("rx_carrier")
            || low.contains("tx_carrier")
            || low.contains("freqadjust")
            || low.contains("freq adjust")
            || low.contains("frequency")
            || low.contains("dl freq")
            || low.contains("rx_tune")
            || low.contains("radio_config")
            || low.contains("samp_freq")
            || low.contains("ftm.rf")
            || low.contains("rflte_ftm_mc_set_trx_on_off");
    }

    private void scanRfTuneFieldStrings() {
        p("");
        p("============================================================");
        p("TARGETED RF TUNE / FREQUENCY STRING SCAN");
        p("Separate from broad CHANNEL search to avoid generic-string flooding");
        p("Exact field labels plus frequency/tuning context; static read-only");
        p("============================================================");

        int inspected = 0;
        int exactHits = 0;
        int contextHits = 0;
        int reported = 0;
        final int MAX_EXACT = 100;
        final int MAX_CONTEXT = 80;
        final int MAX_TOTAL = 160;

        try {
            ghidra.program.model.listing.DataIterator it =
                currentProgram.getListing().getDefinedData(true);

            while (it.hasNext()
                    && inspected < 300000
                    && reported < MAX_TOTAL
                    && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;

                Data d = it.next();
                inspected++;

                String typeName = String.valueOf(d.getDataType()).toLowerCase();
                if (!typeName.contains("string")) continue;

                String value = String.valueOf(d.getValue());
                if (value == null || value.length() == 0) continue;

                boolean exact = isExactRfFieldName(value);
                boolean context = !exact && isRfFrequencyContext(value);

                if (exact && exactHits >= MAX_EXACT) continue;
                if (context && contextHits >= MAX_CONTEXT) continue;
                if (!exact && !context) continue;

                if (exact) exactHits++;
                else contextHits++;
                reported++;

                p("");
                p("RF_TUNE_STRING #" + reported
                    + " kind=" + (exact ? "EXACT_FIELD" : "FREQ_CONTEXT"));
                p("  address=" + d.getAddress());
                p("  type=" + d.getDataType());
                p("  value=" + value);

                ReferenceIterator refs =
                    currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                int refCount = 0;
                while (refs.hasNext() && refCount < 8 && lines < MAX_LINES) {
                    if (monitor.isCancelled()) return;
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    p("  XREF[" + refCount + "] from=" + from
                        + " type=" + ref.getReferenceType());
                    if (from.getAddressSpace().isMemorySpace()
                            && currentProgram.getFunctionManager()
                                .getFunctionContaining(from) != null) {
                        p("    function=" + functionInfo(from.getOffset()));
                        p("    instruction=" + instructionInfo(from.getOffset()));
                    }
                    refCount++;
                }
                p("  XREFS_SHOWN=" + refCount);
            }

            p("");
            p("RF_TUNE_DATA_ITEMS_INSPECTED=" + inspected);
            p("RF_TUNE_EXACT_FIELD_HITS=" + exactHits);
            p("RF_TUNE_CONTEXT_HITS=" + contextHits);
            p("RF_TUNE_TOTAL_REPORTED=" + reported);
        }
        catch (Exception e) {
            p("RF_TUNE STRING SCAN ERROR: " + e.getMessage());
        }
    }

    private void dumpStaticWordNeighborhood(long center, int radius, String label) {
        p("");
        p("============================================================");
        p("STATIC POINTER NEIGHBORHOOD: " + label + " @ " + hex(center));
        p("Aligned u32 words around the non-table handler-pointer candidate");
        p("============================================================");

        long start = center - radius;
        long end = center + radius;
        MemoryBlock b = block(center);

        if (b == null || !b.isInitialized()) {
            p("  CENTER_BLOCK=<none>");
            return;
        }

        if (start < b.getStart().getOffset()) start = b.getStart().getOffset();
        if (end > b.getEnd().getOffset()) end = b.getEnd().getOffset();

        start = (start + 3L) & ~3L;
        for (long off = start; off + 3L <= end; off += 4L) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            try {
                long value = u32(off);
                MemoryBlock vb = block(value);
                String tag = "";
                if (value == CURRENT_RUNTIME_DISPATCH) tag = " <CURRENT_HANDLER_VALUE>";
                else if (value == PREVIOUS_BUILD_DISPATCH) tag = " <OLD_HANDLER_VALUE>";
                else if (vb != null) tag = vb.isExecute()
                    ? " <POINTER_TO_EXEC_BLOCK:" + vb.getName() + ">"
                    : " <POINTER_TO_DATA_BLOCK:" + vb.getName() + ">";

                String pointedText = "";
                if (vb != null && !vb.isExecute()) {
                    String text = readAsciiAt(value, 96);
                    if (text != null) pointedText = " text=\"" + text + "\"";
                }

                p("  " + hex(off) + " = " + hex(value) + tag + pointedText);
            }
            catch (Exception e) {
                p("  WORD_READ_ERROR @ " + hex(off) + ": " + e.getMessage());
            }
        }
    }

    private static final long CURRENT_RUNTIME_DISPATCH = 0xD819C208L;
    private static final long PREVIOUS_BUILD_DISPATCH = 0xD8150ED8L;
    private static final long CURRENT_FTM_TABLE = 0xC4951828L;
    private static final int CURRENT_FTM_TABLE_COUNT = 80;
    private static final long MAX_POINTER_SCAN_BYTES = 0x80000000L;

    private String currentDispatchPointerRole(long hit) {
        long firstHandler = CURRENT_FTM_TABLE + 4L;
        long delta = hit - firstHandler;

        if (delta >= 0L && (delta % 8L) == 0L) {
            long index = delta / 8L;
            if (index >= 0L && index < CURRENT_FTM_TABLE_COUNT) {
                try {
                    long entry = CURRENT_FTM_TABLE + index * 8L;
                    int lo = u16(entry);
                    int hi = u16(entry + 2L);
                    return String.format(
                        "FTM_TABLE_ENTRY index=%d selector_lo=0x%04X selector_hi=0x%04X",
                        index, lo, hi);
                }
                catch (Exception e) {
                    return "FTM_TABLE_ENTRY index=" + index + " selector=<read-error>";
                }
            }
        }

        return "EXTERNAL_OR_NON_TABLE_REFERENCE";
    }

    private void scanRuntimeDispatchPointers() {
        p("");
        p("============================================================");
        p("RUNTIME DISPATCH POINTER CENSUS");
        p("Searches aligned 32-bit references throughout initialized blocks");
        p("Targets: current candidate 0xD819C208 and prior-build 0xD8150ED8");
        p("Current table context: 0xC4951828, 80 entries; non-table hits are called out");
        p("READ ONLY / NO COMMAND GENERATION");
        p("============================================================");

        long[] targets = {
            CURRENT_RUNTIME_DISPATCH,
            PREVIOUS_BUILD_DISPATCH
        };
        String[] labels = {
            "CURRENT_FTM_HANDLER",
            "PREVIOUS_BUILD_HANDLER"
        };

        long scanned = 0;
        int[] grandCounts = new int[targets.length];

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!isScanableStaticBlock(b)) continue;

            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset();
            int[] blockCounts = new int[targets.length];
            int[] storedCounts = new int[targets.length];
            long[][] storedHits = new long[targets.length][256];

            byte[] buf = new byte[RAW_CHUNK];
            long pos = start;

            try {
                while (pos <= end && scanned < MAX_POINTER_SCAN_BYTES) {
                    if (monitor.isCancelled() || lines >= MAX_LINES) return;

                    int want = (int)Math.min((long)RAW_CHUNK, end - pos + 1L);
                    if (want < 4) break;
                    memory().getBytes(addr(pos), buf, 0, want);

                    for (int i = 0; i + 4 <= want; i++) {
                        long at = pos + i;
                        if ((at & 3L) != 0L) continue;

                        long value = bufferU32(buf, i);
                        for (int t = 0; t < targets.length; t++) {
                            if (value != targets[t]) continue;

                            blockCounts[t]++;
                            grandCounts[t]++;

                            if (storedCounts[t] < storedHits[t].length) {
                                storedHits[t][storedCounts[t]++] = at;
                            }
                        }
                    }

                    long advance = want - 3L;
                    if (advance <= 0L) break;
                    pos += advance;
                    scanned += advance;
                }
            }
            catch (Exception e) {
                p("  PTR_SCAN_BLOCK_ERROR block=" + b.getName()
                    + " range=" + hex(start) + ".." + hex(end)
                    + " error=" + e.getMessage());
            }

            boolean found = false;
            for (int t = 0; t < targets.length; t++) {
                if (blockCounts[t] == 0) continue;
                found = true;

                p("  PTR_BLOCK target=" + labels[t]
                    + " value=" + hex(targets[t])
                    + " block=" + b.getName()
                    + " exec=" + b.isExecute()
                    + " hits_in_block=" + blockCounts[t]);

                for (int k = 0; k < storedCounts[t]; k++) {
                    long hit = storedHits[t][k];
                    String role = currentDispatchPointerRole(hit);
                    p("    PTR_HIT[" + k + "] at=" + hex(hit)
                        + " role=" + role
                        + " function=" + functionInfo(hit));

                    if (role.equals("EXTERNAL_OR_NON_TABLE_REFERENCE")) {
                        dumpStaticWordNeighborhood(hit, 0x30,
                            labels[t] + "_NON_TABLE_HIT_" + hex(hit));
                    }

                    if (b.isExecute()) {
                        p("      instruction=" + instructionInfo(hit));
                    }
                }

                if (blockCounts[t] > storedCounts[t]) {
                    p("    ADDITIONAL_HITS_NOT_LISTED="
                        + (blockCounts[t] - storedCounts[t]));
                }
            }
        }

        p("POINTER_SCAN_BYTES_APPROX=" + scanned);
        p("POINTER_TOTAL " + labels[0] + "=" + grandCounts[0]);
        p("POINTER_TOTAL " + labels[1] + "=" + grandCounts[1]);
    }

    private void scanRfMsgConstRecords() {
        p("");
        p("============================================================");
        p("RFTEST MSG_CONST RECORD DISCOVERY");
        p("Looks for {fmt_ptr, fname_ptr, (ssid<<16)|line, argc} records");
        p("Reports only relevant FTM/RF source files; static read-only");
        p("============================================================");

        long scanned = 0;
        int candidates = 0;
        int reported = 0;
        final int MAX_REPORTS = 180;
        final long MAX_MSG_SCAN_BYTES = 0x80000000L;

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!isScanableStaticBlock(b) || b.isExecute()) continue;

            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset();
            byte[] buf = new byte[RAW_CHUNK];
            long pos = start;
            long lastProcessedCandidate = start - 4L;
            int blockReports = 0;

            try {
                while (pos <= end
                        && scanned < MAX_MSG_SCAN_BYTES
                        && reported < MAX_REPORTS) {
                    if (monitor.isCancelled() || lines >= MAX_LINES) return;

                    int want = (int)Math.min((long)RAW_CHUNK, end - pos + 1L);
                    if (want < 16) break;
                    memory().getBytes(addr(pos), buf, 0, want);

                    int firstAligned = (int)((4L - (pos & 3L)) & 3L);

                    for (int i = firstAligned; i + 16 <= want; i += 4) {
                        long holder = pos + i;
                        if (holder <= lastProcessedCandidate) continue;

                        long fmtPtr = bufferU32(buf, i);
                        long filePtr = bufferU32(buf, i + 4);
                        long packed = bufferU32(buf, i + 8);
                        long argcValue = bufferU32(buf, i + 12);

                        if (fmtPtr == 0L || filePtr == 0L || argcValue > 16L) continue;
                        if (!validDataPointer(filePtr) || !validDataPointer(fmtPtr)) continue;

                        int ssid = (int)((packed >>> 16) & 0xffffL);
                        int line = (int)(packed & 0xffffL);
                        if (ssid < 1 || ssid > 0x100 || line < 1 || line > 0x7fff) continue;

                        String file = readAsciiAt(filePtr, 160);
                        if (!isRelevantRfSourceName(file)) continue;

                        String fmt = readAsciiAt(fmtPtr, 320);
                        if (fmt == null || fmt.length() == 0) continue;

                        candidates++;
                        if (reported < MAX_REPORTS) {
                            p("");
                            p("MSG_CONST_HIT #" + (reported + 1)
                                + " holder=" + hex(holder)
                                + " block=" + b.getName());
                            p("  fmt_ptr=" + hex(fmtPtr));
                            p("  fname_ptr=" + hex(filePtr));
                            p("  source=" + file);
                            p("  packed=" + hex(packed)
                                + " ssid=" + ssid
                                + " line=" + line
                                + " argc=" + argcValue);
                            p("  format=" + fmt);
                            reported++;
                            blockReports++;
                        }
                    }

                    long highestCompleteStart = pos + want - 16L;
                    if (highestCompleteStart > lastProcessedCandidate) {
                        lastProcessedCandidate = highestCompleteStart;
                    }

                    long advance = want - 15L;
                    if (advance <= 0L) break;
                    pos += advance;
                    scanned += advance;
                }
            }
            catch (Exception e) {
                p("  MSG_CONST_SCAN_BLOCK_ERROR block=" + b.getName()
                    + " range=" + hex(start) + ".." + hex(end)
                    + " error=" + e.getMessage());
            }

            if (blockReports > 0) {
                p("  MSG_CONST_BLOCK_SUMMARY block=" + b.getName()
                    + " reported=" + blockReports);
            }
        }

        p("");
        p("MSG_CONST_CANDIDATES_FOUND=" + candidates);
        p("MSG_CONST_RECORDS_REPORTED=" + reported);
        p("MSG_CONST_SCAN_BYTES_APPROX=" + scanned);
    }

    private static final long DIAG_REC_MAGIC0 = 0x00FF0000L;
    private static final long DIAG_REC_MAGIC2 = 0x000000FFL;
    private static final long DIAG_REC_MAGIC3 = 0xFFFFFFFFL;
    private static final int TARGET_FTM_SUBSYS = 0x000B;
    private static final int MAX_MASTER_RECORD_HITS = 64;
    private static final long MAX_MASTER_SCAN_BYTES = 0x80000000L;

    private boolean validDataPointer(long value) {
        MemoryBlock b = block(value);
        return b != null && b.isInitialized() && !b.isExecute();
    }

    private void dumpFtmTableCandidate(long table, int count) {
        p("    FTM_TABLE_CANDIDATE=" + hex(table) + " count=" + count);

        if (!validDataPointer(table)) {
            p("      table_valid=false");
            return;
        }

        MemoryBlock b = block(table);
        p("      table_block=" + b.getName()
            + " range=" + b.getStart() + ".." + b.getEnd());

        int shown = 0;
        long[] handlerValues = new long[Math.min(count, 96)];
        int[] handlerCounts = new int[Math.min(count, 96)];
        int uniqueHandlers = 0;

        for (int i = 0; i < count && i < 96 && shown < 96; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            long p0 = table + (long)i * 8L;
            if (!initialized(p0, 8)) break;

            try {
                int lo = u16(p0);
                int hi = u16(p0 + 2L);
                long handler = u32(p0 + 4L);
                if (lo > hi) continue;

                MemoryBlock hb = block(handler);

                p(String.format(
                    "      entry[%02d] @%s lo=%s hi=%s handler=%s handler_block=%s",
                    i, hex(p0), hex(lo), hex(hi), hex(handler),
                    hb == null ? "<none>" : hb.getName()));

                int handlerSlot = -1;
                for (int j = 0; j < uniqueHandlers; j++) {
                    if (handlerValues[j] == handler) {
                        handlerSlot = j;
                        break;
                    }
                }
                if (handlerSlot < 0) {
                    handlerSlot = uniqueHandlers++;
                    handlerValues[handlerSlot] = handler;
                }
                handlerCounts[handlerSlot]++;

                shown++;
            }
            catch (Exception e) {
                p("      entry[" + i + "] ERROR=" + e.getMessage());
            }
        }

        p("      TABLE_VALID_ENTRIES_SHOWN=" + shown);
        p("      UNIQUE_HANDLER_POINTERS=" + uniqueHandlers);
        for (int i = 0; i < uniqueHandlers; i++) {
            MemoryBlock hb = block(handlerValues[i]);
            p("      HANDLER_SUMMARY[" + i + "] ptr=" + hex(handlerValues[i])
                + " count=" + handlerCounts[i]
                + " block=" + (hb == null ? "<none>" : hb.getName()));
        }
    }

    private void scanDiagMasterRecordsExact() {
        p("");
        p("============================================================");
        p("DIAG MASTER RECORD STRUCTURE SCAN");
        p("Independent Qualcomm FTM report structure:");
        p("[u32 0x00FF0000][u32 count<<16|subsys][u32 0xFF][u32 FFFFFFFF][u32 table]");
        p("Target subsys=0x000B; READ ONLY / HARD LIMITED");
        p("============================================================");

        long scanned = 0;
        int hits = 0;

        try {
            for (MemoryBlock b : memory().getBlocks()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                if (!isScanableStaticBlock(b) || b.isExecute()) continue;

                long start = b.getStart().getOffset();
                long end = b.getEnd().getOffset();

                p("MASTER_SCAN_BLOCK " + b.getName()
                    + " " + hex(start) + ".." + hex(end));

                byte[] buf = new byte[RAW_CHUNK];
                long pos = start;

                while (pos <= end
                        && scanned < MAX_MASTER_SCAN_BYTES
                        && hits < MAX_MASTER_RECORD_HITS) {

                    if (monitor.isCancelled() || lines >= MAX_LINES) return;

                    int want = (int)Math.min((long)RAW_CHUNK, end - pos + 1L);
                    memory().getBytes(addr(pos), buf, 0, want);

                    for (int i = 0; i + 20 <= want
                            && hits < MAX_MASTER_RECORD_HITS; i += 4) {

                        long p0 = pos + i;

                        long magic0 = ((long)(buf[i] & 0xff))
                            | ((long)(buf[i + 1] & 0xff) << 8)
                            | ((long)(buf[i + 2] & 0xff) << 16)
                            | ((long)(buf[i + 3] & 0xff) << 24);

                        if (magic0 != DIAG_REC_MAGIC0) continue;

                        long packed = ((long)(buf[i + 4] & 0xff))
                            | ((long)(buf[i + 5] & 0xff) << 8)
                            | ((long)(buf[i + 6] & 0xff) << 16)
                            | ((long)(buf[i + 7] & 0xff) << 24);

                        int subsys = (int)(packed & 0xffffL);
                        int count = (int)((packed >>> 16) & 0xffffL);

                        if (subsys != TARGET_FTM_SUBSYS || count < 1 || count > 256)
                            continue;

                        long magic2 = ((long)(buf[i + 8] & 0xff))
                            | ((long)(buf[i + 9] & 0xff) << 8)
                            | ((long)(buf[i + 10] & 0xff) << 16)
                            | ((long)(buf[i + 11] & 0xff) << 24);

                        if (magic2 != DIAG_REC_MAGIC2) continue;

                        long magic3 = ((long)(buf[i + 12] & 0xff))
                            | ((long)(buf[i + 13] & 0xff) << 8)
                            | ((long)(buf[i + 14] & 0xff) << 16)
                            | ((long)(buf[i + 15] & 0xff) << 24);

                        if (magic3 != DIAG_REC_MAGIC3) continue;

                        long table = ((long)(buf[i + 16] & 0xff))
                            | ((long)(buf[i + 17] & 0xff) << 8)
                            | ((long)(buf[i + 18] & 0xff) << 16)
                            | ((long)(buf[i + 19] & 0xff) << 24);

                        p("");
                        p("MASTER_RECORD_HIT #" + (++hits) + " @" + hex(p0));
                        p("  packed=" + hex(packed)
                            + " subsys=" + hex(subsys)
                            + " count=" + count);
                        p("  magic2=" + hex(magic2)
                            + " magic3=" + hex(magic3));
                        p("  table=" + hex(table)
                            + " valid=" + validDataPointer(table));

                        dumpFtmTableCandidate(table, count);
                    }

                    scanned += want;
                    if (want <= 0) break;
                    pos += want;
                }
            }
        }
        catch (Exception e) {
            p("MASTER STRUCTURE SCAN ERROR: " + e.getMessage());
        }

        p("");
        p("MASTER STRUCTURE BYTES SCANNED=" + scanned);
        p("MASTER STRUCTURE HITS=" + hits);
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

        inspectAddress(REF_MASTER, "MASTER_REFERENCE_ADDRESS");
        inspectAddress(REF_TABLE, "FTM_TABLE_REFERENCE_ADDRESS");

        scanDiagMasterRecordsExact();

        scanRuntimeDispatchPointers();

        scanRfMsgConstRecords();

        scanRfTuneFieldStrings();

        scanHighValueStrings();

        scanSourceAnchorPointers();

        // Exact-Hz literal scan was already negative; prioritize structural evidence here.

        p("");
        p("============================================================");
        p("INTERPRETATION GUIDE");
        p("============================================================");
        p("1. Current-build DIAG master hit: C8EB6EE0; table: C4951828; count: 80.");
        p("2. The 81st pointer hit must be evaluated from the printed neighboring words; it may be adjacent data, not a call reference.");
        p("3. Targeted RF tune strings are scanned separately so common CHANNEL strings cannot consume the output cap.");
        p("4. D8150ED8 is retained only as a previous-build comparison, not assumed current.");
        p("5. RFTEST msg_const records provide source filename, SSID, line, argc, and format text.");
        p("6. All scans are static and read-only; no DIAG packets are emitted.");
        p("7. Frequency selection is not inferred from a matching string alone; correlate field IDs and dispatch flow.");
        p("");
        p("DONE");
        p("No program data or structures modified.");
    }
}
