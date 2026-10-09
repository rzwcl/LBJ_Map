import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
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
 * TRACE_BUILD = DIAG-FTM-STRUCTURE-25
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

    private static final String TRACE_BUILD = "DIAG-FTM-STRUCTURE-25";

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

    // Compact end-of-run metrics make partial console captures diagnosable.
    private int summaryFieldStringsReadable = -1;
    private int summaryFieldReferenceMatches = -1;
    private int summaryFieldAnchorMismatches = -1;
    private long summarySlotInstructionRefs = -1L;
    private long summarySlotDataRefs = -1L;
    private long summaryExecutableInsnsScanned = -1L;
    private int summaryTableImmediateHits = -1;
    private int summaryTableNearbyHits = -1;
    private long summaryCurrentDispatchPointers = -1L;
    private long summaryPreviousDispatchPointers = -1L;
    private long summarySharedThunkPointers = -1L;
    private int summaryUniqueStringTargets = -1;
    private long summaryStringTargetCodeHits = -1L;
    private int summaryExecutableBlocks = -1;
    private int summaryExecutableBlocksSampled = -1;
    private long summaryRadioConfigMsgCandidates = -1L;
    private long summaryRadioConfigMsgReported = -1L;
    private long summaryRfDebugSubsysInstructionsScanned = -1L;
    private long summaryRfDebugSubsysImmediateHits = -1L;
    private long summaryTuneFieldStringsInspected = -1L;
    private long summaryTuneFieldStringsReported = -1L;
    private long summaryRegionPointerSlots = -1L;
    private long summaryRegionReadableStrings = -1L;
    private long summaryRegionNulls = -1L;
    private long summaryRegionUnreadable = -1L;
    private int summaryRegionGroups = -1;

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

    /**
     * The dynamic 614_0_0 scans create addresses through addr(), which always
     * uses the program's default address space. Exclude auxiliary spaces such
     * as ELF headers and unallocated blocks before passing their offsets there.
     */
    private boolean isDefaultDynamicAddressBlock(MemoryBlock b) {
        if (b == null) return false;
        try {
            Address start = b.getStart();
            Address end = b.getEnd();
            if (start == null || end == null) return false;

            ghidra.program.model.address.AddressSpace defaultSpace =
                currentProgram.getAddressFactory().getDefaultAddressSpace();
            return start.getAddressSpace().isMemorySpace()
                && start.getAddressSpace().equals(defaultSpace)
                && end.getAddressSpace().equals(defaultSpace);
        }
        catch (Exception e) {
            return false;
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
        p("FUNCTION NAME CENSUS: FTM / RFA / RFC / RFDEBUG / DIAG");
        p("Also tracks RF configuration APIs such as path_cfg, band_split, timing_cfg, and FBRX.");
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
                    || low.contains("rfc")
                    || low.contains("rfdebug")
                    || low.contains("radio_config")
                    || low.contains("diag")
                    || low.contains("path_cfg")
                    || low.contains("band_split")
                    || low.contains("timing_cfg")
                    || low.contains("fbrx")
                    || low.contains("antenna_path")
                    || low.contains("rffe_speeds")
                    || low.contains("rfm_path");

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







    private static final long RADIO_CONFIG_FIELD_NAME_TABLE = 0xC9199FB8L;
    private static final int RADIO_CONFIG_FIELD_NAME_COUNT = 38;
    private static final int ADJACENT_NAME_POOL_COUNT = 14;

    // Cross-build comparison labels only. Runtime strings read from this image
    // are the primary evidence; these labels are printed as a sanity check.
    private static final String[] RADIO_CONFIG_REFERENCE_LABELS = {
        "UNASSIGNED", "IS_TEARDOWN", "RADIO_SETUP_TYPE", "RFM_DEVICE",
        "SIG_PATH", "ANT_PATH", "RFM_PATH_TYPE", "BAND", "SUBBAND",
        "RESERVED", "CHANNEL", "WAVEFORM", "BANDWIDTH", "NUM_RB",
        "START_RB", "CW_OFFSET", "IS_DC", "MOD_TYPE", "LOOPBACK_TYPE",
        "BEAM_ID", "CC_INDEX", "CC_START_RB", "CC_NUM_RB", "CC_BANDWIDTH",
        "LOOPBACK_RFM_DEVICE", "PLL_ID", "TUNE_TX_TO_RX_FREQ", "LOAD_CODEBOOK",
        "FREQUENCY", "VERSION", "SWITCH_TDSCDMA_WAVEFORM", "SET_MOD",
        "CC_SCS", "WAVEFORM_ORIGIN", "NDR_STATE", "NR5G_MOD_TYPE",
        "WAVEFORM_IMMEDIATE_TRIGGER", "<NULL_TERMINATOR>"
    };

    private void printReferencesToAddress(long target, int limit, String label) {
        p("  ADDRESS_XREFS " + label + " target=" + hex(target));
        try {
            ReferenceIterator it =
                currentProgram.getReferenceManager().getReferencesTo(addr(target));
            int n = 0;
            while (it.hasNext() && n < limit && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;
                Reference r = it.next();
                Address from = r.getFromAddress();
                Function f = from.getAddressSpace().isMemorySpace()
                    ? currentProgram.getFunctionManager().getFunctionContaining(from)
                    : null;
                p("    XREF[" + n + "] from=" + from
                    + " type=" + r.getReferenceType()
                    + " function=" + (f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint()));
                if (f != null) p("      instruction=" + instructionInfo(from.getOffset()));
                n++;
            }
            p("    XREFS_SHOWN=" + n);
        }
        catch (Exception e) {
            p("    XREF_ERROR: " + e.getMessage());
        }
    }

    private void dumpRadioConfigFieldNameTable() {
        p("");
        p("============================================================");
        p("RADIO_CONFIG FIELD-NAME TABLE CANDIDATE");
        p("Candidate base=0xC9199FB8; 37 properties at indices 0..36 plus NULL at index 37; entry size=4");
        p("Confirmed anchors: property 26 TUNE_TX_TO_RX_FREQ at 0xC919A020; property 28 FREQUENCY at 0xC919A028.");
        p("The decoded strings in this image are authoritative; reference labels are cross-build comparison only.");
        p("Read-only; validates property IDs 26 and 28 and the NULL separator before the RX_OVERRIDE candidate table.");
        p("============================================================");

        long base = RADIO_CONFIG_FIELD_NAME_TABLE;
        MemoryBlock b = block(base);
        p("  table_block=" + (b == null ? "<none>" : b.getName())
            + " valid=" + initialized(base, RADIO_CONFIG_FIELD_NAME_COUNT * 4));
        if (!initialized(base, RADIO_CONFIG_FIELD_NAME_COUNT * 4)) {
            p("  TABLE_CANDIDATE_NOT_FULLY_INITIALIZED");
            return;
        }

        int readable = 0;
        int stringMatches = 0;
        int anchorMismatches = 0;
        int[] anchors = {26, 28, 34, 36};
        for (int i = 0; i < RADIO_CONFIG_FIELD_NAME_COUNT; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            long slot = base + (long)i * 4L;
            try {
                long ptr = u32(slot);
                String actual = readAsciiAt(ptr, 120);
                String refLabel = i < RADIO_CONFIG_REFERENCE_LABELS.length
                    ? RADIO_CONFIG_REFERENCE_LABELS[i] : "<none>";

                if (actual != null) readable++;
                if (actual != null
                        && actual.trim().equalsIgnoreCase(refLabel)) stringMatches++;

                boolean isAnchor = false;
                for (int a : anchors) if (a == i) isAnchor = true;
                if (isAnchor && (actual == null
                        || !actual.trim().equalsIgnoreCase(refLabel))) {
                    anchorMismatches++;
                }

                p(String.format(
                    "  FIELD[%02d] slot=%s ptr=%s actual=%s reference=%s match=%s",
                    i, hex(slot), hex(ptr),
                    actual == null ? "<unreadable>" : actual,
                    refLabel,
                    actual != null && actual.trim().equalsIgnoreCase(refLabel)));
            }
            catch (Exception e) {
                p("  FIELD[" + i + "] ERROR=" + e.getMessage());
            }
        }

        p("  PRIMARY_FIELD_ENTRIES=" + RADIO_CONFIG_FIELD_NAME_COUNT);
        p("  FIELD_STRINGS_READABLE=" + readable);
        p("  EXACT_REFERENCE_LABEL_MATCHES=" + stringMatches);
        p("  ANCHOR_MISMATCHES=" + anchorMismatches);
        summaryFieldStringsReadable = readable;
        summaryFieldReferenceMatches = stringMatches;
        summaryFieldAnchorMismatches = anchorMismatches;

        printReferencesToAddress(base, 24, "TABLE_BASE");
        printReferencesToAddress(base + 26L * 4L, 12, "PROPERTY_26_TUNE_TX_TO_RX_FREQ_SLOT");
        printReferencesToAddress(base + 28L * 4L, 12, "PROPERTY_28_FREQUENCY_SLOT");
        printReferencesToAddress(base + 34L * 4L, 12, "PROPERTY_34_NDR_STATE_SLOT");
        printReferencesToAddress(base + 36L * 4L, 12, "PROPERTY_36_WAVEFORM_IMMEDIATE_TRIGGER_SLOT");
    }



    private void dumpAdjacentRadioConfigNamePool() {
        long base = RADIO_CONFIG_FIELD_NAME_TABLE
            + (long)RADIO_CONFIG_FIELD_NAME_COUNT * 4L;
        p("");
        p("============================================================");
        p("RADIO_CONFIG ADJACENT NAME POOL CANDIDATE");
        p("Start=0xC919A050; RX_OVERRIDE property-name candidate; entries_checked=" + ADJACENT_NAME_POOL_COUNT);
        p("Candidate second property_names[] table; initial entries should be compared with RX_OVERRIDE property IDs.");
        p("============================================================");

        for (int i = 0; i < ADJACENT_NAME_POOL_COUNT; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            long slot = base + (long)i * 4L;
            try {
                long ptr = u32(slot);
                String actual = ptr == 0L ? null : readAsciiAt(ptr, 120);
                p("  ADJ_POOL[" + i + "] slot=" + hex(slot)
                    + " ptr=" + hex(ptr)
                    + " actual=" + (ptr == 0L ? "<NULL>" : actual == null ? "<unreadable>" : actual));
            }
            catch (Exception e) {
                p("  ADJ_POOL[" + i + "] ERROR=" + e.getMessage());
            }
        }
    }

    private static final long RADIO_CONFIG_POINTER_REGION_START = 0xC9199FB8L;
    private static final long RADIO_CONFIG_POINTER_REGION_END = 0xC919A600L;

    /*
     * Dump the aligned pointer region around the RF field-name tables.
     * NULLs are reported as candidate array boundaries, not assumed semantic
     * boundaries. Non-NULL pointers are labeled only when they decode as text.
     */
    private String compactRegionNames(StringBuilder names) {
        String value = names.toString();
        if (value.length() <= 460) return value;
        return value.substring(0, 330) + " ... " + value.substring(value.length() - 110);
    }

    private void printRadioConfigRegionRun(int index, long start, long end,
            long count, String first, String last, StringBuilder names) {
        p("  REGION_RUN[" + index + "] range=" + hex(start)
            + ".." + hex(end) + " entries=" + count
            + " first=\"" + first + "\" last=\"" + last + "\""
            + " names=[" + compactRegionNames(names) + "]");
    }

    /*
     * Compact read-only census of the aligned pointer-looking words around
     * the RF field-name arrays. It keeps the full run map without emitting
     * one console line per pointer, which previously caused the console capture
     * to lose the beginning of the run and its boundary details.
     *
     * NULL and non-string targets divide candidate runs for analysis only;
     * this does not prove that every run is a semantic table.
     */
    private void dumpRadioConfigPointerRegion() {
        long start = RADIO_CONFIG_POINTER_REGION_START;
        long endExclusive = RADIO_CONFIG_POINTER_REGION_END;
        long slots = 0L;
        long readable = 0L;
        long nulls = 0L;
        long unreadable = 0L;
        int groups = 0;

        long groupStart = -1L;
        long groupEnd = -1L;
        long groupCount = 0L;
        String groupFirst = null;
        String groupLast = null;
        StringBuilder groupNames = new StringBuilder();

        p("");
        p("============================================================");
        p("RADIO_CONFIG CONTIGUOUS STRING-POINTER REGION");
        p("Range=" + hex(start) + ".." + hex(endExclusive - 1L));
        p("Compact mode: emits run summaries, NULL slots, and unreadable-slot ranges.");
        p("NULL/non-string splits are candidates only; pointer-looking data may include other structures.");
        p("============================================================");

        MemoryBlock regionBlock = block(start);
        if (regionBlock == null || !regionBlock.isInitialized()
                || endExclusive - 1L > regionBlock.getEnd().getOffset()) {
            p("  REGION_NOT_FULLY_INITIALIZED block="
                + (regionBlock == null ? "<none>" : regionBlock.getName()));
            return;
        }

        long unreadableRunStart = -1L;
        long unreadableRunEnd = -1L;
        long unreadableRunCount = 0L;
        long unreadableRunFirstValue = 0L;
        long unreadableRunLastValue = 0L;

        for (long slot = start; slot + 3L < endExclusive; slot += 4L) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            slots++;
            long ptr;
            try {
                ptr = u32(slot);
            }
            catch (Exception e) {
                unreadable++;
                if (groupCount > 0L) {
                    printRadioConfigRegionRun(groups, groupStart, groupEnd,
                        groupCount, groupFirst, groupLast, groupNames);
                    groups++;
                    groupStart = -1L;
                    groupEnd = -1L;
                    groupCount = 0L;
                    groupFirst = null;
                    groupLast = null;
                    groupNames.setLength(0);
                }
                if (unreadableRunCount == 0L) {
                    unreadableRunStart = slot;
                    unreadableRunFirstValue = -1L;
                }
                unreadableRunEnd = slot;
                unreadableRunLastValue = -1L;
                unreadableRunCount++;
                continue;
            }

            if (ptr == 0L) {
                nulls++;
                if (groupCount > 0L) {
                    printRadioConfigRegionRun(groups, groupStart, groupEnd,
                        groupCount, groupFirst, groupLast, groupNames);
                    groups++;
                    groupStart = -1L;
                    groupEnd = -1L;
                    groupCount = 0L;
                    groupFirst = null;
                    groupLast = null;
                    groupNames.setLength(0);
                }
                if (unreadableRunCount > 0L) {
                    p("  REGION_UNREADABLE_RUN range=" + hex(unreadableRunStart)
                        + ".." + hex(unreadableRunEnd)
                        + " slots=" + unreadableRunCount
                        + " first_value=" + (unreadableRunFirstValue < 0L ? "<read-error>" : hex(unreadableRunFirstValue))
                        + " last_value=" + (unreadableRunLastValue < 0L ? "<read-error>" : hex(unreadableRunLastValue)));
                    unreadableRunStart = -1L;
                    unreadableRunEnd = -1L;
                    unreadableRunCount = 0L;
                }
                p("  REGION_NULL slot=" + hex(slot) + " next_run=" + groups);
                continue;
            }

            String textValue = readAsciiAt(ptr, 120);
            if (textValue == null) {
                unreadable++;
                if (groupCount > 0L) {
                    printRadioConfigRegionRun(groups, groupStart, groupEnd,
                        groupCount, groupFirst, groupLast, groupNames);
                    groups++;
                    groupStart = -1L;
                    groupEnd = -1L;
                    groupCount = 0L;
                    groupFirst = null;
                    groupLast = null;
                    groupNames.setLength(0);
                }
                if (unreadableRunCount == 0L) {
                    unreadableRunStart = slot;
                    unreadableRunFirstValue = ptr;
                }
                unreadableRunEnd = slot;
                unreadableRunLastValue = ptr;
                unreadableRunCount++;
                continue;
            }

            if (unreadableRunCount > 0L) {
                p("  REGION_UNREADABLE_RUN range=" + hex(unreadableRunStart)
                    + ".." + hex(unreadableRunEnd)
                    + " slots=" + unreadableRunCount
                    + " first_value=" + (unreadableRunFirstValue < 0L ? "<read-error>" : hex(unreadableRunFirstValue))
                    + " last_value=" + (unreadableRunLastValue < 0L ? "<read-error>" : hex(unreadableRunLastValue)));
                unreadableRunStart = -1L;
                unreadableRunEnd = -1L;
                unreadableRunCount = 0L;
            }

            readable++;
            String name = textValue.trim();
            if (groupCount == 0L) {
                groupStart = slot;
                groupFirst = name;
            }
            groupEnd = slot;
            groupLast = name;
            groupCount++;
            if (groupNames.length() > 0) groupNames.append(", ");
            groupNames.append(name);
        }

        if (groupCount > 0L) {
            printRadioConfigRegionRun(groups, groupStart, groupEnd,
                groupCount, groupFirst, groupLast, groupNames);
            groups++;
        }
        if (unreadableRunCount > 0L) {
            p("  REGION_UNREADABLE_RUN range=" + hex(unreadableRunStart)
                + ".." + hex(unreadableRunEnd)
                + " slots=" + unreadableRunCount
                + " first_value=" + (unreadableRunFirstValue < 0L ? "<read-error>" : hex(unreadableRunFirstValue))
                + " last_value=" + (unreadableRunLastValue < 0L ? "<read-error>" : hex(unreadableRunLastValue)));
        }

        p("  REGION_POINTER_SLOTS=" + slots);
        p("  REGION_READABLE_STRING_POINTERS=" + readable);
        p("  REGION_NULLS=" + nulls);
        p("  REGION_UNREADABLE_NONZERO=" + unreadable);
        p("  REGION_CANDIDATE_RUNS=" + groups);

        summaryRegionPointerSlots = slots;
        summaryRegionReadableStrings = readable;
        summaryRegionNulls = nulls;
        summaryRegionUnreadable = unreadable;
        summaryRegionGroups = groups;
    }

    private static final int MAX_FIELD_TRACE_INSNS = 600000;
    private static final int MAX_FIELD_CODE_HITS = 96;
    private static final int MAX_STRING_POINTER_CODE_HITS = 128;

    /*
     * Collect unique string addresses from the validated 53-entry primary
     * table and the adjacent 12-entry candidate pool. This is a read-only
     * candidate set; adjacency alone does not prove a shared enum or parser.
     */
    private int buildRadioConfigStringTargets(long[] targets, String[] names) {
        int count = 0;
        for (int group = 0; group < 2; group++) {
            long start = group == 0
                ? RADIO_CONFIG_FIELD_NAME_TABLE
                : RADIO_CONFIG_FIELD_NAME_TABLE
                    + (long)RADIO_CONFIG_FIELD_NAME_COUNT * 4L;
            int items = group == 0
                ? RADIO_CONFIG_FIELD_NAME_COUNT - 1
                : ADJACENT_NAME_POOL_COUNT;

            for (int i = 0; i < items; i++) {
                try {
                    long ptr = u32(start + (long)i * 4L);
                    if (ptr == 0L) continue;
                    String name = readAsciiAt(ptr, 120);
                    if (name == null) continue;

                    boolean seen = false;
                    for (int j = 0; j < count; j++) {
                        if (targets[j] == ptr) {
                            seen = true;
                            break;
                        }
                    }
                    if (!seen && count < targets.length) {
                        targets[count] = ptr;
                        names[count] = name.trim();
                        count++;
                    }
                }
                catch (Exception e) {
                    p("  STRING_TARGET_READ_ERROR group=" + group
                        + " index=" + i + " error=" + e.getMessage());
                }
            }
        }
        return count;
    }

    /*
     * Inspect ReferenceManager edges TO the actual strings rather than only
     * to their pointer-table slots. This remains evidence of static references,
     * not proof that a path is reachable at runtime.
     */
    private void auditRadioConfigStringPointerReferences() {
        long[] targets = new long[65];
        String[] names = new String[65];
        int targetCount = buildRadioConfigStringTargets(targets, names);
        summaryUniqueStringTargets = targetCount;

        p("");
        p("============================================================");
        p("RADIO_CONFIG STRING-POINTER REFERENCE AUDIT");
        p("Queries references to each unique string address used by the primary table");
        p("and the adjacent candidate pool; read-only");
        p("============================================================");
        p("  UNIQUE_STRING_TARGETS=" + targetCount);

        for (int i = 0; i < targetCount; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            int total = 0;
            int instructionRefs = 0;
            int dataRefs = 0;
            int otherRefs = 0;
            int shown = 0;
            p("");
            p("  STRING_TARGET[" + i + "] name=" + names[i]
                + " address=" + hex(targets[i]));

            try {
                ReferenceIterator refs =
                    currentProgram.getReferenceManager().getReferencesTo(addr(targets[i]));
                while (refs.hasNext() && lines < MAX_LINES) {
                    if (monitor.isCancelled()) return;
                    Reference ref = refs.next();
                    total++;
                    Address from = ref.getFromAddress();
                    MemoryBlock sourceBlock = from.getAddressSpace().isMemorySpace()
                        ? block(from.getOffset()) : null;
                    boolean isInstruction = sourceBlock != null
                        && sourceBlock.isExecute()
                        && listing().getInstructionAt(from) != null;

                    if (isInstruction) instructionRefs++;
                    else if (sourceBlock != null && !sourceBlock.isExecute()) dataRefs++;
                    else otherRefs++;

                    if (shown < 6) {
                        Function f = from.getAddressSpace().isMemorySpace()
                            ? currentProgram.getFunctionManager().getFunctionContaining(from)
                            : null;
                        p("    STRING_XREF[" + shown + "] from=" + from
                            + " type=" + ref.getReferenceType()
                            + " block=" + (sourceBlock == null ? "<none>" : sourceBlock.getName())
                            + " function=" + (f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint()));
                        shown++;
                    }
                }
            }
            catch (Exception e) {
                p("    STRING_XREF_ERROR=" + e.getMessage());
            }

            p("    XREF_TOTAL=" + total
                + " instruction=" + instructionRefs
                + " data=" + dataRefs
                + " other=" + otherRefs
                + " shown=" + shown);
        }
    }

    /*
     * Scan a bounded sample across every executable block instead of spending
     * the entire instruction budget only at the beginning of the block list.
     * Each block is sampled at its beginning, middle, and end. Operands are
     * compared both with table addresses and with the actual string pointers.
     */
    private void scanExecutableInstructionsForRadioConfigTable() {
        long base = RADIO_CONFIG_FIELD_NAME_TABLE;
        long tableEnd = base + (long)RADIO_CONFIG_FIELD_NAME_COUNT * 4L;
        long scanStart = base - 0x80L;
        long scanEnd = tableEnd + 0x80L;
        long scanned = 0L;
        int exactHits = 0;
        int nearbyHits = 0;
        long stringPointerHits = 0L;
        int stringPointerHitsShown = 0;

        long[] stringTargets = new long[65];
        String[] stringNames = new String[65];
        int stringTargetCount = buildRadioConfigStringTargets(stringTargets, stringNames);
        summaryUniqueStringTargets = stringTargetCount;

        List<MemoryBlock> executableBlocks = new ArrayList<MemoryBlock>();
        for (MemoryBlock b : memory().getBlocks()) {
            if (b.isInitialized() && b.isExecute()) executableBlocks.add(b);
        }
        summaryExecutableBlocks = executableBlocks.size();

        p("");
        p("============================================================");
        p("RADIO_CONFIG DISTRIBUTED CODE-REFERENCE SCAN");
        p("Bounded to " + MAX_FIELD_TRACE_INSNS + " decoded instructions across executable blocks");
        p("Samples each executable block near its beginning, middle, and end");
        p("Exact table range=" + hex(base) + ".." + hex(tableEnd - 1L));
        p("Nearby context range=" + hex(scanStart) + ".." + hex(scanEnd - 1L));
        p("Also checks operands against unique string addresses in both candidate pools.");
        p("A hit is a static lead, not proof of an executed call path.");
        p("============================================================");
        p("  EXECUTABLE_BLOCKS_TOTAL=" + executableBlocks.size());
        p("  UNIQUE_STRING_TARGETS=" + stringTargetCount);

        int blocksSampled = 0;
        int perBlockBudget = executableBlocks.isEmpty()
            ? 0 : Math.max(1, MAX_FIELD_TRACE_INSNS / executableBlocks.size());

        for (MemoryBlock b : executableBlocks) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (scanned >= MAX_FIELD_TRACE_INSNS) break;

            long blockStart = b.getStart().getOffset();
            long blockEnd = b.getEnd().getOffset();
            long blockLength = blockEnd - blockStart + 1L;
            long blockScanned = 0L;
            int zoneBudget = Math.max(1, perBlockBudget / 3);

            for (int zone = 0; zone < 3; zone++) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                if (scanned >= MAX_FIELD_TRACE_INSNS) break;

                long zoneStart = blockStart + (blockLength * (long)zone) / 3L;
                long zoneEnd = zone == 2
                    ? blockEnd
                    : blockStart + (blockLength * (long)(zone + 1)) / 3L - 1L;
                if (zoneEnd < zoneStart) continue;

                int zoneScanned = 0;
                try {
                    InstructionIterator it = listing().getInstructions(addr(zoneStart), true);
                    while (it.hasNext()
                            && zoneScanned < zoneBudget
                            && scanned < MAX_FIELD_TRACE_INSNS
                            && lines < MAX_LINES) {
                        if (monitor.isCancelled()) return;
                        Instruction ins = it.next();
                        long insOff = ins.getAddress().getOffset();
                        if (insOff < zoneStart) continue;
                        if (insOff > zoneEnd) break;

                        scanned++;
                        zoneScanned++;
                        blockScanned++;

                        for (int op = 0; op < ins.getNumOperands(); op++) {
                            Object[] objects = ins.getOpObjects(op);
                            for (Object object : objects) {
                                long value;
                                if (object instanceof Scalar) {
                                    value = ((Scalar)object).getUnsignedValue() & 0xffffffffL;
                                }
                                else if (object instanceof Address) {
                                    value = ((Address)object).getOffset() & 0xffffffffL;
                                }
                                else {
                                    continue;
                                }

                                if (value >= base && value < tableEnd) {
                                    if (exactHits < MAX_FIELD_CODE_HITS) {
                                        p("  TABLE_CODE_IMMEDIATE_HIT value=" + hex(value)
                                            + " operand=" + op
                                            + " at=" + ins.getAddress()
                                            + " function=" + functionInfo(insOff)
                                            + " instruction=" + ins);
                                        exactHits++;
                                    }
                                }
                                else if (value >= scanStart && value < scanEnd) {
                                    if (nearbyHits < MAX_FIELD_CODE_HITS) {
                                        p("  TABLE_NEARBY_IMMEDIATE_HIT value=" + hex(value)
                                            + " operand=" + op
                                            + " at=" + ins.getAddress()
                                            + " function=" + functionInfo(insOff)
                                            + " instruction=" + ins);
                                        nearbyHits++;
                                    }
                                }

                                for (int t = 0; t < stringTargetCount; t++) {
                                    if (value != stringTargets[t]) continue;
                                    stringPointerHits++;
                                    if (stringPointerHitsShown < MAX_STRING_POINTER_CODE_HITS) {
                                        p("  STRING_POINTER_CODE_HIT target="
                                            + stringNames[t] + "@" + hex(stringTargets[t])
                                            + " operand=" + op
                                            + " at=" + ins.getAddress()
                                            + " function=" + functionInfo(insOff)
                                            + " instruction=" + ins);
                                        stringPointerHitsShown++;
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception e) {
                    p("  EXEC_INSTRUCTION_SCAN_ERROR block=" + b.getName()
                        + " zone=" + zone + " error=" + e.getMessage());
                }
            }

            p("  EXEC_BLOCK_SAMPLE name=" + b.getName()
                + " range=" + hex(blockStart) + ".." + hex(blockEnd)
                + " instructions_sampled=" + blockScanned);
            blocksSampled++;
        }

        p("  EXECUTABLE_BLOCKS_SAMPLED=" + blocksSampled);
        p("  EXECUTABLE_INSTRUCTIONS_SCANNED=" + scanned);
        p("  TABLE_CODE_IMMEDIATE_HITS_SHOWN=" + exactHits);
        p("  TABLE_NEARBY_IMMEDIATE_HITS_SHOWN=" + nearbyHits);
        p("  STRING_POINTER_CODE_HITS_TOTAL=" + stringPointerHits);
        p("  STRING_POINTER_CODE_HITS_SHOWN=" + stringPointerHitsShown);
        p("  SCAN_LIMIT_REACHED=" + (scanned >= MAX_FIELD_TRACE_INSNS));

        summaryExecutableBlocksSampled = blocksSampled;
        summaryExecutableInsnsScanned = scanned;
        summaryTableImmediateHits = exactHits;
        summaryTableNearbyHits = nearbyHits;
        summaryStringTargetCodeHits = stringPointerHits;
    }

    /*
     * Slot-level xref audit restored from STRUCTURE-11.
     * Checks references to each pointer slot in the 54-entry primary region.
     * This uses Ghidra's existing ReferenceManager and makes no program changes.
     */
    private void traceRadioConfigSlotConsumers() {
        long base = RADIO_CONFIG_FIELD_NAME_TABLE;
        long totalInstructionOrigins = 0;
        long totalDataOrigins = 0;
        int instructionOriginsShown = 0;
        int dataOriginsShown = 0;
        int slotsVisited = 0;

        p("");
        p("============================================================");
        p("RADIO_CONFIG FIELD SLOT XREF AUDIT");
        p("Checks references TO each of the 54 primary-table slots, not only to their strings");
        p("Origin is classified by whether the reference address belongs to an instruction in an executable block");
        p("READ ONLY");
        p("============================================================");

        for (int i = 0; i < RADIO_CONFIG_FIELD_NAME_COUNT; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            long slot = base + (long)i * 4L;
            slotsVisited++;
            try {
                ReferenceIterator refs =
                    currentProgram.getReferenceManager().getReferencesTo(addr(slot));
                while (refs.hasNext() && lines < MAX_LINES) {
                    if (monitor.isCancelled()) return;
                    Reference r = refs.next();
                    Address from = r.getFromAddress();
                    MemoryBlock fb = from.getAddressSpace().isMemorySpace()
                        ? block(from.getOffset()) : null;
                    Instruction ins = (fb != null && fb.isExecute())
                        ? listing().getInstructionAt(from) : null;

                    if (ins != null) {
                        totalInstructionOrigins++;
                        if (instructionOriginsShown < MAX_FIELD_CODE_HITS) {
                            p("  SLOT_CODE_ORIGIN index=" + i
                                + " slot=" + hex(slot)
                                + " from=" + from
                                + " type=" + r.getReferenceType()
                                + " function=" + functionInfo(from.getOffset())
                                + " instruction=" + ins);
                            instructionOriginsShown++;
                        }
                    }
                    else {
                        totalDataOrigins++;
                        if (dataOriginsShown < 24) {
                            p("  SLOT_DATA_ORIGIN index=" + i
                                + " slot=" + hex(slot)
                                + " from=" + from
                                + " type=" + r.getReferenceType()
                                + " block=" + (fb == null ? "<none>" : fb.getName()));
                            dataOriginsShown++;
                        }
                    }
                }
            }
            catch (Exception e) {
                p("  SLOT_XREF_AUDIT_ERROR index=" + i
                    + " slot=" + hex(slot) + " error=" + e.getMessage());
            }
        }

        p("  SLOTS_VISITED=" + slotsVisited);
        p("  INSTRUCTION_ORIGIN_REFS_TOTAL=" + totalInstructionOrigins);
        p("  INSTRUCTION_ORIGIN_REFS_SHOWN=" + instructionOriginsShown);
        p("  DATA_ORIGIN_REFS_TOTAL=" + totalDataOrigins);
        p("  DATA_ORIGIN_REFS_SHOWN=" + dataOriginsShown);
        summarySlotInstructionRefs = totalInstructionOrigins;
        summarySlotDataRefs = totalDataOrigins;
    }

    private static final String[] RF_FIELD_TABLE_TARGETS = {
        "CENTER_FREQ", "BWP_CENTER_FREQ", "RX_CARRIER", "TX_CARRIER",
        "SUB_TECH", "TECH_MODE", "TECHNOLOGY", "RFM_DEVICE",
        "BANDWIDTH", "SIG_PATH", "SRC_SIG_PATH", "ANT_PATH",
        "USER_ADJ", "TOTAL_ADJ", "ENABLE_XO", "SAMP_FREQ",
        "FREQ_ADJUST", "FREQADJUST", "RX_TUNE", "BAND"
    };

    private boolean isRfFieldTableTarget(String value) {
        if (value == null) return false;
        String n = value.trim().toUpperCase();
        for (String target : RF_FIELD_TABLE_TARGETS) {
            if (n.equals(target)) return true;
        }
        return false;
    }

    private boolean slotAlreadyClustered(List<Long> centers, MemoryBlock targetBlock, long slot) {
        for (Long center : centers) {
            MemoryBlock cb = block(center.longValue());
            if (cb == null || targetBlock == null) continue;
            if (!cb.getName().equals(targetBlock.getName())) continue;
            if (Math.abs(center.longValue() - slot) <= 0x40L) return true;
        }
        return false;
    }

    private void dumpRfPointerCluster(long center, int radius) {
        MemoryBlock b = block(center);
        if (b == null || !b.isInitialized() || b.isExecute()) {
            p("    TABLE_CLUSTER center=" + hex(center) + " block=<none-or-exec>");
            return;
        }

        long start = center - radius;
        long end = center + radius;
        if (start < b.getStart().getOffset()) start = b.getStart().getOffset();
        if (end > b.getEnd().getOffset()) end = b.getEnd().getOffset();
        start = (start + 3L) & ~3L;

        p("    TABLE_CLUSTER block=" + b.getName()
            + " range=" + hex(start) + ".." + hex(end));

        for (long off = start; off + 3L <= end; off += 4L) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            try {
                long value = u32(off);
                String pointed = readAsciiAt(value, 100);
                MemoryBlock vb = block(value);
                String details = "";
                if (pointed != null) details = " text=\"" + pointed + "\"";
                else if (vb != null) details = vb.isExecute()
                    ? " target_exec=" + vb.getName()
                    : " target_mem=" + vb.getName();

                p("      slot=" + hex(off)
                    + " value=" + hex(value) + details);
            }
            catch (Exception e) {
                p("      SLOT_READ_ERROR @ " + hex(off) + ": " + e.getMessage());
            }
        }
    }

    private void inspectRefsToPointerSlot(long slot) {
        try {
            ReferenceIterator refs =
                currentProgram.getReferenceManager().getReferencesTo(addr(slot));
            int n = 0;
            while (refs.hasNext() && n < 16 && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;
                Reference r = refs.next();
                Address from = r.getFromAddress();
                Function f = from.getAddressSpace().isMemorySpace()
                    ? currentProgram.getFunctionManager().getFunctionContaining(from)
                    : null;

                p("      SLOT_XREF[" + n + "] from=" + from
                    + " type=" + r.getReferenceType()
                    + " function=" + (f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint()));
                if (f != null) p("        instruction=" + instructionInfo(from.getOffset()));
                n++;
            }
            p("      SLOT_XREFS_SHOWN=" + n);
        }
        catch (Exception e) {
            p("      SLOT_XREF_ERROR @ " + hex(slot) + ": " + e.getMessage());
        }
    }

    private void scanRfFieldPointerTables() {
        p("");
        p("============================================================");
        p("RF FIELD-NAME POINTER TABLE TRACE");
        p("Exact field-label pointers, surrounding pointer slots, and references to each slot");
        p("Distinguishes data-table references from code references; static read-only");
        p("============================================================");

        List<Long> dumpedCenters = new ArrayList<Long>();
        int stringsInspected = 0;
        int fieldsMatched = 0;
        int pointerSlots = 0;
        int clusters = 0;
        final int MAX_STRINGS = 300000;
        final int MAX_SLOTS = 120;

        try {
            ghidra.program.model.listing.DataIterator it =
                currentProgram.getListing().getDefinedData(true);

            while (it.hasNext()
                    && stringsInspected < MAX_STRINGS
                    && pointerSlots < MAX_SLOTS
                    && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;
                Data d = it.next();
                stringsInspected++;

                String typeName = String.valueOf(d.getDataType()).toLowerCase();
                if (!typeName.contains("string")) continue;

                String value = String.valueOf(d.getValue());
                if (!isRfFieldTableTarget(value)) continue;

                fieldsMatched++;
                p("");
                p("RF_FIELD_STRING value=" + value + " address=" + d.getAddress());

                ReferenceIterator refs =
                    currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                int refsShown = 0;

                while (refs.hasNext() && refsShown < 32
                        && pointerSlots < MAX_SLOTS
                        && lines < MAX_LINES) {
                    if (monitor.isCancelled()) return;

                    Reference r = refs.next();
                    Address from = r.getFromAddress();
                    if (!from.getAddressSpace().isMemorySpace()) continue;

                    long slot = from.getOffset();
                    MemoryBlock slotBlock = block(slot);
                    p("  STRING_REF_SLOT=" + hex(slot)
                        + " block=" + (slotBlock == null ? "<none>" : slotBlock.getName())
                        + " type=" + r.getReferenceType()
                        + " primary=" + r.isPrimary());

                    inspectRefsToPointerSlot(slot);
                    pointerSlots++;
                    refsShown++;

                    if (slotBlock != null && !slotBlock.isExecute()
                            && !slotAlreadyClustered(dumpedCenters, slotBlock, slot)) {
                        dumpRfPointerCluster(slot, 0x30);
                        dumpedCenters.add(slot);
                        clusters++;
                    }
                }

                p("  STRING_REF_SLOTS_SHOWN=" + refsShown);
            }

            p("");
            p("RF_FIELD_STRINGS_INSPECTED=" + stringsInspected);
            p("RF_FIELD_NAMES_MATCHED=" + fieldsMatched);
            p("RF_FIELD_POINTER_SLOTS_REPORTED=" + pointerSlots);
            p("RF_FIELD_POINTER_CLUSTERS_DUMPED=" + clusters);
        }
        catch (Exception e) {
            p("RF FIELD POINTER TABLE SCAN ERROR: " + e.getMessage());
        }
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
            summaryTuneFieldStringsInspected = inspected;
            summaryTuneFieldStringsReported = reported;
        }
        catch (Exception e) {
            p("RF_TUNE STRING SCAN ERROR: " + e.getMessage());
        }
    }

    /*
     * Narrow pass: locate MSG_CONST records that explicitly name
     * ftm_rf_test_radio_config.c, print the encoded source line and format,
     * and inspect registered references to both the record and format string.
     * This is static analysis only.
     */
    private void scanRadioConfigMessageRecords() {
        p("");
        p("============================================================");
        p("RADIO_CONFIG SOURCE-LINE MESSAGE RECORDS");
        p("Filter: ftm_rf_test_radio_config.c");
        p("Record hypothesis: {fmt_ptr, fname_ptr, (ssid<<16)|line, argc}");
        p("Shows source lines and registered xrefs; no RF command is constructed.");
        p("============================================================");

        long scanned = 0L;
        long candidates = 0L;
        long reported = 0L;
        final int MAX_REPORTS = 100;
        final long MAX_SCAN_BYTES = 0x80000000L;

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!isScanableStaticBlock(b) || b.isExecute()) continue;

            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset();
            byte[] buf = new byte[RAW_CHUNK];
            long pos = start;
            long lastProcessedCandidate = start - 4L;

            try {
                while (pos <= end && scanned < MAX_SCAN_BYTES && reported < MAX_REPORTS) {
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
                        long argc = bufferU32(buf, i + 12);

                        if (fmtPtr == 0L || filePtr == 0L || argc > 16L) continue;
                        if (!validDataPointer(filePtr) || !validDataPointer(fmtPtr)) continue;

                        int ssid = (int)((packed >>> 16) & 0xffffL);
                        int line = (int)(packed & 0xffffL);
                        if (ssid < 1 || ssid > 0x100 || line < 1 || line > 0x7fff) continue;

                        String file = readAsciiAt(filePtr, 160);
                        if (file == null || !file.toLowerCase().contains("ftm_rf_test_radio_config.c")) continue;

                        String fmt = readAsciiAt(fmtPtr, 320);
                        if (fmt == null || fmt.length() == 0) continue;
                        candidates++;

                        p("");
                        p("  RADIO_CONFIG_MSG_RECORD[" + reported + "] holder=" + hex(holder)
                            + " block=" + b.getName());
                        p("    source=" + file + " ssid=" + ssid
                            + " line=" + line + " argc=" + argc);
                        p("    fmt_ptr=" + hex(fmtPtr) + " format=\"" + fmt + "\"");

                        int recordRefs = 0;
                        try {
                            ReferenceIterator refs =
                                currentProgram.getReferenceManager().getReferencesTo(addr(holder));
                            while (refs.hasNext() && recordRefs < 8 && lines < MAX_LINES) {
                                if (monitor.isCancelled()) return;
                                Reference ref = refs.next();
                                Address from = ref.getFromAddress();
                                MemoryBlock fromBlock = from.getAddressSpace().isMemorySpace()
                                    ? block(from.getOffset()) : null;
                                p("    RECORD_XREF[" + recordRefs + "] from=" + from
                                    + " type=" + ref.getReferenceType()
                                    + " block=" + (fromBlock == null ? "<none>" : fromBlock.getName())
                                    + " instruction=" + instructionInfo(from.getOffset()));
                                recordRefs++;
                            }
                        }
                        catch (Exception e) {
                            p("    RECORD_XREF_ERROR=" + e.getMessage());
                        }
                        p("    RECORD_XREFS_SHOWN=" + recordRefs);

                        int formatRefs = 0;
                        try {
                            ReferenceIterator refs =
                                currentProgram.getReferenceManager().getReferencesTo(addr(fmtPtr));
                            while (refs.hasNext() && formatRefs < 8 && lines < MAX_LINES) {
                                if (monitor.isCancelled()) return;
                                Reference ref = refs.next();
                                Address from = ref.getFromAddress();
                                MemoryBlock fromBlock = from.getAddressSpace().isMemorySpace()
                                    ? block(from.getOffset()) : null;
                                Function f = from.getAddressSpace().isMemorySpace()
                                    ? currentProgram.getFunctionManager().getFunctionContaining(from)
                                    : null;
                                p("    FORMAT_XREF[" + formatRefs + "] from=" + from
                                    + " type=" + ref.getReferenceType()
                                    + " block=" + (fromBlock == null ? "<none>" : fromBlock.getName())
                                    + " function=" + (f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint()));
                                formatRefs++;
                            }
                        }
                        catch (Exception e) {
                            p("    FORMAT_XREF_ERROR=" + e.getMessage());
                        }
                        p("    FORMAT_XREFS_SHOWN=" + formatRefs);
                        reported++;
                        if (reported >= MAX_REPORTS) break;
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
                p("  RADIO_CONFIG_MSG_SCAN_BLOCK_ERROR block=" + b.getName()
                    + " error=" + e.getMessage());
            }
        }

        p("  RADIO_CONFIG_MSG_CANDIDATES=" + candidates);
        p("  RADIO_CONFIG_MSG_RECORDS_REPORTED=" + reported);
        p("  RADIO_CONFIG_MSG_SCAN_BYTES_APPROX=" + scanned);
        summaryRadioConfigMsgCandidates = candidates;
        summaryRadioConfigMsgReported = reported;
    }

    /*
     * Static lead search for the confirmed RFDEBUG subsystem value 0x007B
     * inside executable instructions. It prints a small instruction window
     * for each direct immediate hit so likely comparisons/dispatch branches
     * can be inspected manually in Ghidra. Hits alone do not prove a dispatcher.
     */
    private void scanRfDebugSubsysImmediateCandidates() {
        p("");
        p("============================================================");
        p("RFDEBUG SUBSYSTEM 0x007B EXECUTABLE-CODE CANDIDATES");
        p("Searches executable instruction operands for the exact value 0x007B.");
        p("For each hit, shows nearby instructions and its containing function.");
        p("Read-only static leads only; no packet generation or transmission.");
        p("============================================================");

        long scanned = 0L;
        long hits = 0L;
        int shown = 0;
        final int MAX_SHOWN = 72;
        final long MAX_INSNS = 1600000L;

        for (MemoryBlock b : memory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || !b.isExecute()) continue;

            long blockEnd = b.getEnd().getOffset();
            try {
                InstructionIterator it = listing().getInstructions(b.getStart(), true);
                while (it.hasNext() && scanned < MAX_INSNS && lines < MAX_LINES) {
                    if (monitor.isCancelled()) return;
                    Instruction ins = it.next();
                    long off = ins.getAddress().getOffset();
                    if (off > blockEnd) break;
                    scanned++;

                    boolean match = false;
                    int matchOperand = -1;
                    for (int op = 0; op < ins.getNumOperands(); op++) {
                        Object[] objects = ins.getOpObjects(op);
                        for (Object object : objects) {
                            long value;
                            if (object instanceof Scalar) {
                                value = ((Scalar)object).getUnsignedValue() & 0xffffffffL;
                            }
                            else if (object instanceof Address) {
                                value = ((Address)object).getOffset() & 0xffffffffL;
                            }
                            else {
                                continue;
                            }
                            if (value == 0x7BL) {
                                match = true;
                                matchOperand = op;
                                break;
                            }
                        }
                        if (match) break;
                    }

                    if (!match) continue;
                    hits++;
                    if (shown >= MAX_SHOWN) continue;

                    Function f = currentProgram.getFunctionManager()
                        .getFunctionContaining(ins.getAddress());
                    p("");
                    p("  RFDEBUG_7B_CANDIDATE[" + shown + "] at=" + ins.getAddress()
                        + " block=" + b.getName()
                        + " operand=" + matchOperand
                        + " function=" + (f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint())
                        + " instruction=" + ins);

                    Instruction cursor = ins;
                    for (int n = 1; n <= 7; n++) {
                        Instruction next = listing().getInstructionAfter(cursor.getAddress());
                        if (next == null || next.getAddress().getOffset() > blockEnd) break;
                        if (f != null) {
                            Function nextFunction = currentProgram.getFunctionManager()
                                .getFunctionContaining(next.getAddress());
                            if (nextFunction == null
                                    || !nextFunction.getEntryPoint().equals(f.getEntryPoint())) break;
                        }
                        p("    +" + n + " " + next.getAddress() + " " + next);
                        cursor = next;
                    }
                    shown++;
                }
            }
            catch (Exception e) {
                p("  RFDEBUG_7B_SCAN_ERROR block=" + b.getName()
                    + " error=" + e.getMessage());
            }
        }

        p("  EXECUTABLE_INSTRUCTIONS_SCANNED=" + scanned);
        p("  RFDEBUG_7B_IMMEDIATE_HITS_TOTAL=" + hits);
        p("  RFDEBUG_7B_CANDIDATES_SHOWN=" + shown);
        p("  SCAN_LIMIT_REACHED=" + (scanned >= MAX_INSNS));
        summaryRfDebugSubsysInstructionsScanned = scanned;
        summaryRfDebugSubsysImmediateHits = hits;
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
    private static final long PREVIOUS_SHARED_THUNK = 0xD89B2790L;
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
        p("Targets: current 0xD819C208, prior-build 0xD8150ED8, historical shared thunk 0xD89B2790");
        p("Current table context: 0xC4951828, 80 entries; non-table hits are called out");
        p("READ ONLY / NO COMMAND GENERATION");
        p("============================================================");

        long[] targets = {
            CURRENT_RUNTIME_DISPATCH,
            PREVIOUS_BUILD_DISPATCH,
            PREVIOUS_SHARED_THUNK
        };
        String[] labels = {
            "CURRENT_FTM_HANDLER",
            "PREVIOUS_BUILD_HANDLER",
            "HISTORICAL_SHARED_THUNK"
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
        p("POINTER_TOTAL " + labels[2] + "=" + grandCounts[2]);
        summaryCurrentDispatchPointers = grandCounts[0];
        summaryPreviousDispatchPointers = grandCounts[1];
        summarySharedThunkPointers = grandCounts[2];
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



    private void printCompactReferenceSummary(long target, String label, int maxSamples) {
        int total = 0;
        int instructionSources = 0;
        int dataSources = 0;
        int shown = 0;

        p("");
        p("HANDLER_REFERENCE_SUMMARY " + label + " target=" + hex(target));
        MemoryBlock tb = block(target);
        p("  mapped=" + (tb != null)
            + " block=" + (tb == null ? "<none>" : tb.getName())
            + " exec=" + (tb != null && tb.isExecute()));

        try {
            ReferenceIterator refs =
                currentProgram.getReferenceManager().getReferencesTo(addr(target));
            while (refs.hasNext()) {
                if (monitor.isCancelled()) return;
                Reference r = refs.next();
                total++;
                Address from = r.getFromAddress();
                MemoryBlock fb = from.getAddressSpace().isMemorySpace()
                    ? block(from.getOffset()) : null;
                Instruction ins = (fb != null && fb.isExecute())
                    ? listing().getInstructionAt(from) : null;

                if (ins != null) instructionSources++;
                else dataSources++;

                if (shown < maxSamples && lines < MAX_LINES) {
                    p("  REF[" + shown + "] from=" + from
                        + " type=" + r.getReferenceType()
                        + " source_block=" + (fb == null ? "<none>" : fb.getName())
                        + " instruction=" + (ins == null ? "<none>" : ins.toString())
                        + " function=" + functionInfo(from.getOffset()));
                    shown++;
                }
            }
        }
        catch (Exception e) {
            p("  REFERENCE_SCAN_ERROR=" + e.getMessage());
        }

        p("  TOTAL_REFERENCES=" + total);
        p("  INSTRUCTION_SOURCES=" + instructionSources);
        p("  NON_INSTRUCTION_SOURCES=" + dataSources);
        p("  SAMPLES_SHOWN=" + shown);
    }

    private void printStructure18ExecutionFooter() {
        // Deliberately bypass p()/MAX_LINES to preserve a compact diagnostic tail.
        println("");
        println("============================================================");
        println("STRUCTURE20 EXECUTION FOOTER");
        println("TRACE_BUILD=" + TRACE_BUILD);
        println("PROGRAM=" + currentProgram.getName());
        println("RADIO_CONFIG_PRIMARY_TABLE=0xC9199FB8 entries=38 including NULL terminator");
        println("RADIO_CONFIG_RX_OVERRIDE_TABLE=0xC919A050 entries_checked=" + ADJACENT_NAME_POOL_COUNT);
        println("FIELD_STRINGS_READABLE=" + summaryFieldStringsReadable);
        println("FIELD_REFERENCE_LABEL_MATCHES=" + summaryFieldReferenceMatches);
        println("FIELD_ANCHOR_MISMATCHES=" + summaryFieldAnchorMismatches);
        println("SLOT_INSTRUCTION_ORIGIN_REFS=" + summarySlotInstructionRefs);
        println("SLOT_DATA_ORIGIN_REFS=" + summarySlotDataRefs);
        println("UNIQUE_STRING_TARGETS=" + summaryUniqueStringTargets);
        println("EXECUTABLE_BLOCKS_TOTAL=" + summaryExecutableBlocks);
        println("EXECUTABLE_BLOCKS_SAMPLED=" + summaryExecutableBlocksSampled);
        println("EXECUTABLE_INSTRUCTIONS_SCANNED=" + summaryExecutableInsnsScanned);
        println("TABLE_CODE_IMMEDIATE_HITS=" + summaryTableImmediateHits);
        println("TABLE_NEARBY_IMMEDIATE_HITS=" + summaryTableNearbyHits);
        println("STRING_POINTER_CODE_HITS=" + summaryStringTargetCodeHits);
        println("RF_TUNE_DATA_ITEMS_INSPECTED=" + summaryTuneFieldStringsInspected);
        println("RF_TUNE_STRINGS_REPORTED=" + summaryTuneFieldStringsReported);
        println("RADIO_CONFIG_MSG_CANDIDATES=" + summaryRadioConfigMsgCandidates);
        println("RADIO_CONFIG_MSG_RECORDS_REPORTED=" + summaryRadioConfigMsgReported);
        println("RFDEBUG_7B_INSTRUCTIONS_SCANNED=" + summaryRfDebugSubsysInstructionsScanned);
        println("RFDEBUG_7B_IMMEDIATE_HITS=" + summaryRfDebugSubsysImmediateHits);
        println("REGION_POINTER_SLOTS=" + summaryRegionPointerSlots);
        println("REGION_READABLE_STRING_POINTERS=" + summaryRegionReadableStrings);
        println("REGION_NULLS=" + summaryRegionNulls);
        println("REGION_UNREADABLE_NONZERO=" + summaryRegionUnreadable);
        println("REGION_CANDIDATE_RUNS=" + summaryRegionGroups);
        println("PTRS_D819C208=" + summaryCurrentDispatchPointers);
        println("PTRS_D8150ED8=" + summaryPreviousDispatchPointers);
        println("PTRS_D89B2790=" + summarySharedThunkPointers);
        println("Negative values mean that a phase was not reached or did not finish.");
        println("============================================================");
    }

    
    /*
     * STRUCTURE-20: dynamic address discovery for 614_0_0.mbn.
     * Do not reuse C919xxxx/C508xxxx addresses from qdsp6sw.mbn.
     * Discover field strings, string-pointer slots and decoded-instruction
     * candidates from the program currently open in Ghidra.
     *
     * READ ONLY: no modem interaction, no command generation, no program edits.
     */
    private static final int DYNAMIC_STRING_HITS_PER_LABEL = 16;
    private static final int DYNAMIC_POINTER_PRINT_LIMIT = 48;
    private static final int DYNAMIC_CODE_HIT_PRINT_LIMIT = 120;
    private static final int DYNAMIC_CONTEXT_LIMIT = 24;
    private static final int DYNAMIC_SCAN_CHUNK = 0x4000;

    private static final String[] DYNAMIC_RF_LABELS = {
        "CENTER_FREQ",
        "BWP_CENTER_FREQ",
        "RX_CARRIER",
        "TX_CARRIER",
        "FREQUENCY",
        "RX_TUNE",
        "RADIO_CONFIG",
        "RFA_RF_LTE_FDD_RX_CONFIG",
        "RFA_RF_LTE_TDD_RX_CONFIG"
    };

    private static class DynamicStringHit {
        long address;
        String label;
        String value;
        String blockName;

        DynamicStringHit(long address, String label, String value, String blockName) {
            this.address = address;
            this.label = label;
            this.value = value;
            this.blockName = blockName;
        }
    }

    private static class DynamicPointerHit {
        long slot;
        long target;
        String label;
        String blockName;

        DynamicPointerHit(long slot, long target, String label, String blockName) {
            this.slot = slot;
            this.target = target;
            this.label = label;
            this.blockName = blockName;
        }
    }

    private final List<DynamicStringHit> dynamic614StringHits =
        new ArrayList<DynamicStringHit>();
    private final List<DynamicPointerHit> dynamic614PointerHits =
        new ArrayList<DynamicPointerHit>();
    private final java.util.Map<Long, String> dynamic614StringAddressLabels =
        new java.util.HashMap<Long, String>();
    private final java.util.Map<Long, String> dynamic614ExactCodeTargets =
        new java.util.HashMap<Long, String>();
    private final java.util.Map<Long, String> dynamic614Low16Targets =
        new java.util.HashMap<Long, String>();

    private long dynamic614BytesScanned = 0L;
    private long dynamic614PointerWordsScanned = 0L;
    private long dynamic614DecodedInstructionsAllBlocks = 0L;
    private long dynamic614DecodedInstructionsExecBlocks = 0L;
    private int dynamic614ExactCodeHits = 0;
    private int dynamic614Low16CodeHits = 0;
    private int dynamic614ContextsPrinted = 0;

    private String readDynamicCString(long offset, int maxLength) {
        try {
            MemoryBlock b = block(offset);
            if (b == null || !b.isInitialized()) return null;
            if (offset < b.getStart().getOffset()
                    || offset > b.getEnd().getOffset()) return null;

            int want = (int)Math.min((long)maxLength,
                b.getEnd().getOffset() - offset + 1L);
            if (want <= 0) return null;

            StringBuilder out = new StringBuilder();
            for (int i = 0; i < want; i++) {
                int c = memory().getByte(addr(offset + i)) & 0xff;
                if (c == 0) return out.length() == 0 ? null : out.toString();
                if (c < 0x20 || c > 0x7e) return null;
                out.append((char)c);
            }
            return null;
        }
        catch (Exception e) {
            return null;
        }
    }

    private boolean dynamicIdentifierBefore(long offset, MemoryBlock b) {
        if (offset <= b.getStart().getOffset()) return false;
        try {
            int c = memory().getByte(addr(offset - 1L)) & 0xff;
            return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '_';
        }
        catch (Exception e) {
            return false;
        }
    }

    private void addDynamic614String(long offset, String label, String value, MemoryBlock b) {
        for (DynamicStringHit old : dynamic614StringHits) {
            if (old.address == offset && old.label.equals(label)) return;
        }

        dynamic614StringHits.add(new DynamicStringHit(offset, label, value, b.getName()));
        String previous = dynamic614StringAddressLabels.get(Long.valueOf(offset));
        if (previous == null) previous = label;
        else if (!previous.contains(label)) previous = previous + "|" + label;
        dynamic614StringAddressLabels.put(Long.valueOf(offset), previous);
        dynamic614ExactCodeTargets.put(Long.valueOf(offset),
            "STRING:" + previous + "@" + hex(offset));

        long low = offset & 0xffffL;
        if (low >= 0x1000L && !dynamic614Low16Targets.containsKey(Long.valueOf(low))) {
            dynamic614Low16Targets.put(Long.valueOf(low),
                "LOW16_STRING:" + label + "@" + hex(offset));
        }

        p("  DYNAMIC_STRING_HIT label=" + label
            + " address=" + hex(offset)
            + " block=" + b.getName()
            + " value=\"" + value + "\"");
    }

    private int countDynamic614LabelHits(String label) {
        int count = 0;
        for (DynamicStringHit hit : dynamic614StringHits) {
            if (hit.label.equals(label)) count++;
        }
        return count;
    }

    private void search614StringInBlock(MemoryBlock b, String label) {
        // The _elfHeader/_elfProgramHeaders/unallocated blocks use separate
        // address spaces. addr(offset) creates a default-space address, so do
        // not feed their offsets into the ordinary memory reader.
        if (!isDefaultDynamicAddressBlock(b) || !b.isInitialized()) return;

        byte[] pattern = new byte[label.length()];
        for (int i = 0; i < label.length(); i++) pattern[i] = (byte)label.charAt(i);

        long start = b.getStart().getOffset();
        long end = b.getEnd().getOffset();
        long pos = start;
        long matchCount = 0L;
        long examined = 0L;

        while (pos <= end && !monitor.isCancelled() && lines < MAX_LINES
                && countDynamic614LabelHits(label) < DYNAMIC_STRING_HITS_PER_LABEL) {
            int want = (int)Math.min((long)DYNAMIC_SCAN_CHUNK, end - pos + 1L);
            if (want < pattern.length) break;

            byte[] buf = new byte[want];
            try {
                memory().getBytes(addr(pos), buf, 0, want);
            }
            catch (Exception e) {
                p("  DYNAMIC_STRING_READ_ERROR label=" + label
                    + " block=" + b.getName()
                    + " at=" + hex(pos)
                    + " error=" + e.getMessage());
                break;
            }

            for (int i = 0; i <= want - pattern.length; i++) {
                boolean equal = true;
                for (int j = 0; j < pattern.length; j++) {
                    if (buf[i + j] != pattern[j]) { equal = false; break; }
                }
                if (!equal) continue;

                long at = pos + i;
                if (dynamicIdentifierBefore(at, b)) continue;

                String actual = readDynamicCString(at, 200);
                if (actual == null || !actual.equalsIgnoreCase(label)) continue;

                matchCount++;
                addDynamic614String(at, label, actual, b);
                if (countDynamic614LabelHits(label) >= DYNAMIC_STRING_HITS_PER_LABEL) break;
            }

            long advance = (long)want - pattern.length + 1L;
            if (advance <= 0L) break;
            pos += advance;
            examined += advance;
        }

        dynamic614BytesScanned += examined;
        if (matchCount > 0L) {
            p("  DYNAMIC_STRING_LABEL_SUMMARY label=" + label
                + " matches_seen=" + matchCount
                + " retained_for_label=" + countDynamic614LabelHits(label));
        }
    }

    private void scan614FunctionInventory() {
        p("");
        p("============================================================");
        p("614_0_0 FUNCTION INVENTORY");
        p("Enumerates functions already recognized by Ghidra in the current image.");
        p("This is a discovery list, not proof that a function controls RX tuning.");
        p("============================================================");

        int total = 0;
        int shown = 0;
        try {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled() && lines < MAX_LINES) {
                Function f = it.next();
                total++;
                if (shown < 500) {
                    Address entry = f.getEntryPoint();
                    MemoryBlock b = entry.getAddressSpace().isMemorySpace()
                        ? block(entry.getOffset()) : null;
                    p("  614_FUNCTION[" + shown + "] name=" + f.getName()
                        + " entry=" + entry
                        + " block=" + (b == null ? "<none>" : b.getName())
                        + " thunk=" + f.isThunk()
                        + " body_min=" + f.getBody().getMinAddress()
                        + " body_max=" + f.getBody().getMaxAddress()
                        + " body_bytes=" + f.getBody().getNumAddresses());
                    shown++;
                }
            }
            p("614_FUNCTIONS_TOTAL=" + total);
            p("614_FUNCTIONS_PRINTED=" + shown);
        }
        catch (Exception e) {
            p("614_FUNCTION_INVENTORY_ERROR=" + e.getMessage());
        }
    }

    private final List<long[]> dynamic614CodePointerRunRanges =
        new ArrayList<long[]>();

    private void report614FunctionPointerRun(
            String blockName,
            List<Long> runSlots,
            List<Long> runValues,
            List<String> runTargets,
            int[] stats) {
        if (runSlots.size() >= 4) {
            dynamic614CodePointerRunRanges.add(new long[] {
                runSlots.get(0).longValue(),
                runSlots.get(runSlots.size() - 1).longValue()
            });
            stats[0]++;
            if (stats[1] < 120 && lines < MAX_LINES) {
                p("614_CODE_POINTER_RUN #" + stats[0]
                    + " block=" + blockName
                    + " range=" + hex(runSlots.get(0).longValue())
                    + ".." + hex(runSlots.get(runSlots.size() - 1).longValue())
                    + " count=" + runSlots.size());
                stats[1]++;

                for (int i = 0; i < runSlots.size(); i++) {
                    if (monitor.isCancelled() || lines >= MAX_LINES) break;
                    if (stats[2] >= 600) break;
                    p("  CODE_PTR slot=" + hex(runSlots.get(i).longValue())
                        + " value=" + hex(runValues.get(i).longValue())
                        + " target=" + runTargets.get(i));
                    stats[2]++;
                }
            }
        }
        runSlots.clear();
        runValues.clear();
        runTargets.clear();
    }

    /**
     * Scans initialized non-executable memory for contiguous arrays of 32-bit
     * values that exactly match known function entry points. These are candidate
     * function-pointer tables only; their role must be verified from references.
     */
    private void scan614PcRelativeDataReferences() {
        p("");
        p("============================================================");
        p("614_0_0 PC-RELATIVE DATA REFERENCES NEAR FUNCTION-POINTER RUNS");
        p("Finds Hexagon-style add Rd,PC,immediate effective targets near discovered pointer runs.");
        p("Uses instruction address plus instruction length plus signed displacement.");
        p("READ ONLY; targets are leads, not proof of caller/callee semantics.");
        p("============================================================");

        if (dynamic614CodePointerRunRanges.isEmpty()) {
            p("614_PCREL_NOTE=No pointer runs were collected; run the pointer scan first.");
            return;
        }

        InstructionIterator it = listing().getInstructions(true);
        long addPcInstructions = 0L;
        long effectiveDataTargets = 0L;
        long nearbyRunTargets = 0L;
        int printed = 0;
        int windowsPrinted = 0;
        java.util.Set<Long> printedTargetWindows = new java.util.HashSet<Long>();

        while (it.hasNext() && !monitor.isCancelled() && lines < MAX_LINES) {
            Instruction ins = it.next();
            MemoryBlock codeBlock;
            try {
                codeBlock = memory().getBlock(ins.getAddress());
            }
            catch (Exception e) {
                continue;
            }
            if (codeBlock == null || !codeBlock.isExecute()
                    || !isDefaultDynamicAddressBlock(codeBlock)) continue;
            if (!"add".equalsIgnoreCase(ins.getMnemonicString())) continue;

            boolean hasPcRegister = false;
            boolean hasScalar = false;
            long displacement = 0L;

            for (int op = 0; op < ins.getNumOperands(); op++) {
                Object[] objects = ins.getOpObjects(op);
                for (Object object : objects) {
                    if (object instanceof ghidra.program.model.lang.Register) {
                        String registerName =
                            ((ghidra.program.model.lang.Register)object).getName();
                        if ("PC".equalsIgnoreCase(registerName)) {
                            hasPcRegister = true;
                        }
                    }
                    else if (object instanceof Scalar) {
                        displacement = ((Scalar)object).getSignedValue();
                        hasScalar = true;
                    }
                }
            }

            if (!hasPcRegister || !hasScalar) continue;
            addPcInstructions++;

            long target = ins.getAddress().getOffset()
                + (long)ins.getLength() + displacement;
            if (target < 0L || target > 0xffffffffL) continue;

            MemoryBlock targetBlock;
            try {
                targetBlock = memory().getBlock(addr(target));
            }
            catch (Exception e) {
                continue;
            }
            if (targetBlock == null || !targetBlock.isInitialized()
                    || !isDefaultDynamicAddressBlock(targetBlock)) continue;
            effectiveDataTargets++;

            long nearestDistance = Long.MAX_VALUE;
            long nearestStart = -1L;
            long nearestEnd = -1L;
            for (long[] range : dynamic614CodePointerRunRanges) {
                if (range == null || range.length < 2) continue;
                long start = range[0];
                long end = range[1];
                long distance;
                if (target < start) distance = start - target;
                else if (target > end) distance = target - end;
                else distance = 0L;

                if (distance < nearestDistance) {
                    nearestDistance = distance;
                    nearestStart = start;
                    nearestEnd = end;
                }
            }

            if (nearestDistance > 0x100L) continue;
            nearbyRunTargets++;
            if (printed >= 240 || lines >= MAX_LINES) continue;

            p("614_PCREL_NEAR_RUN hit=" + nearbyRunTargets
                + " ins=" + ins.getAddress()
                + " function=" + functionInfo(ins.getAddress().getOffset())
                + " target=" + hex(target)
                + " target_block=" + targetBlock.getName()
                + " nearest_run=" + hex(nearestStart) + ".." + hex(nearestEnd)
                + " distance=0x" + Long.toHexString(nearestDistance)
                + " instruction=" + ins);
            printed++;

            Long targetKey = Long.valueOf(target & ~3L);
            if (windowsPrinted >= 60 || !printedTargetWindows.add(targetKey)) continue;

            long windowStart = Math.max(targetBlock.getStart().getOffset(), (target & ~3L) - 0x0cL);
            long windowEnd = Math.min(targetBlock.getEnd().getOffset(), (target & ~3L) + 0x0cL);
            windowStart = (windowStart + 3L) & ~3L;
            p("  PCREL_DATA_WINDOW target=" + hex(target)
                + " range=" + hex(windowStart) + ".." + hex(windowEnd));

            for (long at = windowStart; at + 3L <= windowEnd && lines < MAX_LINES; at += 4L) {
                try {
                    long value = u32(at);
                    Function targetFunction = null;
                    MemoryBlock valueBlock = block(value);
                    if (valueBlock != null) {
                        targetFunction = currentProgram.getFunctionManager()
                            .getFunctionAt(addr(value));
                    }
                    p("    PCREL_DATA_WORD slot=" + hex(at)
                        + " value=" + hex(value)
                        + (targetFunction == null ? "" :
                            " function=" + targetFunction.getName()
                                + "@" + targetFunction.getEntryPoint()));
                }
                catch (Exception e) {
                    p("    PCREL_DATA_READ_ERROR slot=" + hex(at)
                        + " error=" + e.getMessage());
                }
            }
            windowsPrinted++;
        }

        p("614_PCREL_ADD_PC_INSTRUCTIONS=" + addPcInstructions);
        p("614_PCREL_EFFECTIVE_DATA_TARGETS=" + effectiveDataTargets);
        p("614_PCREL_TARGETS_NEAR_POINTER_RUNS=" + nearbyRunTargets);
        p("614_PCREL_TARGETS_PRINTED=" + printed);
        p("614_PCREL_DATA_WINDOWS_PRINTED=" + windowsPrinted);
        p("PC-relative effective-address reconstruction is a static candidate and should be checked against the disassembly.");
    }

    private void scan614CodePointerRuns() {
        dynamic614CodePointerRunRanges.clear();
        p("");
        p("============================================================");
        p("614_0_0 CONTIGUOUS FUNCTION-POINTER RUN SCAN");
        p("Finds aligned 32-bit words in data blocks that point to known function entries.");
        p("This scan does not modify the listing or infer vtable semantics automatically.");
        p("READ ONLY");
        p("============================================================");

        java.util.Map<Long, String> entryNames =
            new java.util.HashMap<Long, String>();
        int functionsIndexed = 0;

        try {
            Address defaultSpaceAddress =
                currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0);
            ghidra.program.model.address.AddressSpace defaultSpace =
                defaultSpaceAddress.getAddressSpace();
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);

            while (fit.hasNext() && !monitor.isCancelled()) {
                Function f = fit.next();
                Address entry = f.getEntryPoint();
                if (entry == null || !entry.getAddressSpace().equals(defaultSpace)) continue;
                long key = entry.getOffset() & 0xffffffffL;
                Long boxed = Long.valueOf(key);
                if (!entryNames.containsKey(boxed)) {
                    entryNames.put(boxed, f.getName() + "@" + entry);
                    functionsIndexed++;
                }
            }
        }
        catch (Exception e) {
            p("614_CODE_POINTER_INDEX_ERROR=" + e.getClass().getSimpleName()
                + ": " + e.getMessage());
            return;
        }

        p("614_CODE_POINTER_FUNCTION_ENTRIES_INDEXED=" + functionsIndexed);

        int[] stats = new int[] { 0, 0, 0 };
        MemoryBlock[] blocks = memory().getBlocks();

        for (MemoryBlock b : blocks) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || b.isExecute()
                    || !isDefaultDynamicAddressBlock(b)) continue;

            long pos = (b.getStart().getOffset() + 3L) & ~3L;
            long end = b.getEnd().getOffset();
            byte[] buf = new byte[DYNAMIC_SCAN_CHUNK];
            List<Long> runSlots = new ArrayList<Long>();
            List<Long> runValues = new ArrayList<Long>();
            List<String> runTargets = new ArrayList<String>();

            while (pos + 3L <= end && !monitor.isCancelled() && lines < MAX_LINES) {
                int want = (int)Math.min((long)DYNAMIC_SCAN_CHUNK, end - pos + 1L);
                want -= want % 4;
                if (want < 4) break;

                try {
                    memory().getBytes(addr(pos), buf, 0, want);
                }
                catch (Exception e) {
                    p("614_CODE_POINTER_SCAN_READ_ERROR block=" + b.getName()
                        + " at=" + hex(pos) + " error=" + e.getMessage());
                    report614FunctionPointerRun(
                        b.getName(), runSlots, runValues, runTargets, stats);
                    pos += want;
                    continue;
                }

                for (int i = 0; i + 3 < want; i += 4) {
                    long slot = pos + i;
                    long value = ((long)(buf[i] & 0xff))
                        | ((long)(buf[i + 1] & 0xff) << 8)
                        | ((long)(buf[i + 2] & 0xff) << 16)
                        | ((long)(buf[i + 3] & 0xff) << 24);
                    String targetName = entryNames.get(Long.valueOf(value));

                    if (targetName != null) {
                        runSlots.add(Long.valueOf(slot));
                        runValues.add(Long.valueOf(value));
                        runTargets.add(targetName);
                    }
                    else {
                        report614FunctionPointerRun(
                            b.getName(), runSlots, runValues, runTargets, stats);
                    }
                }
                pos += want;
            }

            report614FunctionPointerRun(
                b.getName(), runSlots, runValues, runTargets, stats);
        }

        p("614_CODE_POINTER_RUNS_FOUND=" + stats[0]);
        p("614_CODE_POINTER_RUNS_PRINTED=" + stats[1]);
        p("614_CODE_POINTER_ENTRIES_PRINTED=" + stats[2]);
        p("614_CODE_POINTER_MIN_RUN_LENGTH=4");
        p("Pointer runs are candidates; table type/ownership still requires cross-reference validation.");
    }

    private boolean is614RfConfigFunctionTarget(String functionName) {
        if (functionName == null) return false;
        String n = functionName.toLowerCase();

        String[] terms = {
            "get_rfm_path_info_tbl",
            "get_signals_info",
            "get_ant_switch_path_info",
            "get_phy_device_cfg",
            "get_logical_device_cfg",
            "get_antenna_path_table_cfg",
            "get_logical_path_config",
            "get_ant_path_info_config",
            "get_sig_path_info_config",
            "get_rffe_speeds_info",
            "path_cfg_data_get",
            "fbrx_cfg_data_get",
            "get_fbrx_path_table_cfg",
            "band_split_cfg_data_get",
            "timing_cfg_data_get",
            "get_lte_properties",
            "get_wcdma_properties",
            "get_gsm_properties",
            "get_cmn_properties",
            "get_nr_bands_bitmask_in_endc",
            "get_rfcard_data",
            "rfc_card_instance_get",
            "rfc_get_remapped_device_info",
            "get_alt_path_selection_tbl",
            "get_irat_alt_path_selection_tbl",
            "rfc_hwid614_qrm865ab_v3_ag_"
        };

        for (String term : terms) {
            if (n.contains(term)) return true;
        }
        return false;
    }

    /**
     * Dump a small read-only window around a DATA reference to an RFC method.
     * These windows help distinguish function-pointer/vtable slots from
     * unrelated data references. Offsets are only used in the default space.
     */
    private void scan614ReferenceNeighborhood(
            Address from, java.util.Set<Long> seenWindows) {
        if (from == null || seenWindows == null) return;

        try {
            ghidra.program.model.address.AddressSpace defaultSpace =
                currentProgram.getAddressFactory().getDefaultAddressSpace();
            if (!from.getAddressSpace().isMemorySpace()
                    || !from.getAddressSpace().equals(defaultSpace)) {
                return;
            }

            long sourceOffset = from.getOffset();
            MemoryBlock owner = memory().getBlock(from);
            if (owner == null || !owner.isInitialized()
                    || !isDefaultDynamicAddressBlock(owner)) {
                return;
            }

            long center = sourceOffset & ~3L;
            Long key = Long.valueOf(center);
            if (!seenWindows.add(key)) return;

            long start = Math.max(owner.getStart().getOffset(), center - 0x10L);
            long end = Math.min(owner.getEnd().getOffset(), center + 0x10L);
            start = (start + 3L) & ~3L;

            p("  RF_DATA_WINDOW from=" + from
                + " center=" + hex(center)
                + " block=" + owner.getName()
                + " range=" + hex(start) + ".." + hex(end));

            for (long at = start; at + 3L <= end; at += 4L) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                long value;
                try {
                    value = u32(at);
                }
                catch (Exception e) {
                    p("    RF_DATA_WORD slot=" + hex(at)
                        + " READ_ERROR=" + e.getMessage());
                    continue;
                }

                String target = "";
                MemoryBlock targetBlock = block(value);
                if (targetBlock != null) {
                    Function exact = currentProgram.getFunctionManager()
                        .getFunctionAt(addr(value));
                    Function containing = exact != null ? exact :
                        currentProgram.getFunctionManager()
                            .getFunctionContaining(addr(value));
                    target = " target_block=" + targetBlock.getName();
                    if (containing != null) {
                        target += " target_function=" + containing.getName()
                            + "@" + containing.getEntryPoint()
                            + (exact == null ? " (interior)" : " (entry)");
                    }
                }

                p("    RF_DATA_WORD slot=" + hex(at)
                    + " value=" + hex(value) + target);
            }
        }
        catch (Exception e) {
            p("  RF_DATA_WINDOW_ERROR from=" + from
                + " error=" + e.getClass().getSimpleName()
                + ": " + e.getMessage());
        }
    }

    /**
     * Prints disassembly and incoming references for RF-configuration APIs in
     * 614_0_0.mbn. This is static inspection only; it does not execute firmware
     * code or issue modem/DIAG commands.
     */
    private void scan614RfConfigFunctionDetails() {
        p("");
        p("============================================================");
        p("614_0_0 RF CONFIG FUNCTION DETAIL TRACE");
        p("Selected RFC path/band/timing/FBRX APIs, function instructions, and incoming references.");
        p("Only decoded instructions in executable blocks are printed.");
        p("READ ONLY");
        p("============================================================");

        int selected = 0;
        int functionsPrinted = 0;
        long instructionsPrinted = 0L;
        long referencesSeen = 0L;
        int referencesPrinted = 0;
        java.util.Set<Long> seenDataWindows = new java.util.HashSet<Long>();

        try {
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext() && !monitor.isCancelled() && lines < MAX_LINES) {
                Function f = fit.next();
                if (f.isThunk()) continue;
                if (!is614RfConfigFunctionTarget(f.getName())) continue;

                MemoryBlock owner;
                try {
                    owner = memory().getBlock(f.getEntryPoint());
                }
                catch (Exception e) {
                    continue;
                }
                if (owner == null || !owner.isExecute()
                        || !isDefaultDynamicAddressBlock(owner)) continue;

                selected++;
                if (functionsPrinted >= 64) continue;
                functionsPrinted++;

                p("");
                p("614_RF_FUNCTION #" + functionsPrinted
                    + " name=" + f.getName()
                    + " entry=" + f.getEntryPoint()
                    + " body_min=" + f.getBody().getMinAddress()
                    + " body_max=" + f.getBody().getMaxAddress()
                    + " body_bytes=" + f.getBody().getNumAddresses());

                int insCount = 0;
                InstructionIterator iit = listing().getInstructions(f.getBody(), true);
                while (iit.hasNext() && !monitor.isCancelled() && lines < MAX_LINES) {
                    Instruction ins = iit.next();
                    if (insCount < 72) {
                        p("  RF_INS " + ins.getAddress() + "  " + ins);
                    }
                    insCount++;
                }
                instructionsPrinted += insCount;
                p("  RF_INSTRUCTIONS_TOTAL=" + insCount
                    + (insCount > 72 ? " (printed first 72)" : ""));

                ReferenceIterator rit = currentProgram.getReferenceManager()
                    .getReferencesTo(f.getEntryPoint());
                int functionRefs = 0;
                int functionRefsPrinted = 0;
                while (rit.hasNext() && !monitor.isCancelled() && lines < MAX_LINES) {
                    Reference ref = rit.next();
                    functionRefs++;
                    referencesSeen++;

                    if (functionRefsPrinted >= 24) continue;
                    Address from = ref.getFromAddress();
                    Function caller = currentProgram.getFunctionManager()
                        .getFunctionContaining(from);
                    Instruction sourceIns = listing().getInstructionAt(from);
                    p("  RF_INCOMING_REF[" + functionRefsPrinted + "]"
                        + " from=" + from
                        + " type=" + ref.getReferenceType()
                        + " caller=" + (caller == null ? "<no-function>"
                            : caller.getName() + "@" + caller.getEntryPoint())
                        + " instruction=" + (sourceIns == null ? "<no-instruction>" : sourceIns));
                    if ("DATA".equalsIgnoreCase(String.valueOf(ref.getReferenceType()))) {
                        scan614ReferenceNeighborhood(from, seenDataWindows);
                    }
                    functionRefsPrinted++;
                    referencesPrinted++;
                }
                p("  RF_INCOMING_REFS_TOTAL=" + functionRefs
                    + " printed=" + functionRefsPrinted);
            }

            p("");
            p("614_RF_TARGET_FUNCTIONS_FOUND=" + selected);
            p("614_RF_TARGET_FUNCTIONS_PRINTED=" + functionsPrinted);
            p("614_RF_INSTRUCTIONS_COUNTED=" + instructionsPrinted);
            p("614_RF_INCOMING_REFERENCES_COUNTED=" + referencesSeen);
            p("614_RF_INCOMING_REFERENCES_PRINTED=" + referencesPrinted);
            if (selected == 0) {
                p("614_RF_DETAIL_NOTE=No selected non-thunk function was mapped to an executable default-space block.");
            }
        }
        catch (Exception e) {
            p("614_RF_FUNCTION_DETAIL_ERROR=" + e.getClass().getSimpleName()
                + ": " + e.getMessage());
        }
    }

    private void run614DynamicAddressDiscovery() {
        p("");
        p("============================================================");
        p("614_0_0 DYNAMIC FREQUENCY-FIELD TRACE");
        p("No fixed qdsp6sw.mbn addresses are assumed in this branch.");
        p("Find strings in the current image, then pointer slots and instruction leads.");
        p("READ ONLY: no modem commands, no DIAG packets, no program modifications.");
        p("============================================================");

        MemoryBlock[] blocks = memory().getBlocks();
        p("DYNAMIC_PROGRAM=" + currentProgram.getName());
        p("DYNAMIC_IMAGE_BASE=" + currentProgram.getImageBase());
        p("DYNAMIC_MEMORY_BLOCK_COUNT=" + blocks.length);

        for (int i = 0; i < blocks.length && i < 180; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            MemoryBlock b = blocks[i];
            long size = b.getEnd().getOffset() - b.getStart().getOffset() + 1L;
            p("  DYNAMIC_BLOCK name=" + b.getName()
                + " range=" + b.getStart() + ".." + b.getEnd()
                + " size=" + size
                + " initialized=" + b.isInitialized()
                + " read=" + b.isRead()
                + " write=" + b.isWrite()
                + " execute=" + b.isExecute());
        }

        p("");
        p("============================================================");
        p("614_0_0 RAW STRING DISCOVERY");
        p("Fields are matched as complete C strings, not as substrings.");
        p("============================================================");

        for (MemoryBlock b : blocks) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized()) continue;
            for (String label : DYNAMIC_RF_LABELS) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                search614StringInBlock(b, label);
            }
        }

        p("DYNAMIC_STRING_LABEL_COUNT=" + DYNAMIC_RF_LABELS.length);
        p("DYNAMIC_STRING_HITS=" + dynamic614StringHits.size());
        p("DYNAMIC_STRING_SCAN_BYTES_APPROX=" + dynamic614BytesScanned);

        for (DynamicStringHit hit : dynamic614StringHits) {
            printReferencesToAddress(hit.address, 16,
                "614_STRING_" + hit.label + "_" + hex(hit.address));
        }

        scan614DynamicPointerSlots(blocks);
        scan614DynamicDecodedInstructions(blocks);
        print614DynamicSummary();
    }

    private void scan614DynamicPointerSlots(MemoryBlock[] blocks) {
        p("");
        p("============================================================");
        p("614_0_0 DYNAMIC STRING-POINTER SLOT SCAN");
        p("Targets were discovered in the current program, not copied from another firmware.");
        p("Scans aligned 32-bit words in initialized non-executable blocks in the default address space.");
        p("============================================================");

        int shown = 0;
        for (MemoryBlock b : blocks) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || b.isExecute()
                    || !isDefaultDynamicAddressBlock(b)) continue;

            long pos = (b.getStart().getOffset() + 3L) & ~3L;
            long end = b.getEnd().getOffset();
            byte[] buf = new byte[DYNAMIC_SCAN_CHUNK];

            while (pos + 3L <= end && !monitor.isCancelled() && lines < MAX_LINES) {
                int want = (int)Math.min((long)DYNAMIC_SCAN_CHUNK, end - pos + 1L);
                want -= want % 4;
                if (want < 4) break;

                try {
                    memory().getBytes(addr(pos), buf, 0, want);
                }
                catch (Exception e) {
                    p("  DYNAMIC_PTR_READ_ERROR block=" + b.getName()
                        + " at=" + hex(pos) + " error=" + e.getMessage());
                    break;
                }

                for (int i = 0; i + 4 <= want; i += 4) {
                    dynamic614PointerWordsScanned++;
                    long value = ((long)(buf[i] & 0xff))
                        | ((long)(buf[i + 1] & 0xff) << 8)
                        | ((long)(buf[i + 2] & 0xff) << 16)
                        | ((long)(buf[i + 3] & 0xff) << 24);

                    String targetLabel = dynamic614StringAddressLabels.get(Long.valueOf(value));
                    if (targetLabel == null) continue;

                    long slot = pos + i;
                    dynamic614PointerHits.add(
                        new DynamicPointerHit(slot, value, targetLabel, b.getName()));
                    dynamic614ExactCodeTargets.put(Long.valueOf(slot),
                        "STRING_POINTER_SLOT:" + targetLabel + "@" + hex(slot));

                    long low = slot & 0xffffL;
                    if (low >= 0x1000L && !dynamic614Low16Targets.containsKey(Long.valueOf(low))) {
                        dynamic614Low16Targets.put(Long.valueOf(low),
                            "LOW16_POINTER_SLOT:" + targetLabel + "@" + hex(slot));
                    }

                    if (shown < DYNAMIC_POINTER_PRINT_LIMIT) {
                        p("  DYNAMIC_POINTER_SLOT target=" + targetLabel
                            + " string=" + hex(value)
                            + " slot=" + hex(slot)
                            + " block=" + b.getName());

                        long nearStart = Math.max(b.getStart().getOffset(), slot - 0x18L);
                        long nearEnd = Math.min(b.getEnd().getOffset(), slot + 0x1cL);
                        long near = (nearStart + 3L) & ~3L;
                        for (long at = near; at + 3L <= nearEnd && lines < MAX_LINES; at += 4L) {
                            try {
                                long word = u32(at);
                                String decoded = word == 0L ? null : readAsciiAt(word, 100);
                                p("    WORD slot=" + hex(at) + " value=" + hex(word)
                                    + (decoded == null ? "" : " text=\"" + decoded + "\""));
                            }
                            catch (Exception e) {
                                p("    WORD slot=" + hex(at) + " error=" + e.getMessage());
                            }
                        }
                        printReferencesToAddress(slot, 10, "614_POINTER_SLOT_" + hex(slot));
                        shown++;
                    }
                }
                pos += want;
            }
        }

        p("DYNAMIC_POINTER_WORDS_SCANNED=" + dynamic614PointerWordsScanned);
        p("DYNAMIC_POINTER_SLOTS_FOUND=" + dynamic614PointerHits.size());
        p("DYNAMIC_POINTER_SLOTS_PRINTED=" + shown);
        if (dynamic614PointerHits.isEmpty()) {
            p("DYNAMIC_POINTER_NOTE=No aligned absolute pointers found; relative or register-based references may still exist.");
        }
    }

    private void print614InstructionWindow(Instruction center, int before, int after) {
        if (center == null || dynamic614ContextsPrinted >= DYNAMIC_CONTEXT_LIMIT) return;
        dynamic614ContextsPrinted++;

        Function owner = currentProgram.getFunctionManager()
            .getFunctionContaining(center.getAddress());
        Address entry = owner == null ? null : owner.getEntryPoint();
        List<Instruction> previous = new ArrayList<Instruction>();
        Address cursor = center.getAddress();

        for (int i = 0; i < before; i++) {
            Instruction prior = listing().getInstructionBefore(cursor);
            if (prior == null) break;
            Function f = currentProgram.getFunctionManager()
                .getFunctionContaining(prior.getAddress());
            if (entry != null && (f == null || !entry.equals(f.getEntryPoint()))) break;
            previous.add(prior);
            cursor = prior.getAddress();
        }
        java.util.Collections.reverse(previous);

        p("    CONTEXT_BEGIN");
        for (Instruction prior : previous) p("      " + prior.getAddress() + "  " + prior);
        p("      >>> " + center.getAddress() + "  " + center);
        cursor = center.getAddress();

        for (int i = 0; i < after; i++) {
            Instruction next = listing().getInstructionAfter(cursor);
            if (next == null) break;
            Function f = currentProgram.getFunctionManager()
                .getFunctionContaining(next.getAddress());
            if (entry != null && (f == null || !entry.equals(f.getEntryPoint()))) break;
            p("      " + next.getAddress() + "  " + next);
            cursor = next.getAddress();
        }
        p("    CONTEXT_END");
    }

    private void scan614DynamicDecodedInstructions(MemoryBlock[] blocks) {
        p("");
        p("============================================================");
        p("614_0_0 DECODED-INSTRUCTION FIELD REFERENCE SCAN");
        p("Uses the program-wide instruction iterator, not each block's start address.");
        p("This is intentional: Ghidra may return an empty block-local iterator when the start is not an instruction.");
        p("Exact full-address hits and low-16-bit immediate candidates are reported separately.");
        p("============================================================");

        int exactShown = 0;
        int lowShown = 0;
        java.util.Map<Long, Integer> exactCounts =
            new java.util.HashMap<Long, Integer>();
        java.util.Map<Long, Integer> lowCounts =
            new java.util.HashMap<Long, Integer>();
        java.util.Map<Long, Long> blockCounts =
            new java.util.HashMap<Long, Long>();

        InstructionIterator it = listing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled() && lines < MAX_LINES) {
            Instruction ins = it.next();
            Address insAddress = ins.getAddress();
            MemoryBlock ownerBlock;
            try {
                ownerBlock = memory().getBlock(insAddress);
            }
            catch (Exception e) {
                continue;
            }
            if (ownerBlock == null || !ownerBlock.isInitialized()
                    || !isDefaultDynamicAddressBlock(ownerBlock)) continue;

            dynamic614DecodedInstructionsAllBlocks++;
            if (ownerBlock.isExecute()) dynamic614DecodedInstructionsExecBlocks++;
            Long blockStart = Long.valueOf(ownerBlock.getStart().getOffset());
            Long oldBlockCount = blockCounts.get(blockStart);
            blockCounts.put(blockStart,
                Long.valueOf(oldBlockCount == null ? 1L : oldBlockCount.longValue() + 1L));

            for (int op = 0; op < ins.getNumOperands(); op++) {
                Object[] objects = ins.getOpObjects(op);
                for (Object object : objects) {
                    boolean isScalar = object instanceof Scalar;
                    long value;
                    if (isScalar) {
                        value = ((Scalar)object).getUnsignedValue() & 0xffffffffL;
                    }
                    else if (object instanceof Address) {
                        value = ((Address)object).getOffset() & 0xffffffffL;
                    }
                    else continue;

                    String exactLabel = dynamic614ExactCodeTargets.get(Long.valueOf(value));
                    if (exactLabel != null) {
                        dynamic614ExactCodeHits++;
                        Integer old = exactCounts.get(Long.valueOf(value));
                        exactCounts.put(Long.valueOf(value),
                            Integer.valueOf(old == null ? 1 : old.intValue() + 1));

                        if (exactShown < DYNAMIC_CODE_HIT_PRINT_LIMIT) {
                            p("  614_CODE_EXACT_HIT target=" + exactLabel
                                + " value=" + hex(value)
                                + " at=" + insAddress
                                + " operand=" + op
                                + " function=" + functionInfo(insAddress.getOffset())
                                + " instruction=" + ins);
                            print614InstructionWindow(ins, 3, 5);
                            exactShown++;
                        }
                    }

                    if (!isScalar || value > 0xffffL) continue;
                    long low = value & 0xffffL;
                    if (low < 0x1000L) continue;
                    String lowLabel = dynamic614Low16Targets.get(Long.valueOf(low));
                    if (lowLabel == null) continue;

                    dynamic614Low16CodeHits++;
                    Integer oldLow = lowCounts.get(Long.valueOf(low));
                    lowCounts.put(Long.valueOf(low),
                        Integer.valueOf(oldLow == null ? 1 : oldLow.intValue() + 1));
                    if (lowShown < 140 && (oldLow == null || oldLow.intValue() < 5)) {
                        p("  614_CODE_LOW16_CANDIDATE target=" + lowLabel
                            + " immediate=" + hex(value)
                            + " at=" + insAddress
                            + " operand=" + op
                            + " function=" + functionInfo(insAddress.getOffset())
                            + " instruction=" + ins);
                        lowShown++;
                    }
                }
            }
        }

        for (MemoryBlock b : blocks) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || !isDefaultDynamicAddressBlock(b)) continue;
            Long count = blockCounts.get(Long.valueOf(b.getStart().getOffset()));
            p("  614_DECODED_BLOCK name=" + b.getName()
                + " execute=" + b.isExecute()
                + " instructions=" + (count == null ? 0L : count.longValue()));
        }

        for (java.util.Map.Entry<Long, Integer> entry : exactCounts.entrySet()) {
            if (lines >= MAX_LINES) break;
            p("  614_EXACT_TARGET_COUNT target="
                + dynamic614ExactCodeTargets.get(entry.getKey())
                + " hits=" + entry.getValue());
        }
        for (java.util.Map.Entry<Long, Integer> entry : lowCounts.entrySet()) {
            if (lines >= MAX_LINES) break;
            p("  614_LOW16_TARGET_COUNT target="
                + dynamic614Low16Targets.get(entry.getKey())
                + " hits=" + entry.getValue());
        }

        p("DYNAMIC_DECODED_INSTRUCTIONS_ALL_BLOCKS=" + dynamic614DecodedInstructionsAllBlocks);
        p("DYNAMIC_DECODED_INSTRUCTIONS_EXECUTABLE_BLOCKS=" + dynamic614DecodedInstructionsExecBlocks);
        p("DYNAMIC_EXACT_CODE_HITS_TOTAL=" + dynamic614ExactCodeHits);
        p("DYNAMIC_EXACT_CODE_HITS_PRINTED=" + exactShown);
        p("DYNAMIC_LOW16_CANDIDATES_TOTAL=" + dynamic614Low16CodeHits);
        p("DYNAMIC_LOW16_CANDIDATES_PRINTED=" + lowShown);
        p("DYNAMIC_CONTEXT_WINDOWS_PRINTED=" + dynamic614ContextsPrinted);
        if (dynamic614DecodedInstructionsAllBlocks == 0L) {
            p("DYNAMIC_CODE_SCAN_WARNING=Program-wide iterator found no decoded instruction in the default address space; check the listing and active program.");
        }
    }

    private void print614DynamicSummary() {
        p("");
        p("============================================================");
        p("614_0_0 DYNAMIC FREQUENCY TRACE SUMMARY");
        p("TRACE_BUILD=" + TRACE_BUILD);
        p("PROGRAM=" + currentProgram.getName());
        p("DYNAMIC_STRING_HITS=" + dynamic614StringHits.size());
        p("DYNAMIC_POINTER_SLOTS=" + dynamic614PointerHits.size());
        p("DYNAMIC_POINTER_WORDS_SCANNED=" + dynamic614PointerWordsScanned);
        p("DYNAMIC_STRING_SCAN_BYTES_APPROX=" + dynamic614BytesScanned);
        p("DYNAMIC_DECODED_INSTRUCTIONS_ALL_BLOCKS=" + dynamic614DecodedInstructionsAllBlocks);
        p("DYNAMIC_DECODED_INSTRUCTIONS_EXECUTABLE_BLOCKS=" + dynamic614DecodedInstructionsExecBlocks);
        p("DYNAMIC_EXACT_CODE_HITS_TOTAL=" + dynamic614ExactCodeHits);
        p("DYNAMIC_LOW16_CANDIDATES_TOTAL=" + dynamic614Low16CodeHits);
        p("Hits are static leads only; they do not by themselves prove a live RX tuning path.");
        p("No modem commands were created or transmitted.");
        p("============================================================");
    }


    @Override
    public void run() throws Exception {
        p("============================================================");
        p(" Ghidra_RFDEBUG_Trace");
        p(" TRACE_BUILD=" + TRACE_BUILD);
        p(" READ-ONLY RF FREQUENCY / RFDEBUG STATIC TRACE");
        p("No FTM/RF command is generated or transmitted.");
        p("============================================================");
        p("PROGRAM=" + currentProgram.getName());
        p("IMAGE_BASE=" + currentProgram.getImageBase());

        String programLower = currentProgram.getName().toLowerCase();
        if (programLower.contains("614_0_0")) {
            p("TARGET_PROFILE=614_0_0_DYNAMIC_FREQUENCY_DISCOVERY");
            p("Legacy qdsp6sw.mbn addresses are disabled for this program.");
            scan614FunctionInventory();
            scanNamedFunctions();
            scan614RfConfigFunctionDetails();
            scan614CodePointerRuns();
            scan614PcRelativeDataReferences();
            scanFtmLocatorStrings();
            run614DynamicAddressDiscovery();
        }
        else {
            p("TARGET_PROFILE=LEGACY_RFDEBUG_PROPERTY_TABLE");
            p("Using the existing C9199FB8 RFDEBUG property-table path for the qdsp6sw-style image.");
            dumpRadioConfigFieldNameTable();
            dumpAdjacentRadioConfigNamePool();
            scanRfTuneFieldStrings();
            scanRadioConfigMessageRecords();
            scanRfDebugSubsysImmediateCandidates();

            p("");
            p("INTERPRETATION:");
            p("Property IDs 26 and 28 are checked against the confirmed qdsp6sw RFDEBUG property_names[] table.");
            p("A 0x007B immediate hit is only a candidate; inspect comparison/branch context before assigning dispatcher semantics.");
            printStructure18ExecutionFooter();
        }

        p("DONE");
        p("No program data or structures modified.");
    }
}