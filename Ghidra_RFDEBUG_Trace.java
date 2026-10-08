import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Data;
import ghidra.program.model.listing.Function;
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
        p("");
        p("DONE");
        p("No program data or structures modified.");
    }
}
