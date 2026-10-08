import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ReferenceIterator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/*
 * Ghidra_RFDEBUG_Trace
 *
 * Focused read-only locator for the DIAG -> FTM -> RFDEBUG routing chain.
 *
 * Target structure:
 *   DIAG master record
 *      subsys = 0x000B
 *      table pointer -> FTM selector table
 *      selector 0x007B -> common FTM dispatcher
 *
 * Also checks the reference-build addresses:
 *   master       0xC8DC3B54
 *   FTM table    0xC37BD1E8
 *   common disp  0xD8150ED8
 *
 * Those addresses are only references. Do not assume they belong to the
 * current firmware. The script first verifies whether they are mapped.
 *
 * READ ONLY. No modem access. No program modifications.
 */

public class Ghidra_RFDEBUG_Trace extends GhidraScript {

    private static final String TRACE_BUILD = "DIAG-FTM-MASTER-1";

    private static final long REF_MASTER = 0xC8DC3B54L;
    private static final long REF_TABLE  = 0xC37BD1E8L;
    private static final long REF_DISP   = 0xD8150ED8L;

    private static final int TARGET_SUBSYS = 0x000B;
    private static final int TARGET_SELECTOR = 0x007B;

    private static final int MAX_SCAN_POSITIONS = 2500000;
    private static final int MAX_CANDIDATES = 64;
    private static final int MAX_TABLE_ENTRIES = 96;
    private static final int MAX_LINES = 5000;

    private int lines = 0;

    private Address addr(long off) {
        return currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(off);
    }

    private Memory memory() {
        return currentProgram.getMemory();
    }

    private boolean mapped(long off) {
        try {
            return memory().contains(addr(off));
        }
        catch (Exception e) {
            return false;
        }
    }

    private MemoryBlock block(long off) {
        if (!mapped(off)) return null;
        try {
            return memory().getBlock(addr(off));
        }
        catch (Exception e) {
            return null;
        }
    }

    private boolean initialized(long off, int len) {
        MemoryBlock b = block(off);
        if (b == null || !b.isInitialized()) return false;

        long end = off + len - 1L;
        return end >= off && end <= b.getEnd().getOffset();
    }

    private long u32(long off) throws Exception {
        return memory().getInt(addr(off)) & 0xffffffffL;
    }

    private int u16(long off) throws Exception {
        return memory().getShort(addr(off)) & 0xffff;
    }

    private String hex(long v) {
        return String.format("0x%08X", v & 0xffffffffL);
    }

    private String fn(long off) {
        try {
            Function f = currentProgram.getFunctionManager().getFunctionContaining(addr(off));
            return f == null ? "<no-function>" :
                f.getName() + " @ " + f.getEntryPoint();
        }
        catch (Exception e) {
            return "<error>";
        }
    }

    private boolean plausibleHandler(long off) {
        MemoryBlock b = block(off);
        return b != null && b.isExecute();
    }

    private long[] tableEntry(long table, int index) throws Exception {
        long p = table + (long)index * 8L;
        if (!initialized(p, 8)) return null;

        int lo = u16(p);
        int hi = u16(p + 2);
        long handler = u32(p + 4);

        if (lo > hi) return null;
        if (handler == 0) return null;

        return new long[] { lo, hi, handler };
    }

    private int validEntries(long table, int max) throws Exception {
        int good = 0;
        for (int i = 0; i < Math.min(max, MAX_TABLE_ENTRIES); i++) {
            if (monitor.isCancelled()) break;
            if (tableEntry(table, i) != null) good++;
        }
        return good;
    }

    private static class Candidate {
        long record;
        long table;
        int delay;
        int cmd;
        int subsys;
        int count;
        int proc;
        int good;
        int executable;
        int selectorIndex;
        long selectorHandler;
        int score;

        Candidate(long record, long table, int delay, int cmd, int subsys,
                  int count, int proc, int good, int executable,
                  int selectorIndex, long selectorHandler, int score) {
            this.record = record;
            this.table = table;
            this.delay = delay;
            this.cmd = cmd;
            this.subsys = subsys;
            this.count = count;
            this.proc = proc;
            this.good = good;
            this.executable = executable;
            this.selectorIndex = selectorIndex;
            this.selectorHandler = selectorHandler;
            this.score = score;
        }
    }

    private Candidate inspectMaster16(long p) {
        try {
            if (!initialized(p, 0x18)) return null;

            int delay = u16(p);
            int cmd = u16(p + 2);
            int subsys = u16(p + 4);
            int count = u16(p + 6);
            int proc = u16(p + 8);
            long table = u32(p + 0x10);

            if (subsys != TARGET_SUBSYS) return null;
            if (count < 1 || count > MAX_TABLE_ENTRIES) return null;
            if (delay != 0 && delay != 1) return null;
            if (cmd != 0 && cmd != 0x00FF) return null;
            if (proc > 0x1000) return null;
            if (!mapped(table)) return null;

            int good = validEntries(table, count);
            if (good < 2) return null;

            int executable = 0;
            int selectorIndex = -1;
            long selectorHandler = 0;

            for (int i = 0; i < count && i < MAX_TABLE_ENTRIES; i++) {
                long[] e = tableEntry(table, i);
                if (e == null) continue;
                if (plausibleHandler(e[2])) executable++;
                if (e[0] <= TARGET_SELECTOR && TARGET_SELECTOR <= e[1]) {
                    selectorIndex = i;
                    selectorHandler = e[2];
                }
            }

            int score = 20 + Math.min(good, 8);
            if (executable > 0) score += 12;
            if (selectorIndex >= 0) score += 25;

            return new Candidate(p, table, delay, cmd, subsys, count, proc,
                                 good, executable, selectorIndex,
                                 selectorHandler, score);
        }
        catch (Exception e) {
            return null;
        }
    }

    private Candidate inspectMasterByte(long p) {
        try {
            if (!initialized(p, 0x18)) return null;

            int delay = memory().getByte(addr(p)) & 0xff;
            int cmd = memory().getByte(addr(p + 1)) & 0xff;
            int subsys = u16(p + 2);
            int count = u16(p + 4);
            int proc = u16(p + 6);
            long table = u32(p + 0x10);

            if (subsys != TARGET_SUBSYS) return null;
            if (count < 1 || count > MAX_TABLE_ENTRIES) return null;
            if (delay != 0 && delay != 1) return null;
            if (cmd != 0 && cmd != 0x00FF) return null;
            if (proc > 0x1000) return null;
            if (!mapped(table)) return null;

            int good = validEntries(table, count);
            if (good < 2) return null;

            int executable = 0;
            int selectorIndex = -1;
            long selectorHandler = 0;

            for (int i = 0; i < count && i < MAX_TABLE_ENTRIES; i++) {
                long[] e = tableEntry(table, i);
                if (e == null) continue;
                if (plausibleHandler(e[2])) executable++;
                if (e[0] <= TARGET_SELECTOR && TARGET_SELECTOR <= e[1]) {
                    selectorIndex = i;
                    selectorHandler = e[2];
                }
            }

            int score = 18 + Math.min(good, 8);
            if (executable > 0) score += 12;
            if (selectorIndex >= 0) score += 25;

            return new Candidate(p, table, delay, cmd, subsys, count, proc,
                                 good, executable, selectorIndex,
                                 selectorHandler, score);
        }
        catch (Exception e) {
            return null;
        }
    }

    private void dumpTable(Candidate c) {
        if (lines >= MAX_LINES) return;

        println("");
        println("------------------------------------------------------------");
        println("FTM TABLE @ " + hex(c.table));
        println("record @ " + hex(c.record));
        println("count=" + c.count + " valid=" + c.good +
                " executable_handlers=" + c.executable);

        int shown = 0;
        for (int i = 0; i < c.count && i < MAX_TABLE_ENTRIES && shown < MAX_TABLE_ENTRIES; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            try {
                long[] e = tableEntry(c.table, i);
                if (e == null) continue;

                String hit = (e[0] <= TARGET_SELECTOR && TARGET_SELECTOR <= e[1])
                    ? "  <<< TARGET 0x7B >>>" : "";

                println(String.format(
                    "  entry[%02d] @%s  lo=%s hi=%s handler=%s  %s",
                    i,
                    hex(c.table + (long)i * 8L),
                    hex(e[0]),
                    hex(e[1]),
                    hex(e[2]),
                    hit));
                lines++;
                shown++;
            }
            catch (Exception ignored) {}
        }

        println("TARGET SELECTOR INDEX=" + c.selectorIndex);
        println("TARGET HANDLER=" + (c.selectorIndex < 0
            ? "<not found>" : hex(c.selectorHandler)));
        if (c.selectorIndex >= 0) {
            println("TARGET HANDLER MAPPED=" + mapped(c.selectorHandler));
            println("TARGET HANDLER EXEC=" + plausibleHandler(c.selectorHandler));
            println("TARGET HANDLER FUNCTION=" + fn(c.selectorHandler));
        }
        lines += 4;
    }

    private void inspectReferenceAddresses() {
        println("");
        println("============================================================");
        println("REFERENCE ADDRESS IDENTITY CHECK");
        println("============================================================");

        long[] refs = { REF_MASTER, REF_TABLE, REF_DISP };
        String[] names = { "MASTER", "FTM_TABLE", "COMMON_DISPATCH" };

        for (int i = 0; i < refs.length; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            MemoryBlock b = block(refs[i]);
            println(names[i] + " " + hex(refs[i]) +
                    " mapped=" + (b != null) +
                    " block=" + (b == null ? "<none>" : b.getName()) +
                    " exec=" + (b != null && b.isExecute()));
            lines++;
        }

        println("CURRENT IMAGE BASE=" + currentProgram.getImageBase());
        println("PROGRAM=" + currentProgram.getName());
        lines += 2;
    }

    private void scanMasterRecords() throws Exception {
        println("");
        println("============================================================");
        println("STRUCTURAL DIAG MASTER TABLE SCAN");
        println("TARGET: SUBSYS 0x000B / FTM");
        println("Layouts tested: 16-bit fields and byte+16-bit variant");
        println("READ ONLY / HARD LIMITED");
        println("============================================================");

        List<Candidate> hits = new ArrayList<Candidate>();
        Memory mem = memory();

        long scanned = 0;

        for (MemoryBlock b : mem.getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!b.isInitialized() || b.isExecute()) continue;

            long start = b.getStart().getOffset();
            long end = b.getEnd().getOffset();

            // Master records are aligned in the known reference layout.
            long p = (start + 3L) & ~3L;
            long limit = end - 0x18L + 1L;
            if (limit < p) continue;

            println("SCAN " + b.getName() + " " + hex(start) + " - " + hex(end));
            lines++;

            while (p <= limit && scanned < MAX_SCAN_POSITIONS) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                // Avoid expensive full-record tests unless the possible subsys
                // field already equals 0x000B.
                boolean possible16 = false;
                boolean possibleByte = false;

                try {
                    possible16 = u16(p + 4) == TARGET_SUBSYS;
                    possibleByte = u16(p + 2) == TARGET_SUBSYS;
                }
                catch (Exception ignored) {}

                if (possible16) {
                    Candidate c = inspectMaster16(p);
                    if (c != null && hits.size() < MAX_CANDIDATES) hits.add(c);
                }

                if (possibleByte) {
                    Candidate c = inspectMasterByte(p);
                    if (c != null && hits.size() < MAX_CANDIDATES) hits.add(c);
                }

                p += 4L;
                scanned++;
            }
        }

        Collections.sort(hits, new Comparator<Candidate>() {
            @Override
            public int compare(Candidate a, Candidate b) {
                return Integer.compare(b.score, a.score);
            }
        });

        println("");
        println("============================================================");
        println("MASTER CANDIDATES=" + hits.size());
        println("SCANNED POSITIONS=" + scanned);
        println("============================================================");
        lines += 3;

        int shown = 0;
        for (Candidate c : hits) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (shown++ >= MAX_CANDIDATES) break;

            println("");
            println(String.format(
                "CANDIDATE #%d score=%d record=%s table=%s count=%d selector_index=%d",
                shown, c.score, hex(c.record), hex(c.table),
                c.count, c.selectorIndex));
            println(String.format(
                "  delay=0x%04X cmd=0x%04X subsys=0x%04X proc=0x%04X",
                c.delay, c.cmd, c.subsys, c.proc));
            println("  valid=" + c.good + " executable=" + c.executable);
            lines += 3;

            dumpTable(c);
        }

        if (hits.isEmpty()) {
            println("");
            println("NO FTM MASTER TABLE CANDIDATE FOUND.");
            println("If the reference addresses are also unmapped, this is likely");
            println("the wrong firmware image for DIAG/FTM routing.");
            lines += 3;
        }
    }

    private void inspectHandlerCallers(long handler) {
        if (!mapped(handler) || lines >= MAX_LINES) return;

        Function f = currentProgram.getFunctionManager()
            .getFunctionContaining(addr(handler));
        if (f == null) return;

        println("");
        println("------------------------------------------------------------");
        println("TARGET HANDLER CALLERS");
        println("FUNCTION=" + f.getName() + " @ " + f.getEntryPoint());
        lines += 2;

        ReferenceIterator it =
            currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());

        int n = 0;
        while (it.hasNext() && n < 16 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            if (it.next().getReferenceType().isCall()) {
                n++;
            }
        }

        println("CALL REFERENCES FOUND=" + n);
        lines++;
    }

    @Override
    public void run() throws Exception {
        println("============================================================");
        println(" Ghidra_RFDEBUG_Trace");
        println(" TRACE_BUILD=" + TRACE_BUILD);
        println(" DIAG -> FTM MASTER LOCATOR / READ ONLY");
        println("============================================================");

        inspectReferenceAddresses();
        scanMasterRecords();

        println("");
        println("============================================================");
        println("NEXT ROUTING TARGET");
        println("If selector 0x7B is found, the next static target is its common");
        println("handler. Do not chase generic 0x4B literals in unrelated code.");
        println("============================================================");

        println("");
        println("DONE");
        println("No memory, symbols, comments, or program structures modified.");
    }
}
