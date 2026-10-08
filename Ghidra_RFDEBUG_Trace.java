import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class Ghidra_RFDEBUG_Trace extends GhidraScript {

    private static final int MAX_FUNCTION_INSNS = 20000;
    private static final int MAX_GLOBAL_INSNS = 1800000;
    private static final int MAX_FUNCTIONS = 120;
    private static final int MAX_LINES = 16000;

    private static final int RAW_CHUNK = 0x10000;
    private static final int MAX_RAW_HITS = 200;
    private static final int RAW_CONTEXT_BEFORE = 10;
    private static final int RAW_CONTEXT_AFTER = 26;

    private int lines = 0;

    private String safe(String s) {
        return s == null ? "" : s.replace('\r', ' ').replace('\n', ' ');
    }

    private boolean containsImm(String s, long v) {
        String x = safe(s).toLowerCase();
        String h = String.format("#0x%x", v);
        return x.contains(h);
    }

    private boolean isCompare(String s) {
        return safe(s).toLowerCase().contains("cmp.");
    }

    private boolean isCall(String s) {
        String x = safe(s).toLowerCase();
        return x.contains("call ") || x.startsWith("call.") || x.contains(" call.");
    }

    private boolean is4BCompare(String s) {
        if (!isCompare(s) || !containsImm(s, 0x4b)) return false;
        String x = safe(s).toLowerCase();
        return x.contains("cmpb") ||
               x.contains("cmph") ||
               x.contains("cmp.eq") ||
               x.contains("cmp.gt") ||
               x.contains("cmp.gtu");
    }

    private boolean is0BCompare(String s) {
        if (!isCompare(s) || !containsImm(s, 0x0b)) return false;
        String x = safe(s).toLowerCase();
        return x.contains("cmpb") ||
               x.contains("cmph") ||
               x.contains("cmp.eq") ||
               x.contains("cmp.gt") ||
               x.contains("cmp.gtu");
    }

    private boolean is7BCompare(String s) {
        if (!isCompare(s) || !containsImm(s, 0x7b)) return false;
        String x = safe(s).toLowerCase();
        return x.contains("cmpb") ||
               x.contains("cmph") ||
               x.contains("cmp.eq") ||
               x.contains("cmp.gt") ||
               x.contains("cmp.gtu");
    }

    private boolean hasMemoryRead(String s) {
        String x = safe(s).toLowerCase();
        return x.contains("memub") || x.contains("memuh") ||
               x.contains("memw") || x.contains("memd") ||
               x.contains("memb");
    }

    private Function functionContaining(Address a) {
        return currentProgram.getFunctionManager().getFunctionContaining(a);
    }

    private ArrayList<Instruction> collect(Function f) {
        ArrayList<Instruction> out = new ArrayList<Instruction>();
        if (f == null) return out;

        InstructionIterator it =
            currentProgram.getListing().getInstructions(f.getBody(), true);

        int n = 0;
        while (it.hasNext() && n < MAX_FUNCTION_INSNS) {
            if (monitor.isCancelled()) return out;
            out.add(it.next());
            n++;
        }
        return out;
    }

    private int findNext(ArrayList<Instruction> a, int from, boolean want0b, boolean want7b) {
        for (int i = from + 1; i < a.size() && i <= from + 120; i++) {
            String s = safe(a.get(i).toString());
            if ((want0b && is0BCompare(s)) || (want7b && is7BCompare(s))) {
                return i;
            }
        }
        return -1;
    }

    private void printWindow(ArrayList<Instruction> a, int center, int before, int after) {
        int start = Math.max(0, center - before);
        int end = Math.min(a.size(), center + after + 1);
        for (int i = start; i < end && lines < MAX_LINES; i++) {
            Instruction ins = a.get(i);
            String s = safe(ins.toString());
            if (i == center ||
                is4BCompare(s) ||
                is0BCompare(s) ||
                is7BCompare(s) ||
                isCall(s) ||
                hasMemoryRead(s)) {
                println("  " + ins.getAddress() + " : " + s);
                lines++;
            }
        }
    }

    private void analyzeFunction(Function f) {
        if (f == null || lines >= MAX_LINES) return;

        ArrayList<Instruction> a = collect(f);
        if (a.isEmpty()) return;

        int count4 = 0, count0 = 0, count7 = 0, calls = 0;
        ArrayList<Integer> fourB = new ArrayList<Integer>();

        for (int i = 0; i < a.size(); i++) {
            if (monitor.isCancelled()) return;
            String s = safe(a.get(i).toString());

            if (is4BCompare(s)) {
                count4++;
                fourB.add(i);
            }
            if (is0BCompare(s)) count0++;
            if (is7BCompare(s)) count7++;
            if (isCall(s)) calls++;
        }

        if (count4 == 0) return;

        boolean high = false;
        int best0 = -1, best7 = -1, best4For0 = -1, best4For7 = -1;
        int best0Dist = Integer.MAX_VALUE, best7Dist = Integer.MAX_VALUE;

        for (int i : fourB) {
            int j0 = findNext(a, i, true, false);
            int j7 = findNext(a, i, false, true);

            if (j0 >= 0 && j0 - i < best0Dist) {
                best0 = j0;
                best0Dist = j0 - i;
                best4For0 = i;
            }
            if (j7 >= 0 && j7 - i < best7Dist) {
                best7 = j7;
                best7Dist = j7 - i;
                best4For7 = i;
            }
        }

        if (best0 >= 0 || best7 >= 0) high = true;
        if (!high && !(count0 > 0 && count7 > 0)) return;

        println("\n============================================================");
        println("4B DISPATCH CANDIDATE");
        println("FUNCTION: " + f.getName() + " @ " + f.getEntryPoint());
        println("BODY    : " + f.getBody());
        println("COUNTS  : 4B_CMP=" + count4 +
                " 0B_CMP=" + count0 +
                " 7B_CMP=" + count7 +
                " CALLS=" + calls);

        if (best0 >= 0) {
            println("SEQUENCE: 4B -> 0B compare, distance=" + best0Dist + " instrs");
            println("  4B @ " + a.get(best4For0).getAddress() + " : " +
                    safe(a.get(best4For0).toString()));
            println("  0B @ " + a.get(best0).getAddress() + " : " +
                    safe(a.get(best0).toString()));
        }

        if (best7 >= 0) {
            println("SEQUENCE: 4B -> 7B compare, distance=" + best7Dist + " instrs");
            println("  4B @ " + a.get(best4For7).getAddress() + " : " +
                    safe(a.get(best4For7).toString()));
            println("  7B @ " + a.get(best7).getAddress() + " : " +
                    safe(a.get(best7).toString()));
        }

        if (count0 > 0 && count7 > 0) {
            println("FUNCTION CONTAINS BOTH 0B_CMP AND 7B_CMP");
        }

        if (best4For0 >= 0) {
            printWindow(a, best4For0, 12, 48);
        } else if (best4For7 >= 0) {
            printWindow(a, best4For7, 12, 48);
        }

        if (best0 >= 0 && best0 != best4For0) {
            println("-- 0B DISPATCH CONTEXT --");
            printWindow(a, best0, 8, 28);
        }

        if (best7 >= 0 && best7 != best4For7) {
            println("-- 7B DISPATCH CONTEXT --");
            printWindow(a, best7, 8, 28);
        }
    }

    private void seedFunction(long off) {
        Function f = functionContaining(toAddr(off));
        if (f != null) analyzeFunction(f);
    }

    private String byteHex(byte b) {
        return String.format("%02X", b & 0xff);
    }

    private String readHex(Address a, int len) {
        StringBuilder sb = new StringBuilder();
        Memory mem = currentProgram.getMemory();

        for (int i = 0; i < len; i++) {
            if (i != 0) sb.append(' ');
            try {
                sb.append(byteHex(mem.getByte(a.add(i))));
            } catch (Exception e) {
                sb.append("??");
            }
        }
        return sb.toString();
    }

    private void printInstructionContext(Address hit, String tag, int patternLen) {
        if (lines >= MAX_LINES) return;

        Memory mem = currentProgram.getMemory();
        Instruction ins = currentProgram.getListing().getInstructionContaining(hit);

        Function f = functionContaining(hit);
        if (f == null && ins != null) {
            f = functionContaining(ins.getAddress());
        }

        println("\n------------------------------------------------------------");
        println("RAW HIT: " + tag + " @ " + hit);
        println("BYTES  : " + readHex(hit, Math.max(8, patternLen + 4)));

        if (f != null) {
            println("FUNCTION: " + f.getName() + " @ " + f.getEntryPoint());
        } else {
            println("FUNCTION: <none>");
        }

        if (ins == null) {
            println("INSTRUCTION CONTAINING HIT: <none>");
            Instruction before = currentProgram.getListing().getInstructionBefore(hit);
            Instruction after = currentProgram.getListing().getInstructionAfter(hit);
            if (before != null) {
                println("  PREV : " + before.getAddress() + " : " + safe(before.toString()));
            }
            if (after != null) {
                println("  NEXT : " + after.getAddress() + " : " + safe(after.toString()));
            }
            return;
        }

        long delta = hit.getOffset() - ins.getMinAddress().getOffset();
        println("INSTRUCTION CONTAINING HIT: " + ins.getAddress() +
                " (byte +" + delta + ") : " + safe(ins.toString()));

        Instruction cur = ins;
        ArrayList<Instruction> prev = new ArrayList<Instruction>();
        for (int i = 0; i < RAW_CONTEXT_BEFORE; i++) {
            Instruction p = currentProgram.getListing().getInstructionBefore(cur.getAddress());
            if (p == null) break;
            prev.add(p);
            cur = p;
        }

        for (int i = prev.size() - 1; i >= 0 && lines < MAX_LINES; i--) {
            Instruction x = prev.get(i);
            println("  PREV : " + x.getAddress() + " : " + safe(x.toString()));
            lines++;
        }

        println("  HIT  : " + ins.getAddress() + " : " + safe(ins.toString()));
        lines++;

        cur = ins;
        for (int i = 0; i < RAW_CONTEXT_AFTER && lines < MAX_LINES; i++) {
            Instruction n = currentProgram.getListing().getInstructionAfter(cur.getAddress());
            if (n == null) break;
            println("  NEXT : " + n.getAddress() + " : " + safe(n.toString()));
            lines++;
            cur = n;
        }
    }

    private void rawExecutableByteScan() {
        println("\n============================================================");
        println("RAW HIT / DATA STRUCTURE REVIEW");
        println("KNOWN TARGETS: previous 4B 0B raw hits");
        println("PURPOSE: determine whether hits are code, defined data, or literal-pool bytes");
        println("============================================================");

        long[] knownHits = {
            0xc1f3b121L,
            0xc1f90fb9L,
            0xc1f90fcdL,
            0xc1f90fe1L,
            0xc1f90ff5L,
            0xc1fadcf1L,
            0xc1faee0dL,
            0xc1fb5c01L,
            0xc20027cfL
        };

        Memory mem = currentProgram.getMemory();

        for (int n = 0; n < knownHits.length; n++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            Address a = toAddr(knownHits[n]);
            MemoryBlock block = mem.getBlock(a);
            Data data = currentProgram.getListing().getDataContaining(a);
            Instruction ins = currentProgram.getListing().getInstructionContaining(a);
            Function f = functionContaining(a);

            println("\n------------------------------------------------------------");
            println("KNOWN RAW HIT #" + (n + 1) + " @ " + a);
            println("BYTES -32..+64: " + readHex(a.subtract(32), 96));

            if (block != null) {
                println("MEMORY BLOCK: " + block.getName() +
                        " [" + block.getStart() + " - " + block.getEnd() + "]" +
                        " EXEC=" + block.isExecute() +
                        " READ=" + block.isRead() +
                        " WRITE=" + block.isWrite());
            } else {
                println("MEMORY BLOCK: <none>");
            }

            println("DEFINED DATA: " +
                    (data == null ? "<none>" :
                    data.getAddress() + " : " + safe(data.toString())));

            println("INSTRUCTION: " +
                    (ins == null ? "<none>" :
                    ins.getAddress() + " : " + safe(ins.toString())));

            println("FUNCTION: " +
                    (f == null ? "<none>" :
                    f.getName() + " @ " + f.getEntryPoint()));

            int refs = 0;
            ReferenceIterator rit = currentProgram.getReferenceManager().getReferencesTo(a);
            while (rit.hasNext() && refs < 20) {
                if (monitor.isCancelled()) return;
                Reference r = rit.next();
                println("  XREF TO HIT: " + r.getFromAddress() +
                        " TYPE=" + r.getReferenceType() +
                        " " + (r.isPrimary() ? "PRIMARY" : ""));
                refs++;
            }
            if (refs == 0) println("  XREF TO HIT: <none>");

            // Also check a small neighborhood for defined data items.
            int definedNeighbors = 0;
            for (int d = -32; d <= 64; d++) {
                if (monitor.isCancelled() || definedNeighbors >= 24) break;
                Address x = a.add(d);
                Data dx = currentProgram.getListing().getDataAt(x);
                if (dx != null) {
                    println("  NEAR DATA @ " + dx.getAddress() + " : " + safe(dx.toString()));
                    definedNeighbors++;
                }
            }
        }

        println("\nRAW HIT / DATA REVIEW COMPLETE");
        println("No full executable-memory byte scan was performed.");
    }

    private void listExactCompareLocations() {
        println("\n============================================================");
        println("EXACT 4B / 7B COMPARE LOCATION REVIEW");
        println("PURPOSE: inspect every true immediate compare, especially the only 2 x 0x7B");
        println("============================================================");

        int hits4 = 0;
        int hits7 = 0;
        int printed4 = 0;
        int printed7 = 0;

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!block.isExecute()) continue;

            AddressSet set = new AddressSet(block.getStart(), block.getEnd());
            InstructionIterator it = currentProgram.getListing().getInstructions(set, true);

            while (it.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                Instruction ins = it.next();
                String s = safe(ins.toString());

                boolean b4 = is4BCompare(s);
                boolean b7 = is7BCompare(s);

                if (!b4 && !b7) continue;

                Function f = functionContaining(ins.getAddress());

                if (b4) hits4++;
                if (b7) hits7++;

                // Print every 4B and 7B compare, but only a short instruction context.
                println("\n------------------------------------------------------------");
                println("COMPARE HIT: " + (b4 ? "0x4B" : "0x7B") +
                        " @ " + ins.getAddress());
                println("FUNCTION: " +
                        (f == null ? "<none>" :
                        f.getName() + " @ " + f.getEntryPoint()));
                println("INS: " + safe(ins.toString()));

                Instruction cur = ins;
                ArrayList<Instruction> prev = new ArrayList<Instruction>();
                for (int i = 0; i < 6; i++) {
                    Instruction p = currentProgram.getListing().getInstructionBefore(cur.getAddress());
                    if (p == null) break;
                    prev.add(p);
                    cur = p;
                }

                for (int i = prev.size() - 1; i >= 0; i--) {
                    if (lines >= MAX_LINES) return;
                    Instruction p = prev.get(i);
                    println("  PREV: " + p.getAddress() + " : " + safe(p.toString()));
                    lines++;
                }

                cur = ins;
                for (int i = 0; i < 10 && lines < MAX_LINES; i++) {
                    Instruction nx = currentProgram.getListing().getInstructionAfter(cur.getAddress());
                    if (nx == null) break;
                    println("  NEXT: " + nx.getAddress() + " : " + safe(nx.toString()));
                    lines++;
                    cur = nx;
                }

                if (b4) printed4++;
                if (b7) printed7++;

                // Hard safety valve if an unexpected project state creates too many hits.
                if (printed4 + printed7 >= 64) {
                    println("[COMPARE REVIEW LIMIT] 64 locations");
                    return;
                }
            }
        }

        println("\nCOMPARE LOCATION SUMMARY");
        println("TRUE 0x4B COMPARES: " + hits4);
        println("TRUE 0x7B COMPARES: " + hits7);
    }

    private void globalExactCompareScan() {
        println("\n============================================================");
        println("GLOBAL EXACT COMPARE SCAN: 0x4B / 0x0B / 0x7B");
        println("============================================================");

        int scanned = 0;
        int hits4 = 0;
        int hits0 = 0;
        int hits7 = 0;

        Set<Long> printedFunctions = new HashSet<Long>();

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (monitor.isCancelled()) return;
            if (!block.isExecute()) continue;

            AddressSet set = new AddressSet(block.getStart(), block.getEnd());
            InstructionIterator it =
                currentProgram.getListing().getInstructions(set, true);

            while (it.hasNext()) {
                if (monitor.isCancelled()) return;
                if (scanned++ >= MAX_GLOBAL_INSNS) {
                    println("[HARD LIMIT] " + MAX_GLOBAL_INSNS);
                    return;
                }

                Instruction ins = it.next();
                String s = safe(ins.toString());

                if (!is4BCompare(s) && !is0BCompare(s) && !is7BCompare(s)) continue;

                Function f = functionContaining(ins.getAddress());
                if (f == null) continue;

                long key = f.getEntryPoint().getOffset();

                if (printedFunctions.add(key) &&
                    printedFunctions.size() <= MAX_FUNCTIONS) {
                    analyzeFunction(f);
                }

                if (is4BCompare(s)) hits4++;
                if (is0BCompare(s)) hits0++;
                if (is7BCompare(s)) hits7++;
            }
        }

        println("EXECUTABLE INSTRUCTIONS SCANNED: " + scanned);
        println("EXACT COMPARE HITS: 4B=" + hits4 +
                " 0B=" + hits0 + " 7B=" + hits7);
        println("FUNCTIONS ANALYZED: " + printedFunctions.size());
    }

    private void inspectLikelyCurrentFunctions() {
        long[] seeds = {
            0xc1aafbc0L,
            0xc1902c74L,
            0xc1a23f94L,
            0xc19883bcL,
            0xc19963ccL,
            0xc1ab5394L,
            0xc1ab5514L,
            0xc1d1a760L,
            0xc1d1be3cL,
            0xc1d20cc0L
        };

        println("\n============================================================");
        println("TARGETED REVIEW OF PROTOCOL-LIKE 0x4B FUNCTIONS");
        println("============================================================");

        Set<Long> seen = new HashSet<Long>();

        for (long off : seeds) {
            if (monitor.isCancelled()) return;
            Function f = functionContaining(toAddr(off));
            if (f == null) continue;

            long key = f.getEntryPoint().getOffset();
            if (seen.add(key)) {
                analyzeFunction(f);
            }
        }
    }

    @Override
    public void run() throws Exception {
        println("============================================================");
        println(" Ghidra_RFDEBUG_Trace");
        println(" DIAG 4B -> FTM 0B -> SUBCMD 007B");
        println(" READ ONLY / REUSABLE SINGLE SCRIPT");
        println("============================================================");

        lines = 0;

        inspectLikelyCurrentFunctions();
        println("\n[STEP 1/4] Reviewing previously discovered raw 4B 0B addresses...");
        rawExecutableByteScan();
        println("\n[STEP 2/3] Reviewing exact 4B / 7B compare locations...");
        listExactCompareLocations();
        println("\n[STEP 3/3] Running bounded exact compare scan...");
        globalExactCompareScan();
        println("\n[STEP 4/4] Analysis complete.");

        println("\n============================================================");
        println("DONE");
        println("No memory, symbols, comments, or program structures modified.");
        println("Keep using this same GitHub file: Ghidra_RFDEBUG_Trace.java");
        println("============================================================");
    }
}
