import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class Ghidra_RFDEBUG_Trace extends GhidraScript {

    private static final int MAX_FUNCTION_INSNS = 20000;
    private static final int MAX_GLOBAL_INSNS = 1800000;
    private static final int MAX_FUNCTIONS = 120;
    private static final int MAX_LINES = 12000;
    private static final int LOCAL_WINDOW = 140;

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
        String x = safe(s).toLowerCase();
        return x.contains("cmp.");
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
        for (int i = from + 1; i < a.size() && i <= from + LOCAL_WINDOW; i++) {
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
        int best0 = -1, best7 = -1, best4 = -1;
        int best0Dist = Integer.MAX_VALUE, best7Dist = Integer.MAX_VALUE;

        for (int i : fourB) {
            int j0 = findNext(a, i, true, false);
            int j7 = findNext(a, i, false, true);

            if (j0 >= 0 && j0 - i < best0Dist) {
                best0 = j0;
                best0Dist = j0 - i;
                best4 = i;
            }
            if (j7 >= 0 && j7 - i < best7Dist) {
                best7 = j7;
                best7Dist = j7 - i;
                if (best4 < 0) best4 = i;
            }
        }

        if (best0 >= 0) high = true;
        if (best7 >= 0) high = true;

        // We only print useful 4B functions:
        // 4B->0B compare, 4B->7B compare, or both 0B and 7B elsewhere.
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
            println("SEQUENCE: 4B -> 0B compare, distance=" + best0Dist +
                    " instrs");
            println("  4B @ " + a.get(best4).getAddress() + " : " + safe(a.get(best4).toString()));
            println("  0B @ " + a.get(best0).getAddress() + " : " + safe(a.get(best0).toString()));
        }

        if (best7 >= 0) {
            int from = best4 >= 0 ? best4 : 0;
            println("SEQUENCE: 4B -> 7B compare, distance=" + best7Dist +
                    " instrs");
            println("  4B @ " + a.get(from).getAddress() + " : " + safe(a.get(from).toString()));
            println("  7B @ " + a.get(best7).getAddress() + " : " + safe(a.get(best7).toString()));
        }

        if (count0 > 0 && count7 > 0) {
            println("FUNCTION CONTAINS BOTH 0B_CMP AND 7B_CMP");
        }

        if (best4 >= 0) {
            printWindow(a, best4, 12, 48);
        }

        if (best0 >= 0 && best0 != best4) {
            println("-- 0B DISPATCH CONTEXT --");
            printWindow(a, best0, 8, 28);
        }

        if (best7 >= 0 && best7 != best4) {
            println("-- 7B DISPATCH CONTEXT --");
            printWindow(a, best7, 8, 28);
        }
    }

    private void seedFunction(long off) {
        Function f = functionContaining(toAddr(off));
        if (f != null) {
            analyzeFunction(f);
        }
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

                // Analyze once per function, with strongest candidates first.
                boolean interesting =
                    is4BCompare(s) || is0BCompare(s) || is7BCompare(s);

                if (interesting && printedFunctions.add(key) &&
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
            0xc1aafbc0L,
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
        globalExactCompareScan();

        println("\n============================================================");
        println("DONE");
        println("No memory, symbols, comments, or program structures modified.");
        println("Keep using this same GitHub file: Ghidra_RFDEBUG_Trace.java");
        println("============================================================");
    }
}
