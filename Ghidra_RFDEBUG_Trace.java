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

    private static final long[] TARGET_FUNCS = {
        0xc1aafbc0L,
        0xc1902c74L,
        0xc1ab5514L,
        0xc1a23f94L,
        0xc1a46a70L
    };

    private static final int MAX_FUNCTION_INSNS = 20000;
    private static final int MAX_GLOBAL_INSNS = 1800000;
    private static final int MAX_RESULTS = 80;
    private static final int WINDOW_AFTER_4B = 80;

    private int printed = 0;

    private String safe(String s) {
        return s == null ? "" : s.replace('\r', ' ').replace('\n', ' ');
    }

    private boolean hasHex(String s, long v) {
        String x = safe(s).toLowerCase();
        String h = String.format("0x%x", v);
        return x.contains(h);
    }

    private boolean isCall(String s) {
        String x = safe(s).toLowerCase();
        return x.contains("call ") || x.startsWith("call.") || x.contains(" call.");
    }

    private boolean isCompare(String s) {
        String x = safe(s).toLowerCase();
        return x.contains("cmp.");
    }

    private Function functionAt(long off) {
        FunctionManager fm = currentProgram.getFunctionManager();
        return fm.getFunctionAt(toAddr(off));
    }

    private void printFunction(Function f) {
        if (f == null) {
            println("FUNCTION: <none>");
            return;
        }

        println("FUNCTION: " + f.getName());
        println("ENTRY   : " + f.getEntryPoint());
        println("BODY    : " + f.getBody());

        InstructionIterator it =
            currentProgram.getListing().getInstructions(f.getBody(), true);

        int n = 0;
        int count4b = 0;
        int count0b = 0;
        int count7b = 0;
        int calls = 0;

        while (it.hasNext() && n < MAX_FUNCTION_INSNS) {
            if (monitor.isCancelled()) return;
            Instruction ins = it.next();
            n++;

            String s = safe(ins.toString());

            if (hasHex(s, 0x4b)) count4b++;
            if (hasHex(s, 0x0b)) count0b++;
            if (hasHex(s, 0x7b)) count7b++;
            if (isCall(s)) calls++;
        }

        println("COUNTS: 0x4B=" + count4b +
                " 0x0B=" + count0b +
                " 0x7B=" + count7b +
                " CALLS=" + calls +
                " SCANNED=" + n);
    }

    private ArrayList<Instruction> collect(Function f) {
        ArrayList<Instruction> list = new ArrayList<Instruction>();
        if (f == null) return list;

        InstructionIterator it =
            currentProgram.getListing().getInstructions(f.getBody(), true);

        int n = 0;
        while (it.hasNext() && n < MAX_FUNCTION_INSNS) {
            if (monitor.isCancelled()) return list;
            list.add(it.next());
            n++;
        }
        return list;
    }

    private boolean isPacketLoad(String s, long off) {
        String x = safe(s).toLowerCase();
        String base = "r17";
        if (!x.contains(base)) return false;

        if (off == 0) {
            return x.contains("(r17)") && !x.contains("(r17+");
        }

        String h = String.format("#0x%x", off);
        String h2 = String.format("+0x%x", off);
        return x.contains("(r17+" + h2 + ")") ||
               x.contains("(r17+" + h + ")");
    }

    private void analyzeCandidate(long off) {
        Address a = toAddr(off);
        Function f = functionAt(off);

        println("\n============================================================");
        println("CANDIDATE FUNCTION @" + a);
        println("============================================================");

        if (f == null) {
            println("No function at target.");
            return;
        }

        printFunction(f);

        ArrayList<Instruction> insns = collect(f);
        int fourBIndex = -1;

        for (int i = 0; i < insns.size(); i++) {
            if (monitor.isCancelled()) return;

            String s = safe(insns.get(i).toString());

            boolean is4BCompare =
                hasHex(s, 0x4b) && isCompare(s) &&
                (s.toLowerCase().contains("cmpb") ||
                 s.toLowerCase().contains("cmph") ||
                 s.toLowerCase().contains("cmp.eq") ||
                 s.toLowerCase().contains("cmp.gt") ||
                 s.toLowerCase().contains("cmp.gtu"));

            if (!is4BCompare) continue;

            fourBIndex = i;

            println("\n-- 0x4B COMPARE @ " + insns.get(i).getAddress() + " --");
            println("   " + s);

            int start = Math.max(0, i - 8);
            int end = Math.min(insns.size(), i + WINDOW_AFTER_4B);

            int packet0 = -1;
            int packet1 = -1;
            int packet2 = -1;
            int cmd0b = -1;
            int cmd7b = -1;
            int firstCall = -1;

            for (int j = start; j < end; j++) {
                Instruction z = insns.get(j);
                String zs = safe(z.toString());

                if (isPacketLoad(zs, 0) && packet0 < 0) packet0 = j;
                if (isPacketLoad(zs, 1) && packet1 < 0) packet1 = j;
                if (isPacketLoad(zs, 2) && packet2 < 0) packet2 = j;

                if (hasHex(zs, 0x0b) && cmd0b < 0) cmd0b = j;
                if (hasHex(zs, 0x7b) && cmd7b < 0) cmd7b = j;

                if (j > i && isCall(zs) && firstCall < 0) firstCall = j;

                if ((j >= i - 8 && j <= i + 24) ||
                    hasHex(zs, 0x0b) ||
                    hasHex(zs, 0x7b) ||
                    isPacketLoad(zs, 0) ||
                    isPacketLoad(zs, 1) ||
                    isPacketLoad(zs, 2) ||
                    (j > i && isCall(zs))) {

                    if (printed < MAX_RESULTS) {
                        println("   " + z.getAddress() + " : " + zs);
                        printed++;
                    }
                }
            }

            println("   PACKET LOAD R17+0 : " + (packet0 >= 0 ? insns.get(packet0).getAddress() : "<none>"));
            println("   PACKET LOAD R17+1 : " + (packet1 >= 0 ? insns.get(packet1).getAddress() : "<none>"));
            println("   PACKET LOAD R17+2 : " + (packet2 >= 0 ? insns.get(packet2).getAddress() : "<none>"));
            println("   0x0B RELATED       : " + (cmd0b >= 0 ? insns.get(cmd0b).getAddress() : "<none>"));
            println("   0x7B RELATED       : " + (cmd7b >= 0 ? insns.get(cmd7b).getAddress() : "<none>"));
            println("   FIRST CALL AFTER   : " + (firstCall >= 0 ? insns.get(firstCall).getAddress() : "<none>"));

            if (packet0 >= 0 && packet1 >= 0 && packet2 >= 0) {
                println("   >>> BUFFER-STRUCTURE CANDIDATE: byte[0], byte[1], halfword[2] <<<");
            }
            if (packet0 >= 0 && packet1 >= 0 && cmd0b >= 0) {
                println("   >>> 4B -> buffer byte[1] / 0x0B CANDIDATE <<<");
            }
            if (packet2 >= 0 && cmd7b >= 0) {
                println("   >>> 4B -> halfword@+2 / 0x7B CANDIDATE <<<");
            }
            if (packet0 >= 0 && packet1 >= 0 && packet2 >= 0 && cmd0b >= 0 && cmd7b >= 0) {
                println("   >>> HIGH-VALUE: potential 4B 0B 7B 00 parser path <<<");
            }
        }
    }

    private void globalScanForPacketPattern() throws Exception {
        println("\n============================================================");
        println("GLOBAL EXECUTABLE SCAN FOR PACKET-LIKE 0x4B / R17 PATTERNS");
        println("============================================================");

        int scanned = 0;
        int candidates = 0;
        Set<Long> seen = new HashSet<Long>();

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (monitor.isCancelled()) return;
            if (!block.isExecute()) continue;

            AddressSet set = new AddressSet(block.getStart(), block.getEnd());
            InstructionIterator it =
                currentProgram.getListing().getInstructions(set, true);

            while (it.hasNext()) {
                if (monitor.isCancelled()) return;
                if (scanned >= MAX_GLOBAL_INSNS) {
                    println("[HARD LIMIT] stopped at " + scanned);
                    return;
                }

                Instruction ins = it.next();
                scanned++;
                String s = safe(ins.toString());

                if (!hasHex(s, 0x4b) || !isCompare(s)) continue;

                Function f =
                    currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
                if (f == null) continue;

                ArrayList<Instruction> sample = collect(f);
                boolean hasR17_0 = false;
                boolean hasR17_1 = false;
                boolean hasR17_2 = false;
                boolean has0b = false;
                boolean has7b = false;

                for (Instruction x : sample) {
                    String xs = safe(x.toString());
                    if (isPacketLoad(xs, 0)) hasR17_0 = true;
                    if (isPacketLoad(xs, 1)) hasR17_1 = true;
                    if (isPacketLoad(xs, 2)) hasR17_2 = true;
                    if (hasHex(xs, 0x0b)) has0b = true;
                    if (hasHex(xs, 0x7b)) has7b = true;
                }

                if (hasR17_0 && hasR17_1 && (hasR17_2 || has0b || has7b)) {
                    long key = f.getEntryPoint().getOffset();
                    if (!seen.contains(key)) {
                        seen.add(key);
                        candidates++;
                        println("CANDIDATE #" + candidates +
                                " FUNC=" + f.getName() +
                                " ENTRY=" + f.getEntryPoint() +
                                " r17[0]=" + hasR17_0 +
                                " r17[1]=" + hasR17_1 +
                                " r17[2]=" + hasR17_2 +
                                " 0B=" + has0b +
                                " 7B=" + has7b);
                        if (candidates >= 40) return;
                    }
                }
            }
        }

        println("GLOBAL INSTRUCTIONS SCANNED: " + scanned);
        println("PACKET-LIKE CANDIDATES: " + candidates);
    }

    @Override
    public void run() throws Exception {
        println("============================================================");
        println(" Ghidra_RFDEBUG_Trace");
        println(" DIAG 4B -> FTM 0B -> SUBCMD 007B");
        println(" READ ONLY");
        println("============================================================");

        printed = 0;

        for (long off : TARGET_FUNCS) {
            if (monitor.isCancelled()) return;
            analyzeCandidate(off);
        }

        globalScanForPacketPattern();

        println("\n============================================================");
        println("DONE");
        println("No memory, symbols, comments, or program structures modified.");
        println("The reusable script file should remain named Ghidra_RFDEBUG_Trace.java");
        println("============================================================");
    }
}
