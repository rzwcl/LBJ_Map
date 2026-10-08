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
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Ghidra_RFDEBUG_Trace extends GhidraScript {

    private static final String TRACE_BUILD = "C18E7A50CALLERS-1";

    private static final int MAX_FUNCTION_INSNS = 20000;
    private static final int MAX_DEEP_INSNS = 4000;
    private static final int MAX_FOCUSED_INSNS = 320;
    private static final int MAX_C1902_INSNS = 600;
    private static final int MAX_CALLER_INSNS = 500;
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

    private boolean containsExactImm(String s, long v) {
        String x = safe(s);
        Pattern p = Pattern.compile("(?i)#\\s*#?0x([0-9a-f]+)(?![0-9a-f])");
        Matcher m = p.matcher(x);

        while (m.find()) {
            try {
                long n = Long.parseLong(m.group(1), 16);
                if (n == v) return true;
            } catch (Exception e) {
                // Ignore malformed/non-numeric immediate text.
            }
        }
        return false;
    }

    private boolean isCompare(String s) {
        return safe(s).toLowerCase().contains("cmp.");
    }

    private boolean isCall(String s) {
        String x = safe(s).toLowerCase();
        return x.contains("call ") || x.startsWith("call.") || x.contains(" call.");
    }

    private boolean is4BCompare(String s) {
        if (!isCompare(s) || !containsExactImm(s, 0x4b)) return false;
        String x = safe(s).toLowerCase();
        return x.contains("cmpb") ||
               x.contains("cmph") ||
               x.contains("cmp.eq") ||
               x.contains("cmp.gt") ||
               x.contains("cmp.gtu");
    }

    private boolean is0BCompare(String s) {
        if (!isCompare(s) || !containsExactImm(s, 0x0b)) return false;
        String x = safe(s).toLowerCase();
        return x.contains("cmpb") ||
               x.contains("cmph") ||
               x.contains("cmp.eq") ||
               x.contains("cmp.gt") ||
               x.contains("cmp.gtu");
    }

    private boolean is7BCompare(String s) {
        if (!isCompare(s) || !containsExactImm(s, 0x7b)) return false;
        String x = safe(s).toLowerCase();
        return x.contains("cmpb") ||
               x.contains("cmph") ||
               x.contains("cmp.eq") ||
               x.contains("cmp.gt") ||
               x.contains("cmp.gtu");
    }

    private boolean instructionHasExactImm(Instruction ins, long wanted) {
        if (ins == null) return false;

        int n = ins.getNumOperands();
        for (int op = 0; op < n; op++) {
            Object[] objs = ins.getOpObjects(op);
            if (objs == null) continue;

            for (Object obj : objs) {
                if (obj instanceof Scalar) {
                    Scalar sc = (Scalar)obj;
                    if (sc.getUnsignedValue() == wanted) return true;
                }
            }
        }
        return false;
    }

    private boolean isExact4BInsn(Instruction ins) {
        if (ins == null) return false;
        return isCompare(ins.toString()) && instructionHasExactImm(ins, 0x4b);
    }

    private boolean isExact0BInsn(Instruction ins) {
        if (ins == null) return false;
        return isCompare(ins.toString()) && instructionHasExactImm(ins, 0x0b);
    }

    private boolean isExact7BInsn(Instruction ins) {
        if (ins == null) return false;
        return isCompare(ins.toString()) && instructionHasExactImm(ins, 0x7b);
    }

    private boolean isByteCompare(Instruction ins) {
        if (ins == null) return false;

        String m = safe(ins.getMnemonicString()).toLowerCase();
        if (m.startsWith("cmpb.")) return true;

        // Hexagon commonly performs a byte load (memub/memb) followed by
        // an ordinary cmp.eq/cmp.gt/cmp.gtu rather than a cmpb mnemonic.
        // Treat that as byte-oriented only when the same compared register
        // was populated by a byte load within the preceding 6 instructions.
        if (!isCompare(ins.toString())) return false;

        String reg = extractComparedRegister(ins.toString());
        if (reg == null) return false;

        Instruction cur = ins;
        for (int i = 0; i < 6; i++) {
            Instruction p = currentProgram.getListing().getInstructionBefore(cur.getAddress());
            if (p == null) break;

            String ps = safe(p.toString()).toLowerCase();
            boolean byteLoad = ps.contains("memub ") || ps.contains("memb ");
            if (byteLoad && isLoadIntoRegister(ps, reg)) return true;

            cur = p;
        }

        return false;
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

    private void printWindow(ArrayList<Instruction> a, int center, int before, int after) {        int start = Math.max(0, center - before);        int end = Math.min(a.size(), center + after + 1);        for (int i = start; i < end && lines < MAX_LINES; i++) {            Instruction ins = a.get(i);            String s = safe(ins.toString());            if (i == center ||                is4BCompare(s) ||                is0BCompare(s) ||
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
        println("\n============================================================");        println("RAW HIT / DATA STRUCTURE REVIEW");
        println("KNOWN TARGETS: previous 4B 0B raw hits");        println("PURPOSE: determine whether hits are code, defined data, or literal-pool bytes");
        println("============================================================");
        long[] knownHits = {            0xc1f3b121L,
            0xc1f90fb9L,            0xc1f90fcdL,
            0xc1f90fe1L,            0xc1f90ff5L,
            0xc1fadcf1L,            0xc1faee0dL,
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

    private void inspectExactProtocolCandidates() {
        println("\n============================================================");
        println("EXACT IMMEDIATE PROTOCOL CANDIDATES");
        println("MATCH RULE: immediate numeric value MUST equal 0x4B / 0x0B / 0x7B");
        println("NOT A STRING-SUBSTRING MATCH");
        println("============================================================");

        int exact4 = 0;
        int exact0 = 0;
        int exact7 = 0;
        int candidateFunctions = 0;

        Set<Long> seenFunctions = new HashSet<Long>();

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
                boolean b0 = is0BCompare(s);
                boolean b7 = is7BCompare(s);
                if (b4) exact4++;
                if (b0) exact0++;
                if (b7) exact7++;
                if (!b4 && !b0 && !b7) continue;
                Function f = functionContaining(ins.getAddress());
                if (f == null) continue;
                long key = f.getEntryPoint().getOffset();
                if (!seenFunctions.add(key)) continue;
                ArrayList<Instruction> a = collect(f);
                boolean has4 = false;
                boolean has0 = false;                boolean has7 = false;

                for (Instruction q : a) {                    String qs = safe(q.toString());
                    if (is4BCompare(qs)) has4 = true;
                    if (is0BCompare(qs)) has0 = true;                    if (is7BCompare(qs)) has7 = true;
                }

                // Only print functions that contain an exact 0x4B selector
                // together with exact 0x0B / 0x7B, or a clearly byte-oriented 0x4B.
                boolean candidate = (has4 && (has0 || has7)) || (has4 && isByteOriented4B(s));
                if (!candidate) continue;

                candidateFunctions++;

                println("\n------------------------------------------------------------");
                println("PROTOCOL CANDIDATE FUNCTION");
                println("FUNCTION: " + f.getName() + " @ " + f.getEntryPoint());
                println("HAS EXACT: 4B=" + has4 + " 0B=" + has0 + " 7B=" + has7);

                int shown = 0;
                for (Instruction q : a) {
                    String qs = safe(q.toString());
                    if (is4BCompare(qs) || is0BCompare(qs) || is7BCompare(qs)) {
                        println("  CMP: " + q.getAddress() + " : " + qs);
                        lines++;
                        shown++;
                        if (shown >= 24 || lines >= MAX_LINES) break;
                    }
                }

                // Focused byte-read context around each exact 4B compare.
                for (Instruction q : a) {
                    if (lines >= MAX_LINES) return;
                    String qs = safe(q.toString());
                    if (!is4BCompare(qs)) continue;

                    println("  -- 4B BYTE CONTEXT @ " + q.getAddress() + " --");
                    int qi = a.indexOf(q);
                    int st = Math.max(0, qi - 6);
                    int en = Math.min(a.size(), qi + 9);
                    for (int k = st; k < en && lines < MAX_LINES; k++) {
                        Instruction z = a.get(k);
                        println("     " + z.getAddress() + " : " + safe(z.toString()));
                        lines++;
                    }
                }
            }
        }

        println("\nEXACT IMMEDIATE SUMMARY");
        println("EXACT 0x4B COMPARES: " + exact4);
        println("EXACT 0x0B COMPARES: " + exact0);
        println("EXACT 0x7B COMPARES: " + exact7);
        println("PROTOCOL CANDIDATE FUNCTIONS: " + candidateFunctions);
    }

    private boolean isByteOriented4B(String s) {
        String x = safe(s).toLowerCase();
        return x.contains("cmpb.eq") ||
               x.contains("cmpb.gt") ||
               x.contains("cmpb.gtu") ||
               x.contains("memub");
    }

    private void traceExactByteProtocol() {
        println("\n============================================================");
        println("EXACT BYTE-COMPARE PROTOCOL TRACE");
        println("USES Ghidra Scalar OPERANDS — NOT TEXT SUBSTRING MATCHING");
        println("TARGETS: byte compares against exact 0x4B / 0x0B / 0x7B");
        println("============================================================");

        int total4 = 0, total0 = 0, total7 = 0;
        int byte4 = 0, byte0 = 0, byte7 = 0;

        Set<Long> functions4 = new HashSet<Long>();
        Set<Long> functions0 = new HashSet<Long>();
        Set<Long> functions7 = new HashSet<Long>();

        ArrayList<Instruction> exact4List = new ArrayList<Instruction>();
        ArrayList<Instruction> exact0List = new ArrayList<Instruction>();
        ArrayList<Instruction> exact7List = new ArrayList<Instruction>();

        int scanned = 0;

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!block.isExecute()) continue;

            AddressSet set = new AddressSet(block.getStart(), block.getEnd());
            InstructionIterator it = currentProgram.getListing().getInstructions(set, true);

            while (it.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                Instruction ins = it.next();
                scanned++;

                boolean e4 = isExact4BInsn(ins);
                boolean e0 = isExact0BInsn(ins);
                boolean e7 = isExact7BInsn(ins);

                if (e4) {
                    total4++;
                    if (isByteCompare(ins)) byte4++;
                    exact4List.add(ins);
                    Function f = functionContaining(ins.getAddress());
                    if (f != null) functions4.add(f.getEntryPoint().getOffset());
                }

                if (e0) {
                    total0++;
                    if (isByteCompare(ins)) byte0++;
                    exact0List.add(ins);
                    Function f = functionContaining(ins.getAddress());
                    if (f != null) functions0.add(f.getEntryPoint().getOffset());
                }

                if (e7) {
                    total7++;
                    if (isByteCompare(ins)) byte7++;
                    exact7List.add(ins);
                    Function f = functionContaining(ins.getAddress());
                    if (f != null) functions7.add(f.getEntryPoint().getOffset());
                }
            }
        }

        println("EXECUTABLE INSTRUCTIONS SCANNED: " + scanned);
        println("EXACT IMMEDIATE COUNTS: 4B=" + total4 + " 0B=" + total0 + " 7B=" + total7);
        println("BYTE-COMPARE COUNTS    : 4B=" + byte4 + " 0B=" + byte0 + " 7B=" + byte7);
        println("FUNCTION SETS          : 4B=" + functions4.size() +
                " 0B=" + functions0.size() + " 7B=" + functions7.size());

        // First pass: functions that contain a byte compare against 4B and also
        // a byte compare against 0B or 7B. These are the strongest static matches.
        Set<Long> strongPrinted = new HashSet<Long>();

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!block.isExecute()) continue;

            AddressSet set = new AddressSet(block.getStart(), block.getEnd());
            InstructionIterator it = currentProgram.getListing().getInstructions(set, true);

            while (it.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                Instruction ins = it.next();
                if (!isExact4BInsn(ins) || !isByteCompare(ins)) continue;

                Function f = functionContaining(ins.getAddress());
                if (f == null) continue;

                ArrayList<Instruction> a = collect(f);
                boolean has0 = false, has7 = false;
                for (Instruction q : a) {
                    if (!isByteCompare(q)) continue;
                    if (isExact0BInsn(q)) has0 = true;
                    if (isExact7BInsn(q)) has7 = true;
                }

                if (!has0 && !has7) continue;

                long key = f.getEntryPoint().getOffset();
                if (!strongPrinted.add(key)) continue;

                println("\n------------------------------------------------------------");
                println("STRONG BYTE-PROTOCOL CANDIDATE");
                println("FUNCTION: " + f.getName() + " @ " + f.getEntryPoint());
                println("HAS: cmpb 0x4B=" + true +
                        "  cmpb 0x0B=" + has0 +
                        "  cmpb 0x7B=" + has7);

                int shown = 0;
                for (Instruction q : a) {
                    if (isByteCompare(q) &&
                        (isExact4BInsn(q) || isExact0BInsn(q) || isExact7BInsn(q))) {
                        println("  CMPB: " + q.getAddress() + " : " + safe(q.toString()));
                        lines++;
                        shown++;
                        if (shown >= 24 || lines >= MAX_LINES) break;
                    }
                }
                printCallerXrefs(f);
            }
        }
        println("\n------------------------------------------------------------");
        println("BYTE-COMPARE 0x4B CONTEXT");
        printByteCompareContexts(exact4List, 0x4b);
        println("\n------------------------------------------------------------");
        println("BYTE-COMPARE 0x0B CONTEXT");
        printByteCompareContexts(exact0List, 0x0b);
        println("\n------------------------------------------------------------");
        println("BYTE-COMPARE 0x7B CONTEXT");
        printByteCompareContexts(exact7List, 0x7b);    }

    private void printCallerXrefs(Function f) {
        if (f == null || lines >= MAX_LINES) return;
        println("CALLER XREFS:");
        ReferenceIterator rit =
            currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        int n = 0;
        while (rit.hasNext() && n < 16) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            Reference r = rit.next();
            if (!r.getReferenceType().isCall()) continue;

            Function caller = functionContaining(r.getFromAddress());
            println("  " + r.getFromAddress() + " -> " +
                    (caller == null ? "<unknown>" :
                    caller.getName() + " @ " + caller.getEntryPoint()));
            lines++;
            n++;
        }

        if (n == 0) println("  <no CALL xrefs>");
    }

    private void printByteCompareContexts(ArrayList<Instruction> list, long wanted) {
        int printed = 0;

        for (Instruction center : list) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!isByteCompare(center)) continue;

            // For this focused pass, only exact scalar byte compares.
            if (!instructionHasExactImm(center, wanted)) continue;

            Function f = functionContaining(center.getAddress());

            println("  HIT @ " + center.getAddress() +
                    " : " + safe(center.toString()) +
                    " FUNCTION=" +
                    (f == null ? "<none>" : f.getName()));

            Instruction cur = center;
            ArrayList<Instruction> prev = new ArrayList<Instruction>();
            for (int i = 0; i < 5; i++) {
                Instruction p = currentProgram.getListing().getInstructionBefore(cur.getAddress());
                if (p == null) break;
                prev.add(p);
                cur = p;
            }

            for (int i = prev.size() - 1; i >= 0 && lines < MAX_LINES; i--) {
                Instruction p = prev.get(i);
                println("    PREV: " + p.getAddress() + " : " + safe(p.toString()));
                lines++;
            }

            cur = center;
            for (int i = 0; i < 9 && lines < MAX_LINES; i++) {
                Instruction n = currentProgram.getListing().getInstructionAfter(cur.getAddress());
                if (n == null) break;
                println("    NEXT: " + n.getAddress() + " : " + safe(n.toString()));
                lines++;
                cur = n;
            }

            lines++;
            printed++;
            if (printed >= 40) {
                println("  [BYTE-COMPARE CONTEXT LIMIT] 40");
                return;
            }
        }
    }

    private void rankPacketHeaderCandidates() {
        println("\n============================================================");
        println("PACKET-HEADER DATAFLOW CANDIDATE RANKING");
        println("RULE:");
        println("  exact scalar compare == 0x4B / 0x0B");
        println("  inspect nearby memub/memuh loads and buffer offsets");
        println("  report same-function 4B+0B pairs and their register/source shape");
        println("============================================================");

        ArrayList<Instruction> exact4 = new ArrayList<Instruction>();
        ArrayList<Instruction> exact0 = new ArrayList<Instruction>();
        ArrayList<Instruction> exact7 = new ArrayList<Instruction>();

        int scanned = 0;

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!block.isExecute()) continue;

            AddressSet set = new AddressSet(block.getStart(), block.getEnd());
            InstructionIterator it = currentProgram.getListing().getInstructions(set, true);

            while (it.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                Instruction ins = it.next();
                scanned++;

                if (isExact4BInsn(ins)) exact4.add(ins);
                if (isExact0BInsn(ins)) exact0.add(ins);
                if (isExact7BInsn(ins)) exact7.add(ins);
            }
        }

        println("SCANNED INSTRUCTIONS: " + scanned);
        println("EXACT LISTS: 4B=" + exact4.size() +
                " 0B=" + exact0.size() +
                " 7B=" + exact7.size());

        println("\nEXACT 0x4B LOCATIONS");
        for (Instruction x : exact4) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            Function f = functionContaining(x.getAddress());
            println("  4B @ " + x.getAddress() + " : " + safe(x.toString()) +
                    " FUNCTION=" +
                    (f == null ? "<none>" : f.getName() + " @ " + f.getEntryPoint()));

            printNearByteLoads(x, 10);

            int near0 = nearestExactInList(x, exact0, 160);
            if (near0 >= 0) {
                Instruction y = exact0.get(near0);
                Function fy = functionContaining(y.getAddress());
                if (f != null && fy != null &&
                    f.getEntryPoint().equals(fy.getEntryPoint())) {
                    println("    SAME FUNCTION 0B @ " + y.getAddress() +
                            " DIST=" + instructionDistance(x, y) +
                            " : " + safe(y.toString()));
                    printNearByteLoads(y, 10);
                }
            }

            printFunctionCallers(f);
            lines++;
        }

        println("\nEXACT 0x7B LOCATIONS");
        for (Instruction x : exact7) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            Function f = functionContaining(x.getAddress());
            println("  7B @ " + x.getAddress() + " : " + safe(x.toString()) +
                    " FUNCTION=" +
                    (f == null ? "<none>" : f.getName() + " @ " + f.getEntryPoint()));
            printNearByteLoads(x, 12);
            printFunctionCallers(f);
            lines++;
        }

        println("\nSAME-FUNCTION 4B + 0B PAIRS");
        int pairCount = 0;
        for (Instruction x : exact4) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            Function f = functionContaining(x.getAddress());
            if (f == null) continue;

            for (Instruction y : exact0) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;
                Function fy = functionContaining(y.getAddress());
                if (fy == null ||
                    !f.getEntryPoint().equals(fy.getEntryPoint())) continue;

                int dist = instructionDistance(x, y);
                if (dist < 0 || dist > 220) continue;

                println("  PAIR: " + f.getName() +
                        " 4B@" + x.getAddress() +
                        " <-> 0B@" + y.getAddress() +
                        " DIST=" + dist);
                println("    4B: " + safe(x.toString()));
                println("    0B: " + safe(y.toString()));

                printPairLoadShape(x, y);
                pairCount++;

                if (pairCount >= 24) {                    println("  [PAIR LIMIT] 24");
                    return;
                }
            }
        }
        println("PAIR COUNT SHOWN: " + pairCount);
        println("\nEXACT 0B NEAREST CHECK COMPLETE");
        println("Read-only analysis only.");
    }
    private int instructionDistance(Instruction a, Instruction b) {
        if (a == null || b == null) return -1;
        long d = Math.abs(a.getAddress().subtract(b.getAddress()));
        if (d > 0x7fffffffL) return -1;        return (int)(d / 4);
    }

    private int nearestExactInList(Instruction base, ArrayList<Instruction> list, int maxInstr) {
        int best = -1;        int bestDist = Integer.MAX_VALUE;

        for (int i = 0; i < list.size(); i++) {
            Instruction x = list.get(i);
            Function f1 = functionContaining(base.getAddress());            Function f2 = functionContaining(x.getAddress());

            if (f1 == null || f2 == null ||
                !f1.getEntryPoint().equals(f2.getEntryPoint())) continue;
            int d = instructionDistance(base, x);
            if (d >= 0 && d <= maxInstr && d < bestDist) {
                bestDist = d;
                best = i;
            }        }
        return best;
    }

    private void printNearByteLoads(Instruction center, int before) {
        if (center == null || lines >= MAX_LINES) return;

        Instruction cur = center;
        ArrayList<Instruction> rev = new ArrayList<Instruction>();

        for (int i = 0; i < before; i++) {
            Instruction p = currentProgram.getListing().getInstructionBefore(cur.getAddress());
            if (p == null) break;

            String s = safe(p.toString()).toLowerCase();
            if (s.contains("memub") || s.contains("memuh") || s.contains("memb")) {
                rev.add(p);
            }
            cur = p;
        }

        for (int i = rev.size() - 1; i >= 0 && lines < MAX_LINES; i--) {
            Instruction p = rev.get(i);
            println("    BYTE LOAD BEFORE: " + p.getAddress() + " : " + safe(p.toString()));
            lines++;
        }

        cur = center;
        for (int i = 0; i < 6 && lines < MAX_LINES; i++) {
            Instruction n = currentProgram.getListing().getInstructionAfter(cur.getAddress());
            if (n == null) break;

            String s = safe(n.toString()).toLowerCase();
            if (s.contains("memub") || s.contains("memuh") || s.contains("memb")) {
                println("    BYTE LOAD AFTER : " + n.getAddress() + " : " + safe(n.toString()));
                lines++;
            }
            cur = n;
        }
    }

    private void printPairLoadShape(Instruction a, Instruction b) {
        println("    --- LOAD SHAPE A ---");
        printNearByteLoads(a, 12);
        println("    --- LOAD SHAPE B ---");
        printNearByteLoads(b, 12);
    }

    private void printFunctionCallers(Function f) {
        if (f == null || lines >= MAX_LINES) return;

        ReferenceIterator rit =
            currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());

        int shown = 0;
        while (rit.hasNext() && shown < 12) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            Reference r = rit.next();
            if (!r.getReferenceType().isCall()) continue;

            Function caller = functionContaining(r.getFromAddress());
            println("    CALLER: " + r.getFromAddress() + " <- " +
                    (caller == null ? "<unknown>" :
                    caller.getName() + " @ " + caller.getEntryPoint()));
            lines++;
            shown++;
        }

        if (shown == 0) println("    CALLER: <none>");
    }

    private void scanCombinedProtocolConstants() {
        println("\n============================================================");
        println("COMBINED PROTOCOL CONSTANT SCAN");
        println("TARGET BYTE STREAM: 4B 0B 7B 00");
        println("TEST VALUES:");
        println("  LE32 = 0x007B0B4B");
        println("  24BIT = 0x7B0B4B");
        println("  LE16(first2) = 0x0B4B");
        println("  LE16(last2)  = 0x007B");
        println("  FTM SUBCMD   = 0x007B");
        println("============================================================");

        long[] targets = {
            0x007b0b4bL,
            0x7b0b4bL,
            0x0b4bL,
            0x7bL,
            0x0bL,
            0x4bL
        };

        int[] counts = new int[targets.length];
        int scanned = 0;

        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            if (!block.isExecute()) continue;

            AddressSet set = new AddressSet(block.getStart(), block.getEnd());
            InstructionIterator it = currentProgram.getListing().getInstructions(set, true);

            while (it.hasNext()) {
                if (monitor.isCancelled() || lines >= MAX_LINES) return;

                Instruction ins = it.next();
                scanned++;

                if (!isCompare(ins.toString())) continue;

                for (int k = 0; k < targets.length; k++) {
                    if (!instructionHasExactImm(ins, targets[k])) continue;

                    counts[k]++;

                    println("\nCOMBINED CONSTANT HIT");
                    println("VALUE: 0x" + Long.toHexString(targets[k]));
                    println("ADDR : " + ins.getAddress());
                    println("INS  : " + safe(ins.toString()));

                    Function f = functionContaining(ins.getAddress());
                    println("FUNC : " +
                        (f == null ? "<none>" :
                         f.getName() + " @ " + f.getEntryPoint()));

                    printNearbyLoadsForComparedRegister(ins, 14);
                    printCallsAfter(ins, 18);

                    lines++;
                    if (counts[k] >= 24) {
                        println("  [PER-VALUE LIMIT] 24");
                        break;
                    }
                }
            }
        }

        println("\nCOMBINED CONSTANT SUMMARY");
        for (int k = 0; k < targets.length; k++) {
            println("0x" + Long.toHexString(targets[k]) + " : " + counts[k]);
        }
        println("SCANNED: " + scanned);
    }

    private void printNearbyLoadsForComparedRegister(Instruction cmp, int before) {
        if (cmp == null || lines >= MAX_LINES) return;

        String cs = safe(cmp.toString());
        String reg = extractComparedRegister(cs);
        if (reg == null) {
            println("  COMPARED REGISTER: <not parsed>");
            return;
        }

        println("  COMPARED REGISTER: " + reg);

        Instruction cur = cmp;
        int shown = 0;

        for (int i = 0; i < before && lines < MAX_LINES; i++) {
            Instruction p = currentProgram.getListing().getInstructionBefore(cur.getAddress());
            if (p == null) break;

            String ps = safe(p.toString());            if (isLoadIntoRegister(ps, reg)) {
                println("  LOAD SAME REG: " + p.getAddress() + " : " + ps);
                lines++;
                shown++;
            }
            cur = p;
        }

        if (shown == 0) println("  LOAD SAME REG: <none within " + before + " instructions>");
    }
    private String extractComparedRegister(String s) {
        if (s == null) return null;

        String x = safe(s);
        int comma = x.indexOf(',');
        if (comma < 0) return null;
        String rest = x.substring(comma + 1).trim();

        // Common Ghidra Hexagon forms:
        // cmp.eq P0,R2,#0x4b
        // cmp.gt P0,R21,#0x4b
        int comma2 = rest.indexOf(',');
        if (comma2 < 0) return null;

        String reg = rest.substring(0, comma2).trim();
        if (reg.startsWith("R") || reg.startsWith("r")) {            return reg;
        }

        // Some predicated forms may have an extra predicate token.
        int p = rest.indexOf(",R");
        if (p < 0) p = rest.indexOf(",r");        if (p >= 0) {
            int q = rest.indexOf(',', p + 1);
            if (q > p) return rest.substring(p + 1, q).trim();
        }

        return null;    }

    private boolean isLoadIntoRegister(String s, String reg) {
        if (s == null || reg == null) return false;

        String x = safe(s);
        String lo = x.toLowerCase();
        String rr = reg.toLowerCase();

        boolean load = lo.contains("memub ") ||
                       lo.contains("memuh ") ||
                       lo.contains("memw ") ||
                       lo.contains("memd ") ||
                       lo.contains("memb ");

        if (!load) return false;

        // Avoid needing an ISA parser: require the destination register
        // to occur before the first '(' or before the first comma if needed.
        int paren = x.indexOf('(');
        String lhs = paren >= 0 ? x.substring(0, paren) : x;
        return lhs.toLowerCase().contains(rr);
    }

    private void printCallsAfter(Instruction center, int count) {
        if (center == null || lines >= MAX_LINES) return;

        Instruction cur = center;
        int shown = 0;

        for (int i = 0; i < count && lines < MAX_LINES; i++) {
            Instruction n = currentProgram.getListing().getInstructionAfter(cur.getAddress());
            if (n == null) break;

            String s = safe(n.toString());
            if (isCall(s)) {
                println("  CALL AFTER: " + n.getAddress() + " : " + s);
                lines++;
                shown++;
            }

            cur = n;
        }

        if (shown == 0) println("  CALL AFTER: <none within " + count + " instructions>");
    }

    private void inspectCallSiteByAddress(long off) {
        if (monitor.isCancelled() || lines >= MAX_LINES) return;

        Address site = toAddr(off);
        Instruction callIns = currentProgram.getListing().getInstructionContaining(site);

        println("\n------------------------------------------------------------");
        println("FOCUSED CALL-SITE @ " + site);

        if (callIns == null) {
            println("INSTRUCTION: <none>");
            Instruction p = currentProgram.getListing().getInstructionBefore(site);
            Instruction n = currentProgram.getListing().getInstructionAfter(site);
            if (p != null) println("PREV: " + p.getAddress() + " : " + safe(p.toString()));
            if (n != null) println("NEXT: " + n.getAddress() + " : " + safe(n.toString()));
            return;
        }

        Function f = functionContaining(callIns.getAddress());
        println("FUNCTION: " + (f == null ? "<none>" : f.getName() + " @ " + f.getEntryPoint()));

        Instruction cur = callIns;
        ArrayList<Instruction> prev = new ArrayList<Instruction>();
        for (int i = 0; i < 10; i++) {
            Instruction p = currentProgram.getListing().getInstructionBefore(cur.getAddress());
            if (p == null) break;
            prev.add(p);
            cur = p;
        }
        for (int i = prev.size() - 1; i >= 0 && lines < MAX_LINES; i--) {
            Instruction p = prev.get(i);
            println("  PREV: " + p.getAddress() + " : " + safe(p.toString()));
            lines++;
        }

        println("  CALL: " + callIns.getAddress() + " : " + safe(callIns.toString()));
        lines++;

        cur = callIns;
        for (int i = 0; i < 14 && lines < MAX_LINES; i++) {
            Instruction n = currentProgram.getListing().getInstructionAfter(cur.getAddress());
            if (n == null) break;
            println("  NEXT: " + n.getAddress() + " : " + safe(n.toString()));
            lines++;
            cur = n;
        }
    }

    private void printCompactFunction(long off, int maxInsns, boolean onlyRelevant) {
        if (monitor.isCancelled() || lines >= MAX_LINES) return;

        Address entry = toAddr(off);
        Function f = functionContaining(entry);

        println("\n------------------------------------------------------------");
        println("COMPACT FUNCTION @ " + entry);
        if (f == null) {
            println("FUNCTION: <none>");
            return;
        }

        println("FUNCTION: " + f.getName() + " @ " + f.getEntryPoint());
        println("BODY: " + f.getBody());

        ArrayList<Instruction> a = collect(f);
        int shown = 0;

        // First 40 instructions are always shown to expose the true ABI/input setup.
        int head = Math.min(40, a.size());
        for (int i = 0; i < head && shown < maxInsns && lines < MAX_LINES; i++) {
            Instruction ins = a.get(i);
            println("  HEAD " + ins.getAddress() + " : " + safe(ins.toString()));
            lines++;
            shown++;
        }

        // Then show instructions near the known 0x4B parser and all calls/memory ops.
        for (int i = head; i < a.size() && shown < maxInsns && lines < MAX_LINES; i++) {
            if (monitor.isCancelled()) return;

            Instruction ins = a.get(i);
            String s = safe(ins.toString()).toLowerCase();

            boolean relevant =
                !onlyRelevant ||
                s.contains("mem") ||
                s.contains("call") ||
                s.contains("cmp") ||
                s.contains("assign r0") ||
                s.contains("assign r1") ||
                s.contains("assign r2") ||
                s.contains("assign r3") ||
                s.contains("r0") || s.contains("r1") ||
                s.contains("r2") || s.contains("r3") ||
                (ins.getAddress().getOffset() >= 0xc1902c88L &&
                 ins.getAddress().getOffset() <= 0xc1902cd8L);

            if (!relevant) continue;

            println("  " + ins.getAddress() + " : " + safe(ins.toString()));
            lines++;
            shown++;
        }

        println("SHOWN: " + shown + " / BOUNDED FUNCTION INSNS=" + a.size());
    }

    private void inspectCallSiteNeighborhood(long off, int before, int after) {
        if (monitor.isCancelled() || lines >= MAX_LINES) return;

        Address site = toAddr(off);
        Instruction center = currentProgram.getListing().getInstructionContaining(site);
        println("\n------------------------------------------------------------");
        println("CALL-SITE NEIGHBORHOOD @ " + site);

        if (center == null) {
            println("INSTRUCTION: <none>");
            return;        }

        Function f = functionContaining(center.getAddress());
        println("CALLER FUNCTION: " +
            (f == null ? "<none>" : f.getName() + " @ " + f.getEntryPoint()));

        Instruction cur = center;        ArrayList<Instruction> rev = new ArrayList<Instruction>();

        for (int i = 0; i < before; i++) {
            Instruction p = currentProgram.getListing().getInstructionBefore(cur.getAddress());
            if (p == null) break;
            rev.add(p);
            cur = p;        }

        for (int i = rev.size() - 1; i >= 0 && lines < MAX_LINES; i--) {
            Instruction p = rev.get(i);
            println("  PREV " + p.getAddress() + " : " + safe(p.toString()));
            lines++;
        }
        println("  CALL " + center.getAddress() + " : " + safe(center.toString()));
        lines++;

        cur = center;
        for (int i = 0; i < after && lines < MAX_LINES; i++) {            Instruction n = currentProgram.getListing().getInstructionAfter(cur.getAddress());
            if (n == null) break;
            println("  NEXT " + n.getAddress() + " : " + safe(n.toString()));
            lines++;
            cur = n;
        }
    }
    private void printIncomingCalls(long off, int max) {
        if (monitor.isCancelled() || lines >= MAX_LINES) return;

        Address entry = toAddr(off);
        Function f = functionContaining(entry);
        println("\n------------------------------------------------------------");
        println("INCOMING CALLS @ " + entry);
        if (f == null) {
            println("FUNCTION: <none>");
            return;
        }

        println("FUNCTION: " + f.getName() + " @ " + f.getEntryPoint());

        ReferenceIterator rit =
            currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());

        int n = 0;
        while (rit.hasNext() && n < max && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            Reference r = rit.next();
            if (!r.getReferenceType().isCall()) continue;

            Function caller = functionContaining(r.getFromAddress());
            println("  CALLER " + r.getFromAddress() + " <- " +
                (caller == null ? "<unknown>" :
                 caller.getName() + " @ " + caller.getEntryPoint()));
            lines++;
            n++;
        }

        if (n == 0) println("  <none>");
    }

    private void focusedParserTrace() {
        lines = 0;

        println("\n============================================================");
        println("FOCUSED RFDEBUG-ENTRY CANDIDATE TRACE");
        println("PRIMARY ONLY: c1902c74 / call-site c1902c70");
        println("SECONDARY SUMMARY ONLY: c1d1a760");
        println("NO GLOBAL SCANS / READ ONLY / HARD LIMITED");
        println("============================================================");

        // The most important candidate: keep its complete local ABI/input setup.
        printIncomingCalls(0xc1902c74L, 16);
        inspectCallSiteNeighborhood(0xc1902c70L, 30, 30);
        traceC1902Provenance();
        traceC18E7A50();
        traceC18D0970Registration();
        traceC18D0978External();
        traceC18D09ACRuntime();
        traceC18E7A50CallersAndObject();
        printCompactFunction(0xc1902c74L, MAX_C1902_INSNS, false);

        // Inspect the actual caller function, but do not dump the giant secondary parser.
        Instruction cs = currentProgram.getListing().getInstructionContaining(toAddr(0xc1902c70L));
        Function cf = (cs == null ? null : functionContaining(cs.getAddress()));

        if (cf != null) {
            println("\n------------------------------------------------------------");
            println("CALLER OF c1902c74: COMPACT DATAFLOW");
            println("FUNCTION: " + cf.getName() + " @ " + cf.getEntryPoint());

            ArrayList<Instruction> a = collect(cf);
            int shown = 0;

            // Show prologue and the region around c1902c70.
            for (int i = 0; i < a.size() && shown < MAX_CALLER_INSNS && lines < MAX_LINES; i++) {
                if (monitor.isCancelled()) return;

                Instruction ins = a.get(i);
                long off = ins.getAddress().getOffset();
                String s = safe(ins.toString()).toLowerCase();

                boolean nearCall = off >= 0xc1902bf0L && off <= 0xc1902d00L;
                boolean setup = i < 70;
                boolean important =
                    nearCall || setup ||
                    s.contains("call") ||
                    s.contains("memub") || s.contains("memb") ||
                    s.contains("memw") || s.contains("memd") ||
                    s.contains("sp+") ||
                    s.contains("r0") || s.contains("r1") ||
                    s.contains("r2") || s.contains("r3");

                if (!important) continue;

                println("  " + ins.getAddress() + " : " + safe(ins.toString()));
                lines++;
                shown++;
            }

            println("CALLER SHOWN: " + shown + " / BOUNDED FUNCTION INSNS=" + a.size());

            println("CALLS INTO THIS CALLER FUNCTION:");
            ReferenceIterator rit =
                currentProgram.getReferenceManager().getReferencesTo(cf.getEntryPoint());
            int n = 0;
            while (rit.hasNext() && n < 12 && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;
                Reference r = rit.next();
                if (!r.getReferenceType().isCall()) continue;

                Function caller2 = functionContaining(r.getFromAddress());
                println("  " + r.getFromAddress() + " <- " +
                    (caller2 == null ? "<unknown>" :
                     caller2.getName() + " @ " + caller2.getEntryPoint()));
                lines++;
                n++;
            }
        }

        // Secondary candidate only needs the entry/header and call-site evidence now.
        println("\n------------------------------------------------------------");
        println("SECONDARY CANDIDATE c1d1a760: SUMMARY");
        Function sf = functionContaining(toAddr(0xc1d1a760L));
        if (sf == null) {
            println("FUNCTION: <none>");
        } else {
            println("FUNCTION: " + sf.getName() + " @ " + sf.getEntryPoint());
            println("The previous run already established: 0x4B is read from (R22++#1),");
            println("then the same parser checks 0x76, 0x45, 0x52, 0x4F, 0x45, 0x5F,");
            println("and repeatedly manipulates heap/list buffer pointers.");
            println("This is lower priority than c1902c74.");
        }

        println("\n============================================================");
        println("FOCUSED TRACE COMPLETE");
        println("============================================================");
    }



    private void traceC1902Provenance() {
        println("\n============================================================");
        println("C1902 PROVENANCE TRACE");
        println("TARGETS: c1902c70 / c1902c74 / c1902bc0 / c18d0a18");
        println("READ ONLY / HARD LIMITED");
        println("============================================================");

        long[] targets = {
            0xc1902c70L,
            0xc1902c74L,
            0xc1902bc0L,
            0xc18d0a18L
        };

        for (int t = 0; t < targets.length; t++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            Address a = toAddr(targets[t]);
            Function f = functionContaining(a);

            println("\n------------------------------------------------------------");
            println("TARGET: " + a);
            println("FUNCTION: " +
                (f == null ? "<none>" :
                 f.getName() + " @ " + f.getEntryPoint()));

            ReferenceIterator rit =
                currentProgram.getReferenceManager().getReferencesTo(a);

            int n = 0;
            while (rit.hasNext() && n < 24 && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;

                Reference r = rit.next();                Function rf = functionContaining(r.getFromAddress());

                println("  REF FROM " + r.getFromAddress() +
                        " TYPE=" + r.getReferenceType() +
                        " " + (r.isPrimary() ? "PRIMARY " : "") +
                        "<-" +
                        (rf == null ? "<none>" :                         rf.getName() + " @ " + rf.getEntryPoint()));
                lines++;
                n++;
            }

            if (n == 0) println("  REF: <none>");
        }
        println("\n------------------------------------------------------------");
        println("C1902C70 PREDECESSOR CHAIN");

        Instruction cur =
            currentProgram.getListing().
            getInstructionBefore(toAddr(0xc1902c70L));

        int prevShown = 0;        while (cur != null && prevShown < 48 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            println("  PREV " + cur.getAddress() +
                    " : " + safe(cur.toString()));
            lines++;            prevShown++;

            String m = safe(cur.getMnemonicString()).toLowerCase();
            if (m.equals("jump") || m.startsWith("jump.")) break;

            cur =
                currentProgram.getListing().                getInstructionBefore(cur.getAddress());
        }

        println("\n------------------------------------------------------------");
        println("c1902bc0 FUNCTION");

        Function bf = functionContaining(toAddr(0xc1902bc0L));        if (bf == null) {
            println("  FUNCTION: <none>");
        } else {
            println("  FUNCTION: " + bf.getName() +
                    " @ " + bf.getEntryPoint());
            println("  BODY: " + bf.getBody());

            ArrayList<Instruction> a = collect(bf);
            int shown = 0;
            for (Instruction ins : a) {
                if (monitor.isCancelled() ||
                    shown >= 120 ||
                    lines >= MAX_LINES) return;

                println("  " + ins.getAddress() +
                        " : " + safe(ins.toString()));
                lines++;
                shown++;
            }
            println("  SHOWN=" + shown +
                    " / BOUNDED=" + a.size());
        }

        println("\n------------------------------------------------------------");
        println("c18d0a18 FUNCTION");

        Function df = functionContaining(toAddr(0xc18d0a18L));
        if (df == null) {
            println("  FUNCTION: <none>");
        } else {
            println("  FUNCTION: " + df.getName() +
                    " @ " + df.getEntryPoint());
            println("  BODY: " + df.getBody());

            ArrayList<Instruction> a = collect(df);
            int shown = 0;
            for (Instruction ins : a) {
                if (monitor.isCancelled() ||
                    shown >= 160 ||
                    lines >= MAX_LINES) return;

                println("  " + ins.getAddress() +
                        " : " + safe(ins.toString()));
                lines++;
                shown++;
            }
            println("  SHOWN=" + shown +
                    " / BOUNDED=" + a.size());
        }

        println("\n============================================================");
        println("C1902 PROVENANCE TRACE COMPLETE");
        println("============================================================");
    }


    private void traceC18E7A50() {
        println("\n============================================================");
        println("C18E7A50 / C1902C70 PARAM-REFERENCE TRACE");
        println("PURPOSE: determine what the PARAM reference at c18e7af0 means");
        println("READ ONLY / HARD LIMITED");
        println("============================================================");

        Address target = toAddr(0xc18e7af0L);
        Instruction ti =
            currentProgram.getListing().getInstructionContaining(target);

        println("TARGET INSTRUCTION: " + target);
        println("INS: " + (ti == null ? "<none>" : safe(ti.toString())));

        Function tf = functionContaining(target);
        println("FUNCTION: " +
            (tf == null ? "<none>" :
             tf.getName() + " @ " + tf.getEntryPoint()));

        println("\nREFERENCES TO c18e7af0:");

        ReferenceIterator tr =
            currentProgram.getReferenceManager().
            getReferencesTo(target);

        int trn = 0;
        while (tr.hasNext() && trn < 24 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            Reference r = tr.next();
            Function rf = functionContaining(r.getFromAddress());

            println("  FROM " + r.getFromAddress() +
                    " TYPE=" + r.getReferenceType() +
                    " " + (r.isPrimary() ? "PRIMARY " : "") +
                    "<-" +
                    (rf == null ? "<none>" :
                     rf.getName() + " @ " + rf.getEntryPoint()));

            lines++;
            trn++;
        }

        println("\n------------------------------------------------------------");
        println("FUN_c18e7a50 BOUNDED BODY");

        if (tf == null) {
            println("FUNCTION: <none>");
            return;
        }

        println("BODY: " + tf.getBody());

        ArrayList<Instruction> a = collect(tf);
        int bodyShown = 0;

        for (int i = 0; i < a.size() && bodyShown < 240 && lines < MAX_LINES; i++) {
            if (monitor.isCancelled()) return;

            Instruction ins = a.get(i);
            long off = ins.getAddress().getOffset();

            // Print the bounded function body; explicitly mark the target.
            println((off == 0xc18e7af0L ? ">>> " : "    ") +
                    ins.getAddress() + " : " + safe(ins.toString()));

            lines++;
            bodyShown++;
        }

        println("BODY SHOWN: " + bodyShown + " / BOUNDED=" + a.size());

        println("\n------------------------------------------------------------");
        println("LOCAL WINDOW AROUND c18e7af0");

        int idx = -1;
        for (int i = 0; i < a.size(); i++) {
            if (a.get(i).getAddress().getOffset() == 0xc18e7af0L) {
                idx = i;
                break;
            }
        }

        if (idx >= 0) {
            int st = Math.max(0, idx - 20);
            int en = Math.min(a.size(), idx + 28);

            for (int i = st; i < en && lines < MAX_LINES; i++) {
                if (monitor.isCancelled()) return;

                Instruction ins = a.get(i);
                println((i == idx ? ">>> " : "    ") +
                        ins.getAddress() + " : " + safe(ins.toString()));
                lines++;
            }
        } else {
            println("c18e7af0 not found as an instruction in containing function.");
        }

        println("\n------------------------------------------------------------");
        println("REFERENCES TO c1902c70 FROM THIS AREA");

        ReferenceIterator rr =
            currentProgram.getReferenceManager().
            getReferencesTo(toAddr(0xc1902c70L));

        int refShown = 0;
        while (rr.hasNext() && refShown < 16 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            Reference r = rr.next();

            if (r.getFromAddress().getOffset() >= 0xc18e7a20L &&
                r.getFromAddress().getOffset() <= 0xc18e7b40L) {

                println("  FROM " + r.getFromAddress() +
                        " TYPE=" + r.getReferenceType() +                        " " + (r.isPrimary() ? "PRIMARY" : ""));
                lines++;
                refShown++;
            }
        }

        if (refShown == 0) println("  <none in local range>");
        println("\nC18E7A50 TRACE COMPLETE");
    }


    private void traceC18D0970Registration() {
        println("\n============================================================");
        println("C18D0970 REGISTRATION / C1902C70 CALLBACK TRACE");        println("PURPOSE: determine what callback c1902c70 is registered for");
        println("READ ONLY / HARD LIMITED");
        println("============================================================");

        long[] targets = {
            0xc18d0970L,
            0xc18e7840L,
            0xc18e7980L,            0xc18e7a50L,
            0xc1902c70L,
            0xc1902c74L
        };

        for (int t = 0; t < targets.length; t++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;
            Address a = toAddr(targets[t]);
            Function f = functionContaining(a);

            println("\n------------------------------------------------------------");
            println("TARGET: " + a);
            println("FUNCTION: " +
                (f == null ? "<none>" :
                 f.getName() + " @ " + f.getEntryPoint()));
            println("REFERENCES:");

            ReferenceIterator rit =
                currentProgram.getReferenceManager().getReferencesTo(a);

            int n = 0;
            while (rit.hasNext() && n < 24 && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;

                Reference r = rit.next();
                Function rf = functionContaining(r.getFromAddress());

                println("  FROM " + r.getFromAddress() +
                        " TYPE=" + r.getReferenceType() +
                        "<-" +
                        (rf == null ? "<none>" :
                         rf.getName() + " @ " + rf.getEntryPoint()));

                lines++;
                n++;
            }

            if (n == 0) println("  <none>");
        }

        println("\n------------------------------------------------------------");
        println("FUN_c18d0970 BODY");

        Function rf = functionContaining(toAddr(0xc18d0970L));
        if (rf == null) {
            println("FUNCTION: <none>");
        } else {
            println("FUNCTION: " + rf.getName() +
                    " @ " + rf.getEntryPoint());
            println("BODY: " + rf.getBody());

            ArrayList<Instruction> a = collect(rf);
            int shown = 0;

            for (Instruction ins : a) {
                if (monitor.isCancelled() ||
                    shown >= 220 ||
                    lines >= MAX_LINES) return;

                println("  " + ins.getAddress() +
                        " : " + safe(ins.toString()));
                lines++;
                shown++;
            }

            println("SHOWN: " + shown +
                    " / BOUNDED=" + a.size());
        }

        println("\n------------------------------------------------------------");
        println("REGISTRATION CALL SITE c18e7af0");

        Instruction center =
            currentProgram.getListing().
            getInstructionContaining(toAddr(0xc18e7af0L));

        if (center == null) {
            println("INSTRUCTION: <none>");
        } else {
            println("CENTER: " + center.getAddress() +
                    " : " + safe(center.toString()));

            Instruction cur = center;
            ArrayList<Instruction> prev = new ArrayList<Instruction>();

            for (int i = 0; i < 8; i++) {
                Instruction q =
                    currentProgram.getListing().
                    getInstructionBefore(cur.getAddress());
                if (q == null) break;
                prev.add(q);
                cur = q;
            }

            for (int i = prev.size() - 1; i >= 0 && lines < MAX_LINES; i--) {
                Instruction q = prev.get(i);
                println("  PREV " + q.getAddress() +
                        " : " + safe(q.toString()));
                lines++;
            }

            println("  TARGET " + center.getAddress() +
                    " : " + safe(center.toString()));
            lines++;

            cur = center;
            for (int i = 0; i < 12 && lines < MAX_LINES; i++) {
                Instruction q =
                    currentProgram.getListing().
                    getInstructionAfter(cur.getAddress());
                if (q == null) break;

                println("  NEXT " + q.getAddress() +
                        " : " + safe(q.toString()));
                lines++;
                cur = q;
            }
        }

        println("\n------------------------------------------------------------");
        println("CALL SITES OF c18d0970 INSIDE FUN_c18e7a50");

        Function af = functionContaining(toAddr(0xc18e7a50L));
        if (af != null) {
            ArrayList<Instruction> a = collect(af);
            int shown = 0;

            for (Instruction ins : a) {
                if (monitor.isCancelled() ||
                    shown >= 16 ||
                    lines >= MAX_LINES) return;

                String s = safe(ins.toString());
                if (!s.contains("c18d0970")) continue;

                println("  CALLSITE " + ins.getAddress() +
                        " : " + s);
                lines++;
                shown++;
            }

            if (shown == 0) println("  <none>");
        }

        println("\n============================================================");
        println("C18D0970 REGISTRATION TRACE COMPLETE");
        println("============================================================");
    }


    private void traceC18D0978External() {
        println("\n============================================================");
        println("C18D0970 -> C18D0978 EXTERNAL TARGET TRACE");
        println("PURPOSE: resolve the real API behind the callback registration veneer");
        println("READ ONLY / HARD LIMITED");
        println("============================================================");

        Address veneer = toAddr(0xc18d0970L);
        Address target = toAddr(0xc18d0978L);

        println("VENEER: " + veneer);
        println("TARGET: " + target);

        println("\n------------------------------------------------------------");
        println("c18d0970 INSTRUCTIONS");

        Instruction vi =
            currentProgram.getListing().
            getInstructionContaining(veneer);

        if (vi == null) {
            println("  <none>");
        } else {
            println("  " + vi.getAddress() + " : " + safe(vi.toString()));
            Instruction vn =
                currentProgram.getListing().
                getInstructionAfter(vi.getAddress());

            if (vn != null) {
                println("  " + vn.getAddress() + " : " + safe(vn.toString()));
            }
        }

        println("\n------------------------------------------------------------");
        println("c18d0978 TARGET INSTRUCTION / SYMBOL / BLOCK");

        Instruction ti =
            currentProgram.getListing().
            getInstructionContaining(target);

        println("INSTRUCTION: " +
            (ti == null ? "<none>" :
             ti.getAddress() + " : " + safe(ti.toString())));

        println("PRIMARY SYMBOL: " +
            (currentProgram.getSymbolTable().getPrimarySymbol(target) == null ?
             "<none>" :
             currentProgram.getSymbolTable().getPrimarySymbol(target).getName()));
        MemoryBlock block = currentProgram.getMemory().getBlock(target);
        println("MEMORY BLOCK: " +
            (block == null ? "<none>" :
             block.getName() + " [" + block.getStart() + " - " +
             block.getEnd() + "] EXEC=" + block.isExecute() +
             " READ=" + block.isRead() +
             " WRITE=" + block.isWrite()));

        println("\nNEXT 16 INSTRUCTIONS AT/AFTER c18d0978:");
        Instruction curIns = ti;
        int shown = 0;

        if (curIns == null) {
            curIns =
                currentProgram.getListing().
                getInstructionAfter(target);
        }

        while (curIns != null && shown < 16 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            println("  " + curIns.getAddress() +
                    " : " + safe(curIns.toString()));
            lines++;
            shown++;

            Instruction nx =
                currentProgram.getListing().
                getInstructionAfter(curIns.getAddress());
            if (nx == null) break;
            curIns = nx;
        }

        println("\nREFERENCES TO c18d0978:");

        ReferenceIterator rit =
            currentProgram.getReferenceManager().
            getReferencesTo(target);

        int refs = 0;
        while (rit.hasNext() && refs < 32 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            Reference r = rit.next();
            Function f = functionContaining(r.getFromAddress());

            println("  FROM " + r.getFromAddress() +
                    " TYPE=" + r.getReferenceType() +
                    "<-" +
                    (f == null ? "<none>" :
                     f.getName() + " @ " + f.getEntryPoint()));
            lines++;
            refs++;
        }

        if (refs == 0) println("  <none>");

        println("\n------------------------------------------------------------");
        println("c18d0970 CALL SITES / INPUT REGISTERS");

        ReferenceIterator cr =
            currentProgram.getReferenceManager().
            getReferencesTo(veneer);

        int callsites = 0;

        while (cr.hasNext() && callsites < 16 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            Reference r = cr.next();
            if (!r.getReferenceType().isCall()) continue;

            Address ca = r.getFromAddress();
            Function f = functionContaining(ca);

            println("\n  CALLSITE: " + ca +
                    " FUNCTION=" +
                    (f == null ? "<none>" :
                     f.getName() + " @ " + f.getEntryPoint()));

            Instruction ci =
                currentProgram.getListing().
                getInstructionContaining(ca);

            if (ci == null) {
                println("    <instruction unavailable>");
                callsites++;
                continue;
            }

            Instruction x = ci;
            ArrayList<Instruction> prev = new ArrayList<Instruction>();

            for (int i = 0; i < 8; i++) {
                Instruction q =
                    currentProgram.getListing().
                    getInstructionBefore(x.getAddress());
                if (q == null) break;
                prev.add(q);
                x = q;
            }

            for (int i = prev.size() - 1; i >= 0 && lines < MAX_LINES; i--) {
                Instruction q = prev.get(i);
                println("    PREV " + q.getAddress() +
                        " : " + safe(q.toString()));
                lines++;
            }

            println("    CALL " + ci.getAddress() +
                    " : " + safe(ci.toString()));
            lines++;

            callsites++;
        }

        println("\n============================================================");
        println("C18D0978 EXTERNAL TARGET TRACE COMPLETE");
        println("============================================================");
    }


    private void traceC18D09ACRuntime() {
        println("\n============================================================");
        println("C18D09AC -> D89AD4A8 RUNTIME-CALL TRACE");
        println("PURPOSE: resolve the final shared-runtime call used by c18d0978");
        println("READ ONLY / HARD LIMITED");
        println("============================================================");

        long[] targets = {
            0xc18d09acL,
            0xd89ad4a8L,
            0xc18d0978L
        };

        for (int t = 0; t < targets.length; t++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            Address a = toAddr(targets[t]);
            Function f = functionContaining(a);

            println("\n------------------------------------------------------------");
            println("TARGET: " + a);
            println("FUNCTION: " +
                (f == null ? "<none>" :
                 f.getName() + " @ " + f.getEntryPoint()));

            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            println("BLOCK: " +
                (b == null ? "<none>" :
                 b.getName() + " [" + b.getStart() + " - " +
                 b.getEnd() + "] EXEC=" + b.isExecute() +
                 " READ=" + b.isRead() +
                 " WRITE=" + b.isWrite()));

            println("REFERENCES TO TARGET:");

            ReferenceIterator rit =
                currentProgram.getReferenceManager().
                getReferencesTo(a);

            int n = 0;
            while (rit.hasNext() && n < 32 && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;

                Reference r = rit.next();
                Function rf = functionContaining(r.getFromAddress());

                println("  FROM " + r.getFromAddress() +
                        " TYPE=" + r.getReferenceType() +
                        "<-" +
                        (rf == null ? "<none>" :
                         rf.getName() + " @ " + rf.getEntryPoint()));
                lines++;
                n++;
            }

            if (n == 0) println("  <none>");
        }

        println("\n------------------------------------------------------------");
        println("c18d09ac LOCAL");

        Function af = functionContaining(toAddr(0xc18d09acL));
        if (af == null) {
            println("FUNCTION: <none>");
        } else {
            println("FUNCTION: " + af.getName() +
                    " @ " + af.getEntryPoint());
            ArrayList<Instruction> a = collect(af);
            int shown = 0;

            for (Instruction ins : a) {
                if (monitor.isCancelled() ||
                    shown >= 32 ||
                    lines >= MAX_LINES) return;

                println("  " + ins.getAddress() +
                        " : " + safe(ins.toString()));
                lines++;
                shown++;
            }

            println("SHOWN: " + shown +
                    " / BOUNDED=" + a.size());
        }

        println("\n------------------------------------------------------------");        println("D89AD4A8 LOCAL WINDOW");

        Instruction center =
            currentProgram.getListing().
            getInstructionContaining(toAddr(0xd89ad4a8L));

        if (center == null) {
            println("  INSTRUCTION: <none>");
        } else {
            println("  CENTER " + center.getAddress() +
                    " : " + safe(center.toString()));

            Instruction cur = center;
            ArrayList<Instruction> prev = new ArrayList<Instruction>();

            for (int i = 0; i < 12; i++) {
                Instruction q =
                    currentProgram.getListing().
                    getInstructionBefore(cur.getAddress());
                if (q == null) break;
                prev.add(q);
                cur = q;
            }

            for (int i = prev.size() - 1; i >= 0 && lines < MAX_LINES; i--) {
                Instruction q = prev.get(i);
                println("  PREV " + q.getAddress() +
                        " : " + safe(q.toString()));
                lines++;
            }

            cur = center;
            for (int i = 0; i < 20 && lines < MAX_LINES; i++) {
                Instruction q =
                    currentProgram.getListing().
                    getInstructionAfter(cur.getAddress());
                if (q == null) break;

                println("  NEXT " + q.getAddress() +
                        " : " + safe(q.toString()));
                lines++;
                cur = q;
            }
        }

        println("\n------------------------------------------------------------");
        println("c18d0978 PARAMETER SHAPE");

        Function sf = functionContaining(toAddr(0xc18d0978L));
        if (sf != null) {
            ArrayList<Instruction> a = collect(sf);

            for (int i = 0; i < a.size() && lines < MAX_LINES; i++) {
                if (monitor.isCancelled()) return;

                Instruction ins = a.get(i);
                long off = ins.getAddress().getOffset();

                if (off >= 0xc18d0978L && off <= 0xc18d09a8L) {
                    println("  " + ins.getAddress() +
                            " : " + safe(ins.toString()));
                    lines++;
                }
            }
        }

        println("\n------------------------------------------------------------");
        println("c18d0978 CALL SITES / OBJECT FIELD SHAPE");

        ReferenceIterator cr =
            currentProgram.getReferenceManager().
            getReferencesTo(toAddr(0xc18d0978L));

        int shownCalls = 0;

        while (cr.hasNext() && shownCalls < 16 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            Reference r = cr.next();
            if (!r.getReferenceType().isCall()) continue;

            Function f = functionContaining(r.getFromAddress());

            println("  CALL FROM " + r.getFromAddress() +
                    " FUNCTION=" +
                    (f == null ? "<none>" :
                     f.getName() + " @ " + f.getEntryPoint()));
            lines++;
            shownCalls++;
        }

        println("\n------------------------------------------------------------");
        println("c18e7a50 REGISTRATION OBJECT WINDOWS");

        Function ef = functionContaining(toAddr(0xc18e7a50L));
        if (ef != null) {
            ArrayList<Instruction> a = collect(ef);
            int[] sites = { 0xc18e7af0, 0xc18e7b98 };

            for (int s = 0; s < sites.length && lines < MAX_LINES; s++) {
                int want = sites[s];
                int idx = -1;

                for (int i = 0; i < a.size(); i++) {
                    if ((int)a.get(i).getAddress().getOffset() == want) {
                        idx = i;
                        break;
                    }
                }

                if (idx < 0) continue;

                println("  SITE @ " + a.get(idx).getAddress());

                int st = Math.max(0, idx - 6);
                int en = Math.min(a.size(), idx + 8);

                for (int i = st; i < en && lines < MAX_LINES; i++) {
                    Instruction ins = a.get(i);
                    println("    " + ins.getAddress() +
                            " : " + safe(ins.toString()));
                    lines++;
                }
            }
        }

        println("\n============================================================");
        println("C18D09AC RUNTIME TRACE COMPLETE");
        println("============================================================");
    }


    private void traceC18E7A50CallersAndObject() {
        println("\n============================================================");
        println("C18E7A50 CALLERS / OBJECT-FIELD TRACE");
        println("PURPOSE: identify what c18e7a50 builds and what fields reach c18d0978");
        println("READ ONLY / HARD LIMITED");
        println("============================================================");

        Address target = toAddr(0xc18e7a50L);

        ReferenceIterator rit =
            currentProgram.getReferenceManager().getReferencesTo(target);

        int n = 0;

        while (rit.hasNext() && n < 12 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            Reference r = rit.next();
            if (!r.getReferenceType().isCall()) continue;

            Address ca = r.getFromAddress();
            Function f = functionContaining(ca);

            println("\n------------------------------------------------------------");
            println("CALLER OF c18e7a50: " + ca);
            println("FUNCTION: " +
                (f == null ? "<none>" :
                 f.getName() + " @ " + f.getEntryPoint()));

            if (f == null) {
                n++;
                continue;
            }

            ArrayList<Instruction> a = collect(f);
            int idx = -1;

            for (int i = 0; i < a.size(); i++) {
                if (a.get(i).getAddress().equals(ca)) {
                    idx = i;
                    break;
                }
            }

            if (idx >= 0) {
                int st = Math.max(0, idx - 24);
                int en = Math.min(a.size(), idx + 36);

                for (int i = st; i < en && lines < MAX_LINES; i++) {
                    if (monitor.isCancelled()) return;

                    Instruction ins = a.get(i);
                    println("  " +
                        (i == idx ? ">>> " : "    ") +
                        ins.getAddress() + " : " +
                        safe(ins.toString()));
                    lines++;
                }
            }

            n++;
        }

        println("\n------------------------------------------------------------");
        println("C18E7A50 OBJECT FIELD OFFSETS");

        println("The callback sites use R25 as R0 into c18d0970.");
        println("For first registration:");
        println("  R25 = R19 + (R24 * 0x2480) + 0x94");
        println("  c18d0978 reads R0+0x10 and R0+0x12");
        println("  => backing object fields are base +0xA4 and base +0xA6");
        println("For second registration:");
        println("  R25 = R19 + (R24 * 0x30) + 0x18");
        println("  c18d0978 reads R0+0x10 and R0+0x12");
        println("  => backing object fields are base +0x28 and base +0x2A");

        println("\n------------------------------------------------------------");
        println("C18D0978 CALL PARAMETER FLOW");

        Function sf = functionContaining(toAddr(0xc18d0978L));
        if (sf != null) {
            ArrayList<Instruction> a = collect(sf);

            int shown = 0;
            for (Instruction ins : a) {
                if (monitor.isCancelled() ||
                    shown >= 24 ||
                    lines >= MAX_LINES) return;

                println("  " + ins.getAddress() +
                        " : " + safe(ins.toString()));
                lines++;
                shown++;
            }
        }

        println("\n------------------------------------------------------------");
        println("C18E7A50 CALLBACK CONSTANTS");

        long[] constants = {
            0xc1902c70L,
            0xc1903840L,
            0xc1903858L
        };

        for (int i = 0; i < constants.length; i++) {
            if (monitor.isCancelled() || lines >= MAX_LINES) return;

            Address a = toAddr(constants[i]);

            println("  " + a +
                    " PRIMARY=" +
                    (currentProgram.getSymbolTable().getPrimarySymbol(a) == null ?
                     "<none>" :
                     currentProgram.getSymbolTable().getPrimarySymbol(a).getName()));

            ReferenceIterator x =
                currentProgram.getReferenceManager().getReferencesTo(a);

            int xn = 0;
            while (x.hasNext() && xn < 16 && lines < MAX_LINES) {
                if (monitor.isCancelled()) return;

                Reference r = x.next();

                println("    REF " + r.getFromAddress() +
                        " TYPE=" + r.getReferenceType());
                lines++;
                xn++;
            }

            if (xn == 0) println("    REF <none>");
        }

        println("\n============================================================");
        println("C18E7A50 CALLER / OBJECT TRACE COMPLETE");
        println("============================================================");
    }

    private void deepInspectLikelyParsers() {
        println("\n============================================================");
        println("DEEP INSPECTION OF REAL 0x4B PARSER CANDIDATES");
        println("TARGET A: FUN_c1902c74 @ c1902c74");
        println("TARGET B: FUN_c1d1a760 @ c1d1a760");
        println("READ ONLY / HARD LIMITED");
        println("============================================================");

        inspectCallSiteByAddress(0xc1902c70L);
        inspectFunctionByAddress(0xc1902c74L);
        inspectFunctionByAddress(0xc1d1a760L);
    }

    private void inspectFunctionByAddress(long off) {
        if (monitor.isCancelled() || lines >= MAX_LINES) return;

        Address entry = toAddr(off);
        Function f = functionContaining(entry);

        println("\n------------------------------------------------------------");
        println("DEEP FUNCTION @ " + entry);

        if (f == null) {
            println("FUNCTION: <none>");
            return;
        }

        println("FUNCTION: " + f.getName() + " @ " + f.getEntryPoint());
        println("BODY: " + f.getBody());
        ArrayList<Instruction> a = collect(f);
        println("INSTRUCTION COUNT (bounded): " + a.size());

        int exact4 = 0;
        int exact0 = 0;
        int byteLoads = 0;
        int calls = 0;
        int printed = 0;

        for (int i = 0; i < a.size() && lines < MAX_LINES && printed < MAX_DEEP_INSNS; i++) {
            Instruction ins = a.get(i);
            String s = safe(ins.toString());
            if (isExact4BInsn(ins)) exact4++;
            if (isExact0BInsn(ins)) exact0++;

            String lo = s.toLowerCase();
            if (lo.contains("memub") || lo.contains("memuh") || lo.contains("memb")) byteLoads++;
            if (isCall(s)) calls++;

            // Print every instruction for these small target functions.
            println("  " + ins.getAddress() + " : " + s);
            lines++;
            printed++;
        }

        println("SUMMARY: exact4B=" + exact4 +
                " exact0B=" + exact0 +
                " byteLoads=" + byteLoads +
                " calls=" + calls);

        println("CALL XREFS INTO FUNCTION:");
        ReferenceIterator rit =
            currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());

        int shown = 0;
        while (rit.hasNext() && shown < 32 && lines < MAX_LINES) {
            if (monitor.isCancelled()) return;

            Reference r = rit.next();
            if (!r.getReferenceType().isCall()) continue;
            Function caller = functionContaining(r.getFromAddress());
            println("  CALLER " + r.getFromAddress() + " <- " +
                (caller == null ? "<unknown>" :
                 caller.getName() + " @ " + caller.getEntryPoint()));
            lines++;
            shown++;
        }
        if (shown == 0) println("  <none>");
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
        println(" TRACE_BUILD=" + TRACE_BUILD);
        println(" C1902 PRIMARY TRACE / READ ONLY");
        println("============================================================");

        focusedParserTrace();

        println("\n============================================================");
        println("DONE");
        println("No memory, symbols, comments, or program structures modified.");        println("============================================================");
    }
}