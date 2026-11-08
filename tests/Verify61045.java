import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.zip.*;
import com.android.apksig.ApkVerifier;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedMethodImplementation;
import com.android.tools.smali.dexlib2.dexbacked.instruction.DexBackedInstruction;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;

public class Verify61045 {
  static final String OWNER="Lcom/duolingo/core/energy/models/EnergyConfig;";
  static final String ORD=OWNER+"-><init>(IIJJJIJLjava/lang/Integer;)V";
  static final String SYN=OWNER+"-><init>(IIIJJJIJLjava/lang/Integer;Z)V";
  static final String TARGET="Lf7l;->a()Z";
  static final Set<String> CALLERS=Set.of("Lyd0;->E(Lvp8;Lgpr;Lfpp;Lsp8;)Ljava/lang/Object;", "Lcom/duolingo/sessionend/NetworkInterstitialAdFragment;->onViewCreated(Lfza0;Landroid/os/Bundle;)V");
  static final Map<String,String> HASHES=Map.of("com.duolingo.apk","6639406ae10ced95627b0730261c500f6ddcc02d1b4d1704ee4b38fe3791e335", "config.arm64_v8a.apk","1acec42e8bf9eb4acdb08e44627ff30f34b55b95a21c660f8dded37cf3204e89", "config.xxxhdpi.apk","b75c3dd346a521c09660697510c85c453d6a75157c7cdce17acf35df1400202c");
  static final String ORIGINAL_CERT="1233ff6de4c70ef4d7deae54af15b167fc7cfd2539517bd2175870f3cb771731";
  static void check(boolean ok,String message) { if(!ok) throw new AssertionError(message); }
  static byte[] digest(String alg, byte[] b) throws Exception { return MessageDigest.getInstance(alg).digest(b); }
  static String hex(byte[] b) { return HexFormat.of().formatHex(b); }
  static String sha(Path p) throws Exception { var d=MessageDigest.getInstance("SHA-256"); try(var in=Files.newInputStream(p)) { byte[] b=new byte[65536]; for(int n;(n=in.read(b))!=-1;) d.update(b,0,n); } return hex(d.digest()); }
  static String desc(MethodReference m) { return m.getDefiningClass()+"->"+m.getName()+"("+String.join("",m.getParameterTypes())+")"+m.getReturnType(); }
  static boolean signing(String name) { String u=name.toUpperCase(Locale.ROOT); return u.startsWith("META-INF/") && (u.endsWith(".SF") || u.endsWith(".RSA") || u.endsWith(".DSA") || u.endsWith(".EC") || u.equals("META-INF/MANIFEST.MF") || u.startsWith("META-INF/SIG-")); }
  static Map<String,ZipEntry> entries(ZipFile z) { var m=new HashMap<String,ZipEntry>(); for(var e:Collections.list(z.entries())) { check(m.put(e.getName(),e)==null,"duplicate zip entry "+e.getName()); } return m; }
  static Set<String> inventory(Path dir) throws Exception { try(var s=Files.list(dir)) { var result=new HashSet<String>(); s.filter(p->p.getFileName().toString().endsWith(".apk")).forEach(p->result.add(p.getFileName().toString())); return result; } }
  static void signature(Path apk, byte[] expected, String expectedHash) throws Exception {
    var r=new ApkVerifier.Builder(apk.toFile()).build().verify();
    check(r.isVerified() && r.getSignerCertificates().size()==1,"signature verification failed: "+apk+" "+r.getErrors());
    byte[] c=r.getSignerCertificates().get(0).getEncoded();
    check(expected==null || Arrays.equals(expected,c),"unexpected signer: "+apk);
    check(expectedHash==null || hex(digest("SHA-256",c)).equals(expectedHash),"unexpected original signer: "+apk);
  }
  static void dexIntegrity(byte[] b, String name) throws Exception {
    check(b.length>=112 && b[0]=='d' && b[1]=='e' && b[2]=='x' && b[3]=='\n',"DEX magic: "+name);
    int size=java.nio.ByteBuffer.wrap(b,32,4).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
    check(size==b.length,"DEX file size: "+name);
    check(Arrays.equals(Arrays.copyOfRange(b,12,32),digest("SHA-1",Arrays.copyOfRange(b,32,b.length))),"DEX SHA-1: "+name);
    var ad=new Adler32(); ad.update(b,12,b.length-12);
    check(Integer.toUnsignedLong(java.nio.ByteBuffer.wrap(b,8,4).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt())==ad.getValue(),"DEX Adler32: "+name);
  }
  static Map<String,Method> scan(Path apk) throws Exception {
    var found=new HashMap<String,Method>(); var callers=new HashSet<String>(); int targetCount=0, ordCount=0, synCount=0, callCount=0;
    try(var z=new ZipFile(apk.toFile())) {
      for(var e:entries(z).values()) if(e.getName().matches("classes[0-9]*\\.dex")) {
        byte[] b=z.getInputStream(e).readAllBytes(); dexIntegrity(b,e.getName());
        var dex=new DexBackedDexFile(Opcodes.getDefault(),b);
        for(var c:dex.getClasses()) for(var m:c.getMethods()) {
          String d=desc(m); boolean keep=c.getType().equals(OWNER) || d.equals(TARGET) || CALLERS.contains(d);
          if(d.equals(TARGET)) { targetCount++; check(e.getName().equals("classes5.dex"),"readiness DEX"); }
          if(d.equals(ORD)) { ordCount++; check(e.getName().equals("classes.dex"),"ordinary DEX"); }
          if(d.equals(SYN)) { synCount++; check(e.getName().equals("classes.dex"),"synthetic DEX"); }
          if(keep) check(found.put(d,m)==null,"duplicate method "+d);
          if(m.getImplementation()!=null) for(var i:m.getImplementation().getInstructions()) if(i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference ref && desc(ref).equals(TARGET)) { callers.add(d); callCount++; }
        }
      }
    }
    check(targetCount==1 && ordCount==1 && synCount==1,"target uniqueness");
    check(callCount==2 && callers.equals(CALLERS),"readiness callers: "+callers+" count="+callCount);
    check(found.keySet().containsAll(CALLERS),"missing readiness caller");
    return found;
  }
  static List<Instruction> ins(Method m) { var result=new ArrayList<Instruction>(); m.getImplementation().getInstructions().forEach(result::add); return result; }
  static int start(Method m) { return ((DexBackedInstruction)ins(m).get(0)).instructionStart; }
  static int header(Method m,int offset) { var b=(DexBackedMethodImplementation)m.getImplementation(); return offset==12 ? b.dexFile.getDataBuffer().readSmallUint(start(m)-16+offset) : b.dexFile.getDataBuffer().readUshort(start(m)-16+offset); }
  static void shape(Method m,int flags,int regs,int in,int out,int tries,int count,int units) {
    check(m.getAccessFlags()==flags && m.getImplementation().getRegisterCount()==regs && header(m,2)==in && header(m,4)==out && m.getImplementation().getTryBlocks().size()==tries && ins(m).size()==count && header(m,12)==units,"method header/instruction mismatch: "+desc(m));
  }
  static List<String> normalizedBody(Method m, Set<Integer> insertedIndices) {
    var all=ins(m); var addresses=new HashMap<Integer,Integer>(); int address=0, ordinal=0;
    for(int n=0;n<all.size();n++) { addresses.put(address,ordinal); if(!insertedIndices.contains(n)) ordinal++; address+=all.get(n).getCodeUnits(); }
    addresses.put(address,ordinal); var rows=new ArrayList<String>(); address=0;
    for(int n=0;n<all.size();n++) {
      var i=all.get(n); if(!insertedIndices.contains(n)) {
        String s=i.getOpcode().toString();
        if(i instanceof OneRegisterInstruction r) s+=" a="+r.getRegisterA();
        if(i instanceof TwoRegisterInstruction r) s+=" b="+r.getRegisterB();
        if(i instanceof ThreeRegisterInstruction r) s+=" c="+r.getRegisterC();
        if(i instanceof FiveRegisterInstruction r) s+=" invoke="+r.getRegisterCount()+","+r.getRegisterC()+","+r.getRegisterD()+","+r.getRegisterE()+","+r.getRegisterF()+","+r.getRegisterG();
        if(i instanceof RegisterRangeInstruction r) s+=" range="+r.getStartRegister()+","+r.getRegisterCount();
        if(i instanceof WideLiteralInstruction l) s+=" literal="+l.getWideLiteral();
        if(i instanceof ReferenceInstruction r) s+=" ref="+r.getReference();
        if(i instanceof OffsetInstruction o) { int targetAddress=address+o.getCodeOffset(); Integer target=addresses.get(targetAddress); if(!insertedIndices.isEmpty()) { int at=0; for(int k=0;k<all.size();k++) { if(at==targetAddress) check(!insertedIndices.contains(k) && !insertedIndices.contains(k-1),"branch bypasses insertion: "+desc(m)); at+=all.get(k).getCodeUnits(); } } check(target!=null,"branch destination not instruction: "+desc(m)); s+=" target="+target; }
        if(i instanceof SwitchPayload p) for(var x:p.getSwitchElements()) s+=" switch="+x.getKey()+","+x.getOffset();
        if(i instanceof ArrayPayload p) s+=" array="+p.getElementWidth()+":"+p.getArrayElements();
        rows.add(s);
      } address+=i.getCodeUnits();
    }
    return rows;
  }
  static List<String> handlers(Method m) { var rows=new ArrayList<String>(); for(var t:m.getImplementation().getTryBlocks()) { String s=t.getStartCodeAddress()+":"+t.getCodeUnitCount(); for(var h:t.getExceptionHandlers()) s+=" "+h.getExceptionType()+":"+h.getHandlerCodeAddress(); rows.add(s); } return rows; }
  static void originalShapes(Map<String,Method> m) {
    shape(m.get(ORD),65537,13,13,1,0,15,27); shape(m.get(SYN),69633,18,15,3,0,39,71); shape(m.get(TARGET),17,3,1,1,0,26,49);
    var s=normalizedBody(m.get(SYN),Set.of());
    check(s.get(0).equals("AND_INT_LIT8 a=0 b=4 literal=63") && s.get(2).equals("CONST_16 a=2 literal=63") && s.get(3).equals("IF_NE a=2 b=0 target=34") && s.get(38).equals("THROW a=1"),"required-field validation");
    check(s.get(23).equals("AND_INT_LIT16 a=4 b=4 literal=256") && s.get(24).equals("IF_NEZ a=4 target=31") && s.get(25).equals("IF_NE a=5 b=6 target=28"),"synthetic fullness logic");
    check(normalizedBody(m.get(ORD),Set.of()).get(9).equals("IF_NE a=1 b=2 target=12"),"ordinary fullness logic");
  }
  static void preflight(Path xapk,Path originalDir) throws Exception {
    check(sha(xapk).equals("88ffdaa3156e996bf32e94a3529ad91af16834c666dd739aa25a69b6a1cb6f36"),"archive hash");
    check(inventory(originalDir).equals(HASHES.keySet()),"original APK inventory");
    try(var z=new ZipFile(xapk.toFile())) { var e=entries(z); check(e.keySet().equals(Set.of("com.duolingo.apk","config.arm64_v8a.apk","config.xxxhdpi.apk","manifest.json","icon.png")),"archive inventory");
      for(var n:HASHES.keySet()) { Path p=originalDir.resolve(n); check(sha(p).equals(HASHES.get(n)),"component hash "+n); try(var in=z.getInputStream(e.get(n))) { check(hex(MessageDigest.getInstance("SHA-256").digest(in.readAllBytes())).equals(HASHES.get(n)),"archived component "+n); } signature(p,null,ORIGINAL_CERT); }
    }
    originalShapes(scan(originalDir.resolve("com.duolingo.apk"))); System.out.println("PASS preflight: pinned archive, components, signatures, target shapes and callers");
  }
  static void verifyRaw(Path originalBase, Path patchedBase) throws Exception {
    var before=scan(originalBase); var after=scan(patchedBase); originalShapes(before);
    shape(after.get(ORD),65537,13,13,1,0,16,29); shape(after.get(SYN),69633,18,15,3,0,41,75); shape(after.get(TARGET),17,3,1,0,0,2,2);
    var o=normalizedBody(after.get(ORD),Set.of()); var s=normalizedBody(after.get(SYN),Set.of());
    check(o.get(1).equals("CONST_16 a=1 literal=25"),"ordinary insertion");
    check(s.get(5).equals("CONST_16 a=5 literal=25") && s.get(6).equals("AND_INT_LIT16 a=4 b=4 literal=-257"),"synthetic insertions");
    check(normalizedBody(before.get(ORD),Set.of()).equals(normalizedBody(after.get(ORD),Set.of(1))),"ordinary branch/instruction mismatch");
    check(normalizedBody(before.get(SYN),Set.of()).equals(normalizedBody(after.get(SYN),Set.of(5,6))),"synthetic branch/instruction mismatch");
    check(normalizedBody(after.get(TARGET),Set.of()).equals(List.of("CONST_4 a=0 literal=0","RETURN a=0")),"readiness stub");
    check(before.keySet().equals(after.keySet()),"energy/caller method inventory");
    for(String d:before.keySet()) if(!Set.of(ORD,SYN,TARGET).contains(d)) { Method a=before.get(d), b=after.get(d); check(a.getAccessFlags()==b.getAccessFlags(),"flags changed "+d); if(a.getImplementation()==null || b.getImplementation()==null) { check(a.getImplementation()==null && b.getImplementation()==null,"implementation changed "+d); continue; } check(a.getImplementation().getRegisterCount()==b.getImplementation().getRegisterCount() && header(a,2)==header(b,2) && header(a,4)==header(b,4) && header(a,12)==header(b,12) && handlers(a).equals(handlers(b)) && normalizedBody(a,Set.of()).equals(normalizedBody(b,Set.of())),"untouched method changed: "+d); }
    System.out.println("PASS raw DEX shapes, integrity, insertions, branches, callers and energy methods");
  }
  static final String PROF="assets/dexopt/baseline.prof", META="assets/dexopt/baseline.profm", EMBED="assets/art-profile/baseline.prof";
  record DexView(DexBackedDexFile file,long crc32) {}
  record ProfileView(Set<String> classes,Map<String,Integer> methods) {}
  static class Cursor {
    byte[] b; int p;
    Cursor(byte[] b) { this.b=b; }
    byte[] take(int n) { check(n>=0 && n<=b.length-p,"profile truncated"); byte[] r=Arrays.copyOfRange(b,p,p+n); p+=n; return r; }
    int u8() { return take(1)[0]&255; }
    int u16() { return u8() | u8()<<8; }
    long u32() { return Integer.toUnsignedLong(u16() | u16()<<16); }
    int size() { long n=u32(); check(n<=16777216,"profile length limit"); return (int)n; }
    String str(int n) throws Exception { return java.nio.charset.StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(take(n))).toString(); }
    void end() { check(p==b.length,"profile trailing data"); }
    void magic(String m) throws Exception { check(Arrays.equals(take(8),m.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)),"profile magic/version"); }
  }
  static byte[] inflateExact(byte[] compressed,int expectedSize) throws Exception {
    check(expectedSize>=0 && expectedSize<=16777216,"profile inflation limit"); var z=new Inflater(); z.setInput(compressed); byte[] out=new byte[expectedSize]; int n=0;
    try { while(!z.finished() && n<out.length) { int k=z.inflate(out,n,out.length-n); if(k==0) break; n+=k; } if(n==out.length && !z.finished()) { byte[] extra=new byte[1]; check(z.inflate(extra)==0,"profile inflated size"); } check(z.finished() && n==out.length && z.getRemaining()==0,"profile compressed length"); return out; } finally { z.end(); }
  }
  static byte[] profileEntry(ZipFile z,String n) throws Exception { var e=entries(z).get(n); check(e!=null && e.getSize()>=0 && e.getSize()<=16777216,"missing/oversized profile "+n); return z.getInputStream(e).readAllBytes(); }
  static Map<String,DexView> profileDexes(ZipFile apk) throws Exception {
    var out=new HashMap<String,DexView>(); for(var e:entries(apk).values()) if(e.getName().matches("(?:.*/)?classes[0-9]*\\.dex")) { byte[] b=apk.getInputStream(e).readAllBytes(); dexIntegrity(b,e.getName()); if(!e.getName().contains("/")) { var crc=new CRC32(); crc.update(b); out.put(e.getName(),new DexView(new DexBackedDexFile(Opcodes.getDefault(),b),crc.getValue())); } } return out;
  }
  static DexView dex(Map<String,DexView> dexes,String key,long crc,long methods) {
    DexView d=dexes.get(key); check(d!=null,"profile DEX key: "+key); check(d.crc32()==crc,"profile DEX CRC32: "+key); check(d.file().getMethodSection().size()==methods,"profile method count: "+key); return d;
  }
  static int[] ascending(Cursor c,int count,int max) { int[] a=new int[count]; int last=0; for(int i=0;i<count;i++) { int delta=c.u16(); check(i==0 || delta>0,"profile duplicate index"); last+=delta; check(last<max,"profile index out of range"); a[i]=last; } return a; }
  static Set<String> types(DexView d,int[] indices) { var s=new HashSet<String>(); for(int i:indices) check(s.add(d.file().getTypeSection().get(i)),"duplicate profile class"); return s; }
  static void hot(Cursor c,int length,int max,Map<Integer,Integer> flags) { Cursor h=new Cursor(c.take(length)); int last=0, n=0; while(h.p<h.b.length) { int delta=h.u16(); check(n++==0 || delta>0,"duplicate hot method"); last+=delta; check(last<max,"hot method index"); check(h.u16()==0,"nonzero inline cache"); flags.merge(last,1,(a,b)->a|b); } h.end(); }
  static void bitmap(Cursor c,int count,int[] bits,Map<Integer,Integer> flags) { int total=Math.multiplyExact(count,bits.length); byte[] b=c.take((total+7)/8); if(total%8!=0) check(((b[b.length-1]&255) >>> (total%8))==0,"nonzero bitmap padding"); for(int n=0;n<total;n++) if((b[n/8] & (1<<(n%8)))!=0) flags.merge(n%count,bits[n/count],(a,x)->a|x); }
  static Map<String,Integer> methodNames(DexView d,Map<Integer,Integer> values) { var out=new HashMap<String,Integer>(); for(var e:values.entrySet()) check(out.put(desc(d.file().getMethodSection().get(e.getKey())),e.getValue())==null,"duplicate method identity"); return out; }
  record AssetHeader(String name,int classes,int hot,long crc,int methods) {}
  static Map<String,ProfileView> readAssetProfiles(ZipFile apk,Map<String,DexView> dexes) throws Exception {
    Cursor p=new Cursor(profileEntry(apk,PROF)); p.magic("pro\0"+"010\0"); int count=p.u8(), len=p.size(), compressed=p.size(); Cursor b=new Cursor(inflateExact(p.take(compressed),len)); p.end(); var headers=new ArrayList<AssetHeader>(); var names=new HashSet<String>();
    for(int i=0;i<count;i++) { int kl=b.u16(), cl=b.u16(), hot=b.size(); long crc=b.u32(); int methods=b.size(); String name=b.str(kl); check(names.add(name),"duplicate asset DEX key"); dex(dexes,name,crc,methods); headers.add(new AssetHeader(name,cl,hot,crc,methods)); }
    var out=new LinkedHashMap<String,ProfileView>(); for(var h:headers) { DexView d=dexes.get(h.name()); var flags=new HashMap<Integer,Integer>(); hot(b,h.hot(),h.methods(),flags); int[] cl=ascending(b,h.classes(),d.file().getTypeSection().size()); bitmap(b,h.methods(),new int[]{2,4},flags); out.put(h.name(),new ProfileView(types(d,cl),methodNames(d,flags))); } b.end();
    Cursor m=new Cursor(profileEntry(apk,META)); m.magic("prm\0"+"002\0"); check(m.u16()==count,"metadata DEX count"); len=m.size(); compressed=m.size(); Cursor q=new Cursor(inflateExact(m.take(compressed),len)); m.end(); var seen=new HashSet<Integer>();
    for(int i=0;i<count;i++) { int index=q.u16(); check(index<count && seen.add(index),"metadata record index"); String key=q.str(q.u16()); var h=headers.get(index); check(key.equals(h.name()),"metadata key"); DexView d=dexes.get(key); check(q.u32()==d.file().getTypeSection().size(),"metadata type count"); int[] defs=ascending(q,q.u16(),d.file().getClassSection().size()); var mapped=new HashSet<String>(); for(int def:defs) check(mapped.add(d.file().getClassSection().get(def).getType()),"metadata duplicate class"); check(mapped.equals(out.get(key).classes()),"metadata class mapping: "+key); } q.end(); return out;
  }
  record Section(int kind,int offset,int stored,int inflated) {}
  static Map<Integer,byte[]> sections(byte[] file) throws Exception {
    Cursor c=new Cursor(file); c.magic("pro\0"+"015\0"); check(c.u32()==3,"profile section count"); var list=new ArrayList<Section>(); var kinds=new HashSet<Integer>();
    for(int i=0;i<3;i++) { int kind=c.size(), off=c.size(), size=c.size(), expanded=c.size(); check(Set.of(0,2,3).contains(kind) && kinds.add(kind),"profile section kind"); list.add(new Section(kind,off,size,expanded)); }
    list.sort(Comparator.comparingInt(Section::offset)); int end=c.p; var out=new HashMap<Integer,byte[]>(); for(var s:list) { check(s.offset()==end && s.stored()<=file.length-end,"profile section bounds"); check(s.kind()==0 ? s.inflated()==0 : s.inflated()>0,"profile section compression"); byte[] data=Arrays.copyOfRange(file,end,end+s.stored()); end+=s.stored(); out.put(s.kind(),s.inflated()==0?data:inflateExact(data,s.inflated())); } check(end==file.length,"profile section trailing data"); return out;
  }
  static Map<String,ProfileView> readEmbeddedProfile(ZipFile apk,Map<String,DexView> dexes) throws Exception {
    var sec=sections(profileEntry(apk,EMBED)); Cursor d=new Cursor(sec.get(0)); int count=d.u16(); var names=new ArrayList<String>(); var views=new ArrayList<DexView>(); var counts=new ArrayList<Integer>(); var unique=new HashSet<String>();
    for(int i=0;i<count;i++) { long crc=d.u32(), typeCount=d.u32(), methodCount=d.u32(); String key=d.str(d.u16()); check(key.equals("base.apk") || key.matches("base\\.apk!classes(?:[2-9]|[1-9][0-9]+)\\.dex"),"installed DEX key: "+key); String name=key.equals("base.apk")?"classes.dex":key.substring(9); check(unique.add(name),"duplicate installed DEX key"); DexView v=dex(dexes,name,crc,methodCount); check(typeCount==v.file().getTypeSection().size(),"embedded type count"); names.add(name); views.add(v); counts.add((int)methodCount); } d.end();
    var classes=new HashMap<Integer,Set<String>>(); Cursor c=new Cursor(sec.get(2)); while(c.p<c.b.length) { int i=c.u16(); check(i<count && !classes.containsKey(i),"embedded class record index"); classes.put(i,types(views.get(i),ascending(c,c.u16(),views.get(i).file().getTypeSection().size()))); } check(classes.size()==count,"embedded class records");
    var methods=new HashMap<Integer,Map<String,Integer>>(); Cursor m=new Cursor(sec.get(3)); while(m.p<m.b.length) { int i=m.u16(), size=m.size(); check(i<count && !methods.containsKey(i),"embedded method record index"); Cursor record=new Cursor(m.take(size)); int all=record.u16(); check((all & ~7)==0,"unsupported profile flags"); var flags=new HashMap<Integer,Integer>(); int[] planes=(all&6)==6?new int[]{2,4}:(all&2)!=0?new int[]{2}:(all&4)!=0?new int[]{4}:new int[0]; bitmap(record,counts.get(i),planes,flags); if((all&1)!=0) hot(record,record.b.length-record.p,counts.get(i),flags); record.end(); int union=0; for(int v:flags.values()) union|=v; check(union==all,"embedded flags union"); methods.put(i,methodNames(views.get(i),flags)); } check(methods.size()==count,"embedded method records");
    var out=new HashMap<String,ProfileView>(); for(int i=0;i<count;i++) out.put(names.get(i),new ProfileView(classes.get(i),methods.get(i))); return out;
  }
  static void sameProfiles(Map<String,ProfileView> expected,Map<String,ProfileView> actual,String label) {
    check(expected.keySet().equals(actual.keySet()),label+" DEX membership mismatch");
    for(String key:expected.keySet()) { var a=expected.get(key); var b=actual.get(key); check(a.classes().equals(b.classes()),label+" class identity mismatch: "+key); check(a.methods().keySet().equals(b.methods().keySet()),label+" method identity mismatch: "+key); check(a.methods().equals(b.methods()),label+" method flags mismatch: "+key); }
  }
  static void verifyProfiles(Path originalBase,Path patchedBase) throws Exception {
    check(sha(originalBase).equals(HASHES.get("com.duolingo.apk")),"original base hash"); try(var a=new ZipFile(originalBase.toFile()); var b=new ZipFile(patchedBase.toFile())) {
      var x=readAssetProfiles(a,profileDexes(a)); var dexes=profileDexes(b); var y=readAssetProfiles(b,dexes); var z=readEmbeddedProfile(b,dexes);
      sameProfiles(x,y,"asset profile"); sameProfiles(x,z,"embedded profile"); int methods=x.values().stream().mapToInt(v->v.methods().size()).sum(); check(x.size()==9 && methods==66340,"profile expected membership/count"); System.out.println("PASS profiles: 9 DEX, 66340 method identities/flags; original, assets and embedded equal");
    }
  }

  static void verifyOutput(Path originalDir,Path patchedDir,Path expectedCert) throws Exception {
    check(inventory(originalDir).equals(HASHES.keySet()) && inventory(patchedDir).equals(HASHES.keySet()),"output APK inventory"); byte[] cert=Files.readAllBytes(expectedCert);
    for(String n:HASHES.keySet()) signature(patchedDir.resolve(n),cert,null);
    verifyRaw(originalDir.resolve("com.duolingo.apk"),patchedDir.resolve("com.duolingo.apk"));
    verifyProfiles(originalDir.resolve("com.duolingo.apk"),patchedDir.resolve("com.duolingo.apk"));
    for(String n:HASHES.keySet()) { try(var a=new ZipFile(originalDir.resolve(n).toFile()); var b=new ZipFile(patchedDir.resolve(n).toFile())) {
      var ae=entries(a); var be=entries(b); var ak=new HashSet<>(ae.keySet()); var bk=new HashSet<>(be.keySet()); ak.removeIf(Verify61045::signing); bk.removeIf(Verify61045::signing); ak.removeIf(x->ae.get(x).isDirectory()); bk.removeIf(x->be.get(x).isDirectory()); if(n.equals("com.duolingo.apk")) { check(!ak.contains(EMBED) && bk.contains(EMBED),"embedded profile inventory"); ak.add(EMBED); } check(ak.equals(bk),"ZIP inventory changed: "+n);
      for(String e:ak) if(!(n.equals("com.duolingo.apk") && (e.equals("classes.dex") || e.equals("classes5.dex") || e.equals(PROF) || e.equals(META) || e.equals(EMBED)))) { try(var ai=a.getInputStream(ae.get(e)); var bi=b.getInputStream(be.get(e))) { check(Arrays.equals(digest("SHA-256",ai.readAllBytes()),digest("SHA-256",bi.readAllBytes())),"payload changed: "+n+" "+e); } }
    }}
    System.out.println("PASS output signatures, complete inventory and unchanged non-target payloads");
  }
  static void put32(byte[] b,int at,int value) { for(int i=0;i<4;i++) b[at+i]=(byte)(value >>> (8*i)); }
  static int int32(byte[] b,int at) { return (b[at]&255) | (b[at+1]&255)<<8 | (b[at+2]&255)<<16 | b[at+3]<<24; }
  static byte[] deflate(byte[] b) throws Exception { var out=new ByteArrayOutputStream(); try(var z=new DeflaterOutputStream(out)) { z.write(b); } return out.toByteArray(); }
  static byte[] assetFile(byte[] original,byte[] body) throws Exception { byte[] zipped=deflate(body); byte[] out=Arrays.copyOf(original,18+zipped.length); put32(out,10,body.length); put32(out,14,zipped.length); System.arraycopy(zipped,0,out,18,zipped.length); return out; }
  static byte[] embeddedFile(Map<Integer,byte[]> parts) throws Exception {
    var out=new ByteArrayOutputStream(); out.write(new byte[]{'p','r','o',0,'0','1','5',0,3,0,0,0}); var payload=new ByteArrayOutputStream(); int offset=60;
    for(int kind:new int[]{0,2,3}) { byte[] raw=parts.get(kind), stored=kind==0?raw:deflate(raw); byte[] h=new byte[16]; put32(h,0,kind); put32(h,4,offset); put32(h,8,stored.length); put32(h,12,kind==0?0:raw.length); out.write(h); payload.write(stored); offset+=stored.length; } out.write(payload.toByteArray()); return out.toByteArray();
  }
  static boolean bit(byte[] b,int start,int n) { return (b[start+n/8] & (1<<(n%8)))!=0; }
  static void flip(byte[] b,int start,int n) { b[start+n/8]^=(byte)(1<<(n%8)); }
  static Map.Entry<String,byte[]> profileMutation(ZipFile apk,String kind) throws Exception {
    var dexes=profileDexes(apk); readAssetProfiles(apk,dexes); readEmbeddedProfile(apk,dexes);
    if(kind.equals("profile-mapping")) {
      byte[] original=profileEntry(apk,META); Cursor f=new Cursor(original); f.magic("prm\0"+"002\0"); int count=f.u16(), size=f.size(), compressed=f.size(); byte[] raw=inflateExact(f.take(compressed),size); f.end(); Cursor c=new Cursor(raw); boolean changed=false;
      for(int i=0;i<count;i++) { c.u16(); c.str(c.u16()); c.u32(); int n=c.u16(); for(int j=0;j<n;j++) { int pos=c.p, delta=c.u16(); if(!changed && j>0 && delta>1 && j+1<n) { int next=(raw[c.p]&255)|((raw[c.p+1]&255)<<8); if(next<65535) { raw[pos]=(byte)(delta-1); raw[pos+1]=(byte)((delta-1)>>>8); raw[c.p]=(byte)(next+1); raw[c.p+1]=(byte)((next+1)>>>8); changed=true; } } } } c.end(); check(changed,"mapping mutation unavailable"); return Map.entry(META,assetFile(original,raw));
    }
    byte[] original=profileEntry(apk,EMBED); if(kind.equals("profile-container")) { byte[] b=original.clone(); put32(b,16,61); return Map.entry(EMBED,b); }
    var parts=sections(original); byte[] header=parts.get(0); Cursor d=new Cursor(header); int count=d.u16(); var counts=new int[count];
    if(kind.equals("profile-checksum")) { header[2]^=1; return Map.entry(EMBED,embeddedFile(parts)); }
    if(kind.equals("profile-key")) { int keyLen=(header[14]&255)|((header[15]&255)<<8); check(keyLen>0 && header[16]=='b',"key mutation original bytes"); header[16]='x'; return Map.entry(EMBED,embeddedFile(parts)); }
    for(int i=0;i<count;i++) { d.u32(); d.u32(); counts[i]=(int)d.u32(); d.str(d.u16()); } d.end();
    check(kind.equals("profile-identity") || kind.equals("profile-flags"),"unknown profile mutation"); byte[] raw=parts.get(3); Cursor m=new Cursor(raw); boolean changed=false;
    while(m.p<raw.length) { int i=m.u16(), len=m.size(), start=m.p; Cursor r=new Cursor(m.take(len)); int all=r.u16(); int planes=Integer.bitCount(all&6), n=counts[i], bits=n*planes, bitmapStart=start+2; r.take((bits+7)/8); var hotFlags=new HashMap<Integer,Integer>(); if((all&1)!=0) hot(r,r.b.length-r.p,n,hotFlags); r.end(); if(changed || (all&2)==0) continue;
      if(kind.equals("profile-flags")) { for(int k=0;k<n;k++) if(hotFlags.containsKey(k) && !bit(raw,bitmapStart,k)) { flip(raw,bitmapStart,k); changed=true; break; } }
      else { int from=-1,to=-1; for(int k=0;k<n;k++) { boolean startup=bit(raw,bitmapStart,k); boolean post=(all&4)!=0 && bit(raw,bitmapStart,n+k); boolean h=hotFlags.containsKey(k); if(startup && !post && !h && from<0) from=k; if(!startup && !post && !h && to<0) to=k; if(from>=0 && to>=0) break; } if(from>=0 && to>=0) { flip(raw,bitmapStart,from); flip(raw,bitmapStart,to); changed=true; } }
    }
    check(changed,"profile mutation unavailable: "+kind); return Map.entry(EMBED,embeddedFile(parts));
  }

  static void mutate(Path inputApk,String kind,Path outputApk) throws Exception {
    check(!Files.exists(outputApk),"mutation output exists"); check(!inputApk.toAbsolutePath().normalize().equals(outputApk.toAbsolutePath().normalize()),"mutation input equals output");
    if(kind.startsWith("profile-")) {
      Map.Entry<String,byte[]> mutation; try(var in=new ZipFile(inputApk.toFile())) { mutation=profileMutation(in,kind); }
      var created=Files.newOutputStream(outputApk,StandardOpenOption.CREATE_NEW);
      try(var out=new ZipOutputStream(created); var in=new ZipFile(inputApk.toFile())) { for(var e:Collections.list(in.entries())) { byte[] b=e.getName().equals(mutation.getKey())?mutation.getValue():in.getInputStream(e).readAllBytes(); out.putNextEntry(new ZipEntry(e.getName())); out.write(b); out.closeEntry(); } } catch(Exception | AssertionError ex) { Files.deleteIfExists(outputApk); throw ex; }
      System.out.println("PASS created mutation "+kind+": "+outputApk); return;
    }
    var methods=scan(inputApk); Method m; String dex; int pos; byte[] old, replacement;
    switch(kind) {
      case "energy-mask" -> { m=methods.get(SYN); dex="classes.dex"; pos=start(m)+2; old=new byte[]{4,63}; replacement=new byte[]{4,62}; }
      case "interstitial-registers" -> { m=methods.get(TARGET); dex="classes5.dex"; pos=start(m)-16; old=new byte[]{3,0}; replacement=new byte[]{4,0}; }
      case "energy-branch" -> { m=methods.get(ORD); dex="classes.dex"; var i=(DexBackedInstruction)ins(m).get(10); pos=i.instructionStart+2; old=new byte[]{4,0}; replacement=new byte[]{5,0}; }
      default -> throw new IllegalArgumentException("unknown mutation: "+kind);
    }
    var created=Files.newOutputStream(outputApk,StandardOpenOption.CREATE_NEW);
    try(var out=new ZipOutputStream(created); var in=new ZipFile(inputApk.toFile())) {
      for(var e:Collections.list(in.entries())) { byte[] b=in.getInputStream(e).readAllBytes(); if(e.getName().equals(dex)) { check(Arrays.equals(Arrays.copyOfRange(b,pos,pos+old.length),old),"mutation original bytes mismatch"); System.arraycopy(replacement,0,b,pos,replacement.length); System.arraycopy(digest("SHA-1",Arrays.copyOfRange(b,32,b.length)),0,b,12,20); var ad=new Adler32(); ad.update(b,12,b.length-12); for(int n=0;n<4;n++) b[8+n]=(byte)(ad.getValue() >>> (8*n)); }
        out.putNextEntry(new ZipEntry(e.getName())); out.write(b); out.closeEntry(); }
    } catch(Exception | AssertionError ex) { Files.deleteIfExists(outputApk); throw ex; }
    System.out.println("PASS created mutation "+kind+": "+outputApk);
  }
  public static void main(String[] args) throws Exception {
    if(args.length==3 && args[0].equals("preflight")) preflight(Path.of(args[1]),Path.of(args[2]));
    else if(args.length==3 && args[0].equals("profiles")) verifyProfiles(Path.of(args[1]),Path.of(args[2]));
    else if(args.length==3 && args[0].equals("raw")) verifyRaw(Path.of(args[1]),Path.of(args[2]));
    else if(args.length==4 && args[0].equals("output")) verifyOutput(Path.of(args[1]),Path.of(args[2]),Path.of(args[3]));
    else if(args.length==4 && args[0].equals("mutate")) mutate(Path.of(args[1]),args[2],Path.of(args[3]));
    else throw new IllegalArgumentException("usage: preflight XAPK DIR | profiles ORIGINAL PATCHED | raw ORIGINAL PATCHED | output ORIGINAL_DIR PATCHED_DIR CERT | mutate INPUT KIND OUTPUT");
  }
}
