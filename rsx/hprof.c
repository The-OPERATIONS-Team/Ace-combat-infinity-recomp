#include "hprof.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#pragma comment(lib, "dbghelp")
#pragma comment(lib, "user32")

enum {
    HP_MAXTHR = 96,
    HP_DEPTH  = 48,
    HP_STAGE  = 65536,
    HP_FNCAP  = 1 << 17,
    HP_PCCAP  = 1 << 18,
    HP_STKCAP = 1 << 15,
    HP_STKD   = 14,
    HP_MAXMOD = 512,
    HP_NWAIT  = 32,
};

typedef struct { uintptr_t base, end; const RUNTIME_FUNCTION* rf; DWORD nrf; int is_main; char name[48]; } HMod;
static HMod g_mod[HP_MAXMOD]; static int g_nmod; static int g_mod_dirty;
static uintptr_t g_main_base;

static int mod_cmp(const void* a, const void* b){
    uintptr_t x=((const HMod*)a)->base, y=((const HMod*)b)->base; return x<y?-1:x>y?1:0;
}
static void mods_refresh(void){
    HMODULE hm[HP_MAXMOD]; DWORD need=0;
    if(!K32EnumProcessModules(GetCurrentProcess(),hm,sizeof hm,&need)) return;
    int n=(int)(need/sizeof(HMODULE)); if(n>HP_MAXMOD) n=HP_MAXMOD;
    HMod tmp[HP_MAXMOD]; int k=0;
    for(int i=0;i<n;i++){
        MODULEINFO mi;
        if(!K32GetModuleInformation(GetCurrentProcess(),hm[i],&mi,sizeof mi)) continue;
        uintptr_t base=(uintptr_t)mi.lpBaseOfDll;
        const IMAGE_DOS_HEADER* dos=(const IMAGE_DOS_HEADER*)base;
        if(dos->e_magic!=IMAGE_DOS_SIGNATURE) continue;
        const IMAGE_NT_HEADERS64* nt=(const IMAGE_NT_HEADERS64*)(base+dos->e_lfanew);
        if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC) continue;
        const IMAGE_DATA_DIRECTORY* dd=&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        HMod* m=&tmp[k++];
        m->base=base; m->end=base+mi.SizeOfImage;
        m->rf=dd->Size?(const RUNTIME_FUNCTION*)(base+dd->VirtualAddress):0;
        m->nrf=dd->Size/sizeof(RUNTIME_FUNCTION);
        m->is_main=(base==g_main_base);
        if(!K32GetModuleBaseNameA(GetCurrentProcess(),hm[i],m->name,sizeof m->name))
            snprintf(m->name,sizeof m->name,"%p",(void*)base);
    }
    qsort(tmp,(size_t)k,sizeof(HMod),mod_cmp);
    memcpy(g_mod,tmp,(size_t)k*sizeof(HMod)); g_nmod=k; g_mod_dirty=0;
}
static HMod* mod_find(uintptr_t pc){
    int lo=0, hi=g_nmod-1;
    while(lo<=hi){ int mid=(lo+hi)>>1; HMod* m=&g_mod[mid];
        if(pc<m->base) hi=mid-1; else if(pc>=m->end) lo=mid+1; else return m; }
    return 0;
}
static const RUNTIME_FUNCTION* rf_find(const HMod* m, DWORD rva){
    if(!m->rf) return 0;
    int lo=0, hi=(int)m->nrf-1;
    while(lo<=hi){ int mid=(lo+hi)>>1; const RUNTIME_FUNCTION* r=&m->rf[mid];
        if(rva<r->BeginAddress) hi=mid-1; else if(rva>=r->EndAddress) lo=mid+1; else return r; }
    return 0;
}
static uintptr_t fn_start(uintptr_t pc){
    const HMod* m=mod_find(pc); if(!m) return pc;
    const RUNTIME_FUNCTION* r=rf_find(m,(DWORD)(pc-m->base));
    return r ? m->base+r->BeginAddress : pc;
}

static int unwind(CONTEXT* c, uintptr_t lo, uintptr_t hi, uintptr_t* out, int max){
    int d=0;
    __try {
        while(d<max){
            uintptr_t pc=(uintptr_t)c->Rip; if(!pc) break;
            out[d++]=pc;
            uintptr_t look = d==1 ? pc : pc-1;
            HMod* m=mod_find(look);
            if(!m){ g_mod_dirty=1; break; }
            if(c->Rsp<lo || c->Rsp+8>hi) break;
            const RUNTIME_FUNCTION* r=rf_find(m,(DWORD)(look-m->base));
            if(!r){ c->Rip=*(const DWORD64*)(uintptr_t)c->Rsp; c->Rsp+=8; }
            else { PVOID hd; DWORD64 ef;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER,(DWORD64)m->base,(DWORD64)pc,(PRUNTIME_FUNCTION)r,c,&hd,&ef,NULL); }
            if(c->Rsp<lo || c->Rsp>=hi) break;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { }
    return d;
}

static uintptr_t g_wait_pc[HP_NWAIT]; static int g_nwait;
static void waits_init(void){
    static const char* const nt[]={ "NtWaitForSingleObject","NtWaitForMultipleObjects",
        "NtWaitForAlertByThreadId","NtDelayExecution","NtYieldExecution","NtRemoveIoCompletion",
        "NtRemoveIoCompletionEx","NtSignalAndWaitForSingleObject","NtWaitForKeyedEvent",
        "NtWaitForWorkViaWorkerFactory","NtReplyWaitReceivePort","NtWaitForDebugEvent",
        "NtAlpcSendWaitReceivePort","NtWaitForMultipleObjects32" };
    static const char* const wu[]={ "NtUserMsgWaitForMultipleObjectsEx","NtUserGetMessage","NtUserWaitMessage" };
    HMODULE n=GetModuleHandleA("ntdll.dll"), w=LoadLibraryA("win32u.dll");
    for(size_t i=0;i<sizeof nt/sizeof nt[0]&&g_nwait<HP_NWAIT;i++){
        FARPROC p=n?GetProcAddress(n,nt[i]):0; if(p) g_wait_pc[g_nwait++]=(uintptr_t)p; }
    for(size_t i=0;i<sizeof wu/sizeof wu[0]&&g_nwait<HP_NWAIT;i++){
        FARPROC p=w?GetProcAddress(w,wu[i]):0; if(p) g_wait_pc[g_nwait++]=(uintptr_t)p; }
}
static int is_wait(uintptr_t pc){
    for(int i=0;i<g_nwait;i++) if(pc-g_wait_pc[i]<64) return 1;
    return 0;
}

typedef struct { LONG ExitStatus; PVOID TebBaseAddress; PVOID UniqueProcess, UniqueThread;
                 ULONG_PTR AffinityMask; LONG Priority, BasePriority; } HP_TBI;
typedef LONG (NTAPI *NtQIT_t)(HANDLE, int, PVOID, ULONG, PULONG);
static NtQIT_t g_ntqit;

typedef struct {
    DWORD tid; HANDLE h; const NT_TIB* tib; int alive;
    char label[24];
    uint64_t b, bl, w, wl;
} HThr;
static HThr g_thr[HP_MAXTHR]; static int g_nthr;
static HprofLabeler g_labeler;
static int g_all_threads;

static void threads_refresh(void){
    for(int i=0;i<g_nthr;i++)
        if(g_thr[i].alive && WaitForSingleObject(g_thr[i].h,0)==WAIT_OBJECT_0){
            g_thr[i].alive=0; CloseHandle(g_thr[i].h); g_thr[i].h=0; }
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    if(snap==INVALID_HANDLE_VALUE) return;
    DWORD pid=GetCurrentProcessId(), self=GetCurrentThreadId();
    THREADENTRY32 te; te.dwSize=sizeof te;
    if(Thread32First(snap,&te)) do {
        if(te.th32OwnerProcessID!=pid || te.th32ThreadID==self) continue;
        int known=0;
        for(int i=0;i<g_nthr;i++) if(g_thr[i].tid==te.th32ThreadID && g_thr[i].alive){ known=1; break; }
        if(known || g_nthr>=HP_MAXTHR) continue;
        char lb[24]=""; int want=g_labeler?g_labeler(te.th32ThreadID,lb,sizeof lb):0;
        if(!want){ if(!g_all_threads) continue; snprintf(lb,sizeof lb,"h%lu",(unsigned long)te.th32ThreadID); }
        HANDLE h=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,te.th32ThreadID);
        if(!h) continue;
        HP_TBI tbi; memset(&tbi,0,sizeof tbi);
        if(!g_ntqit || g_ntqit(h,0 ,&tbi,sizeof tbi,NULL)!=0 || !tbi.TebBaseAddress){
            CloseHandle(h); continue; }
        HThr* t=&g_thr[g_nthr++]; memset(t,0,sizeof *t);
        t->tid=te.th32ThreadID; t->h=h; t->tib=(const NT_TIB*)tbi.TebBaseAddress; t->alive=1;
        snprintf(t->label,sizeof t->label,"%s",lb);
    } while(Thread32Next(snap,&te));
    CloseHandle(snap);
}

typedef struct { uint8_t thr, depth; uint8_t wait, pad; uintptr_t pc[HP_DEPTH]; } HSample;
static HSample* g_stage; static int g_nstage; static long long g_stage_drop;

static void sample_all(void){
    for(int i=0;i<g_nthr;i++){
        HThr* t=&g_thr[i]; if(!t->alive) continue;
        if(g_nstage>=HP_STAGE){ g_stage_drop++; continue; }
        HSample* s=&g_stage[g_nstage];
        CONTEXT c; memset(&c,0,sizeof c); c.ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER;
        if(SuspendThread(t->h)==(DWORD)-1) continue;
        int d=0;
        if(GetThreadContext(t->h,&c)){
            uintptr_t lo=0, hi=0;
            __try { lo=(uintptr_t)t->tib->StackLimit; hi=(uintptr_t)t->tib->StackBase; }
            __except(EXCEPTION_EXECUTE_HANDLER) { lo=hi=0; }
            if(hi>lo) d=unwind(&c,lo,hi,s->pc,HP_DEPTH);
        }
        ResumeThread(t->h);
        if(d<=0) continue;
        s->thr=(uint8_t)i; s->depth=(uint8_t)d; s->wait=(uint8_t)is_wait(s->pc[0]);
        g_nstage++;
    }
}

typedef struct { uint64_t key; uint32_t b, bl, w, wl; } HCnt;
static HCnt* g_self;
static HCnt* g_incl;
static HCnt* g_wsite;
static HCnt* g_leaf;
static long long g_tab_drop;
#define HP_KEY(t,a) (((uint64_t)(t)<<56)|((uint64_t)(a)&0x00ffffffffffffffull))
#define HP_KTHR(k)  ((int)((k)>>56))
#define HP_KADDR(k) ((uintptr_t)((k)&0x00ffffffffffffffull))

static HCnt* cnt_get(HCnt* tab, uint32_t cap, uint64_t key){
    uint64_t h=key*0x9E3779B97F4A7C15ull;
    for(uint32_t i=0;i<cap;i++){
        HCnt* c=&tab[(uint32_t)((h>>32)+i)&(cap-1)];
        if(c->key==key) return c;
        if(!c->key){ c->key=key; return c; }
    }
    g_tab_drop++; return 0;
}
static void cnt_add(HCnt* c, int wait, int late){
    if(!c) return;
    if(wait){ c->w++; if(late) c->wl++; } else { c->b++; if(late) c->bl++; }
}

typedef struct { uint64_t hash; uint32_t b, bl, w, wl; uint8_t thr, depth; uintptr_t f[HP_STKD]; } HStk;
static HStk* g_stk;

static uint64_t g_frames, g_frames_late, g_rounds;
static LARGE_INTEGER g_win_t0;
static int g_partial, g_unfinished;

static void merge_stage(int late){
    for(int i=0;i<g_nstage;i++){
        HSample* s=&g_stage[i];
        HThr* t=&g_thr[s->thr];
        if(s->wait){ t->w++; if(late) t->wl++; } else { t->b++; if(late) t->bl++; }
        uintptr_t fs[HP_DEPTH];
        for(int d=0;d<s->depth;d++) fs[d]=fn_start(s->pc[d]);
        cnt_add(cnt_get(g_self,HP_FNCAP,HP_KEY(s->thr,fs[0])),s->wait,late);
        if(!s->wait) cnt_add(cnt_get(g_leaf,HP_PCCAP,HP_KEY(s->thr,s->pc[0])),0,late);
        for(int d=0;d<s->depth;d++){
            int dup=0; for(int e=0;e<d;e++) if(fs[e]==fs[d]){ dup=1; break; }
            if(!dup) cnt_add(cnt_get(g_incl,HP_FNCAP,HP_KEY(s->thr,fs[d])),s->wait,late);
        }
        if(s->wait){
            for(int d=0;d<s->depth;d++){ const HMod* m=mod_find(s->pc[d]);
                if(m && m->is_main){ cnt_add(cnt_get(g_wsite,HP_FNCAP,HP_KEY(s->thr,fs[d])),1,late); break; } }
        }
        int sd=s->depth<HP_STKD?s->depth:HP_STKD;
        uint64_t h=0xcbf29ce484222325ull^s->thr;
        for(int d=0;d<sd;d++){ h^=fs[d]; h*=0x100000001b3ull; }
        h^=(uint64_t)s->wait<<63; if(!h) h=1;
        for(uint32_t k=0;k<HP_STKCAP;k++){
            HStk* e=&g_stk[(uint32_t)((h>>20)+k)&(HP_STKCAP-1)];
            if(!e->hash){ e->hash=h; e->thr=s->thr; e->depth=(uint8_t)sd; memcpy(e->f,fs,(size_t)sd*sizeof(uintptr_t)); }
            if(e->hash==h){ if(s->wait){ e->w++; if(late) e->wl++; } else { e->b++; if(late) e->bl++; } break; }
            if(k==HP_STKCAP-1) g_tab_drop++;
        }
    }
    g_nstage=0;
}

static void window_reset(void){
    memset(g_self,0,sizeof(HCnt)*HP_FNCAP); memset(g_incl,0,sizeof(HCnt)*HP_FNCAP);
    memset(g_wsite,0,sizeof(HCnt)*HP_FNCAP); memset(g_leaf,0,sizeof(HCnt)*HP_PCCAP);
    memset(g_stk,0,sizeof(HStk)*HP_STKCAP);
    int k=0;
    for(int i=0;i<g_nthr;i++) if(g_thr[i].alive){ HThr t=g_thr[i]; t.b=t.bl=t.w=t.wl=0; g_thr[k++]=t; }
    g_nthr=k;
    g_frames=g_frames_late=g_rounds=0; g_nstage=0; g_stage_drop=0; g_tab_drop=0;
    g_partial=g_unfinished=0;
    QueryPerformanceCounter(&g_win_t0);
}
static void window_finish(void){
    if(g_partial){ merge_stage(1); g_frames++; g_frames_late++; g_unfinished=1; }
    g_nstage=0;
}

static volatile LONG g_flips;
static volatile LONG g_flip_vb[256];
void hprof_frame(int vblanks){
    LONG n=g_flips+1;
    g_flip_vb[n&255]=vblanks;
    InterlockedExchange(&g_flips,n);
}

static HANDLE g_proc; static int g_sym_ok;
typedef struct { uintptr_t a; char* name; } HName;
static HName* g_names; static uint32_t g_nnames_cap=1u<<15;

static const char* sym_name(uintptr_t a){
    uint32_t h=(uint32_t)((a*0x9E3779B97F4A7C15ull)>>40);
    for(uint32_t i=0;i<g_nnames_cap;i++){
        HName* e=&g_names[(h+i)&(g_nnames_cap-1)];
        if(e->a==a) return e->name;
        if(!e->a){
            char buf[512]; buf[0]=0;
            const HMod* m=mod_find(a);
            char sbuf[sizeof(SYMBOL_INFO)+256]; SYMBOL_INFO* si=(SYMBOL_INFO*)sbuf;
            memset(sbuf,0,sizeof sbuf); si->SizeOfStruct=sizeof(SYMBOL_INFO); si->MaxNameLen=255;
            DWORD64 disp=0;
            if(g_sym_ok && SymFromAddr(g_proc,(DWORD64)a,&disp,si)){
                if(m && !m->is_main) snprintf(buf,sizeof buf,"%s!%s%s",m->name,si->Name,disp?"+":"");
                else snprintf(buf,sizeof buf,"%s%s",si->Name,disp?"+":"");
                if(disp){ size_t l=strlen(buf); snprintf(buf+l,sizeof buf-l,"0x%llx",(unsigned long long)disp); }
            } else if(m) snprintf(buf,sizeof buf,"%s+0x%llx",m->name,(unsigned long long)(a-m->base));
            else snprintf(buf,sizeof buf,"0x%llx",(unsigned long long)a);
            e->a=a; e->name=_strdup(buf);
            return e->name;
        }
    }
    return "?";
}

enum { HP_BACK = 15, HP_LW = 256 };
static void src_fetch(const char* path, uint32_t ln, char back[HP_BACK][HP_LW]){
    for(int k=0;k<HP_BACK;k++) back[k][0]=0;
    FILE* fp=ln?fopen(path,"rb"):0; if(!fp) return;
    static char ring[HP_BACK][HP_LW]; char buf[HP_LW];
    uint32_t n=1, got=0; int fresh=1;
    while(n<=ln && fgets(buf,sizeof buf,fp)){
        size_t l=strlen(buf);
        if(fresh){ const char* p=buf; while(*p==' '||*p=='\t') p++;
            char* o=ring[n%HP_BACK]; size_t i=0;
            while(p[i] && p[i]!='\n' && p[i]!='\r' && i+1<HP_LW){ o[i]=p[i]; i++; }
            o[i]=0; got=n; }
        fresh = l && buf[l-1]=='\n';
        if(fresh) n++;
    }
    fclose(fp);
    for(uint32_t k=0;k<HP_BACK && k<ln;k++)
        if(ln-k<=got) memcpy(back[k],ring[(ln-k)%HP_BACK],HP_LW);
}
static void guest_of(char back[HP_BACK][HP_LW], int spu, char* out, size_t cap){
    out[0]=0;
    for(int k=0;k<HP_BACK;k++){ const char* b=back[k];
        unsigned a; char mn[160];
        if(sscanf(b,"/* %8x %159[^*]",&a,mn)==2){
            size_t l=strlen(mn); while(l&&mn[l-1]==' ') mn[--l]=0;
            snprintf(out,cap,"guest 0x%x  %s",a,mn); return; }
        if(spu && !strncmp(b,"loc_",4)){ unsigned x;
            if(sscanf(b+4,"%x:",&x)==1){ snprintf(out,cap,"ls 0x%x",x); return; } }
    }
}

typedef struct { const HCnt* c; double v; } HRow;
static int row_cmp(const void* a, const void* b){
    double x=((const HRow*)a)->v, y=((const HRow*)b)->v; return x<y?1:x>y?-1:0;
}
typedef struct { uint64_t key, b, bl; uint32_t line; int thr, multi; uintptr_t pc; char file[MAX_PATH]; } HLine;
static int line_cmp(const void* a, const void* b){
    uint64_t x=((const HLine*)a)->b, y=((const HLine*)b)->b; return x<y?1:x>y?-1:0;
}

static double g_ms_per_sample, g_secs;
static int g_noflip;
static double pf_all(uint64_t n){
    double d = g_noflip ? g_secs : (double)g_frames; return d>0 ? n*g_ms_per_sample/d : 0; }
static double pf_late(uint64_t l){
    return !g_noflip && g_frames_late ? l*g_ms_per_sample/(double)g_frames_late : 0; }
static double pf_norm(uint64_t n, uint64_t l){
    if(g_noflip) return pf_all(n);
    uint64_t f=g_frames-g_frames_late; return f ? (double)(n-l)*g_ms_per_sample/(double)f : 0; }
static double pf_more(uint64_t n, uint64_t l){ return g_noflip ? 0 : pf_late(l)-pf_norm(n,l); }

static void write_report(const char* why){
    LARGE_INTEGER t1, fq; QueryPerformanceCounter(&t1); QueryPerformanceFrequency(&fq);
    double secs=(double)(t1.QuadPart-g_win_t0.QuadPart)/(double)fq.QuadPart;
    if(g_rounds==0) return;
    g_ms_per_sample = secs*1000.0/(double)g_rounds;
    g_secs = secs;
    g_noflip = g_frames==(uint64_t)g_unfinished;
    if(!g_sym_ok){
        SymSetOptions(SYMOPT_UNDNAME|SYMOPT_DEFERRED_LOADS|SYMOPT_LOAD_LINES|SYMOPT_FAIL_CRITICAL_ERRORS|SYMOPT_NO_PROMPTS);
        g_sym_ok=SymInitialize(g_proc,NULL,TRUE)?1:0;
        if(!g_sym_ok) fprintf(stderr,"[PROF] DbgHelp SymInitialize failed (%lu): addresses only\n",GetLastError());
    } else SymRefreshModuleList(g_proc);
    CreateDirectoryA("out",NULL);
    static int seq; SYSTEMTIME st; GetLocalTime(&st);
    char path[128]; snprintf(path,sizeof path,"out/prof_%03d_%02d%02d%02d.txt",++seq,st.wHour,st.wMinute,st.wSecond);
    FILE* f=fopen(path,"wb"); if(!f){ fprintf(stderr,"[PROF] cannot write %s\n",path); return; }

    FILETIME a,b,ck,cu; double sampler_cpu=0;
    if(GetThreadTimes(GetCurrentThread(),&a,&b,&ck,&cu)){
        static double last;
        double now=((double)(((uint64_t)ck.dwHighDateTime<<32)|ck.dwLowDateTime)+
                    (double)(((uint64_t)cu.dwHighDateTime<<32)|cu.dwLowDateTime))/1e7;
        sampler_cpu=now-last; last=now; }

    uint64_t fn=g_frames-g_frames_late;
    fprintf(f,"PS3 host profiler (PS3_PROF) - %s\n",why);
    fprintf(f,"window %.1f s, %llu sampling rounds (%.0f Hz achieved), %d threads\n",
            secs,(unsigned long long)g_rounds,(double)g_rounds/secs,g_nthr);
    if(g_noflip)
        fprintf(f,"no flip in this window: figures are ms per second of wall time\n");
    else
        fprintf(f,"frames %llu: %llu on time, %llu LATE (3+ vblanks, %.1f%%)%s\n",
            (unsigned long long)g_frames,(unsigned long long)fn,(unsigned long long)g_frames_late,
            g_frames?100.0*g_frames_late/g_frames:0,
            g_unfinished?" - one of them unfinished, still going at the end of the window":"");
    fprintf(f,"sampler cost %.1f%% of one core; dropped: %lld staged, %lld table\n\n",
            secs>0?100.0*sampler_cpu/secs:0,g_stage_drop,g_tab_drop);
    if(!g_noflip) fprintf(f,"units: ms per frame\n\n");

    fprintf(f,"== Threads ==========================================================\n");
    fprintf(f,"%-10s %9s %9s %9s   %9s %9s %9s   %6s\n","thread","busy","ontime","late","wait","ontime","late","core%");
    int order[HP_MAXTHR]; for(int i=0;i<g_nthr;i++) order[i]=i;
    for(int i=0;i<g_nthr;i++) for(int j=i+1;j<g_nthr;j++)
        if(g_thr[order[j]].b>g_thr[order[i]].b){ int x=order[i]; order[i]=order[j]; order[j]=x; }
    for(int k=0;k<g_nthr;k++){ HThr* t=&g_thr[order[k]]; if(!t->b&&!t->w) continue;
        fprintf(f,"%-10s %9.2f %9.2f %9.2f   %9.2f %9.2f %9.2f   %5.1f%%\n",t->label,
            pf_all(t->b),pf_norm(t->b,t->bl),pf_late(t->bl),
            pf_all(t->w),pf_norm(t->w,t->wl),pf_late(t->wl),
            100.0*(double)t->b/(double)g_rounds); }

    HRow* rows=(HRow*)malloc(sizeof(HRow)*HP_FNCAP); int nr;

    fprintf(f,"\n== Busy, self time, all threads (top 45) ==========================\n");
    fprintf(f,"%8s %8s %8s %8s  %-10s %s\n","ms/f","ontime","late","+late","thread","function");
    nr=0; for(uint32_t i=0;i<HP_FNCAP;i++) if(g_self[i].key&&g_self[i].b){ rows[nr].c=&g_self[i]; rows[nr].v=(double)g_self[i].b; nr++; }
    qsort(rows,(size_t)nr,sizeof(HRow),row_cmp);
    for(int i=0;i<nr&&i<45;i++){ const HCnt* c=rows[i].c;
        fprintf(f,"%8.3f %8.3f %8.3f %+8.3f  %-10s %s\n",pf_all(c->b),pf_norm(c->b,c->bl),pf_late(c->bl),
            pf_more(c->b,c->bl),g_thr[HP_KTHR(c->key)].label,sym_name(HP_KADDR(c->key))); }

    if(!g_noflip && g_frames_late && fn){
        fprintf(f,"\n== Late frames: biggest increases, inclusive (busy+wait) =========\n");
        fprintf(f,"%8s %8s %8s %8s  %-10s %s\n","+late","+busy","ontime","late","thread","function");
        nr=0; for(uint32_t i=0;i<HP_FNCAP;i++) if(g_incl[i].key){ const HCnt* c=&g_incl[i];
            const HThr* t=&g_thr[HP_KTHR(c->key)];
            if((c->b+c->w)*100 >= (t->b+t->w)*95) continue;
            double d=pf_more(c->b+c->w,c->bl+c->wl);
            if(d>0.05){ rows[nr].c=c; rows[nr].v=d; nr++; } }
        qsort(rows,(size_t)nr,sizeof(HRow),row_cmp);
        for(int i=0;i<nr&&i<40;i++){ const HCnt* c=rows[i].c;
            fprintf(f,"%+8.3f %+8.3f %8.3f %8.3f  %-10s %s\n",rows[i].v,pf_more(c->b,c->bl),
                pf_norm(c->b+c->w,c->bl+c->wl),pf_late(c->bl+c->wl),g_thr[HP_KTHR(c->key)].label,sym_name(HP_KADDR(c->key))); }
    }

    for(int k=0;k<g_nthr && k<16;k++){
        int ti=order[k]; HThr* t=&g_thr[ti];
        if(t->b+t->w < g_rounds/50) continue;
        fprintf(f,"\n== Thread %s ==================================================\n",t->label);
        fprintf(f,"busy %.2f ms/f (ontime %.2f, late %.2f), wait %.2f ms/f (ontime %.2f, late %.2f)\n",
            pf_all(t->b),pf_norm(t->b,t->bl),pf_late(t->bl),pf_all(t->w),pf_norm(t->w,t->wl),pf_late(t->wl));
        fprintf(f,"-- inclusive (busy+wait), top 25 --\n");
        fprintf(f,"%8s %6s %8s %8s %8s  %s\n","ms/f","busy%","ontime","late","+late","function");
        nr=0; for(uint32_t i=0;i<HP_FNCAP;i++) if(g_incl[i].key && HP_KTHR(g_incl[i].key)==ti){
            rows[nr].c=&g_incl[i]; rows[nr].v=(double)(g_incl[i].b+g_incl[i].w); nr++; }
        qsort(rows,(size_t)nr,sizeof(HRow),row_cmp);
        for(int i=0;i<nr&&i<25;i++){ const HCnt* c=rows[i].c; uint64_t n=c->b+c->w, l=c->bl+c->wl;
            fprintf(f,"%8.2f %5.0f%% %8.2f %8.2f %+8.2f  %s\n",pf_all(n),100.0*c->b/(double)n,
                pf_norm(n,l),pf_late(l),pf_more(n,l),sym_name(HP_KADDR(c->key))); }
        fprintf(f,"-- busy, self, top 15 --\n");
        nr=0; for(uint32_t i=0;i<HP_FNCAP;i++) if(g_self[i].key && HP_KTHR(g_self[i].key)==ti && g_self[i].b){
            rows[nr].c=&g_self[i]; rows[nr].v=(double)g_self[i].b; nr++; }
        qsort(rows,(size_t)nr,sizeof(HRow),row_cmp);
        for(int i=0;i<nr&&i<15;i++){ const HCnt* c=rows[i].c;
            fprintf(f,"%8.3f %8.3f %8.3f  %s\n",pf_all(c->b),pf_norm(c->b,c->bl),pf_late(c->bl),sym_name(HP_KADDR(c->key))); }
        if(t->w){
            fprintf(f,"-- waiting in (innermost game.exe function), top 10 --\n");
            nr=0; for(uint32_t i=0;i<HP_FNCAP;i++) if(g_wsite[i].key && HP_KTHR(g_wsite[i].key)==ti){
                rows[nr].c=&g_wsite[i]; rows[nr].v=(double)g_wsite[i].w; nr++; }
            qsort(rows,(size_t)nr,sizeof(HRow),row_cmp);
            for(int i=0;i<nr&&i<10;i++){ const HCnt* c=rows[i].c;
                fprintf(f,"%8.3f %8.3f %8.3f  %s\n",pf_all(c->w),pf_norm(c->w,c->wl),pf_late(c->wl),sym_name(HP_KADDR(c->key))); }
        }
        fprintf(f,"-- hottest call stacks (innermost first), top 6 --\n");
        int used[6]={-1,-1,-1,-1,-1,-1};
        for(int r=0;r<6;r++){
            int best=-1; uint64_t bv=0;
            for(int i=0;i<HP_STKCAP;i++){ HStk* e=&g_stk[i];
                if(!e->hash||e->thr!=ti) continue;
                int u=0; for(int q=0;q<r;q++) if(used[q]==i) u=1;
                if(!u && e->b+e->w>bv){ bv=e->b+e->w; best=i; } }
            if(best<0) break; used[r]=best; HStk* e=&g_stk[best];
            fprintf(f,"  %.2f ms/f (%s, late %.2f):\n",pf_all(e->b+e->w),e->w?"wait":"busy",pf_late(e->bl+e->wl));
            for(int d=0;d<e->depth;d++) fprintf(f,"      %s\n",sym_name(e->f[d]));
        }
    }

    fprintf(f,"\n== Hottest source lines in game.exe (busy, all threads) ===========\n");
    fprintf(f,"%8s %8s %8s  %-10s %s\n","ms/f","ontime","late","thread","function / line / guest / source");
    {
        enum { HP_LINES = 4000 };
        nr=0; for(uint32_t i=0;i<HP_PCCAP&&nr<HP_FNCAP;i++) if(g_leaf[i].key&&g_leaf[i].b){
            const HMod* m=mod_find(HP_KADDR(g_leaf[i].key));
            if(m&&m->is_main){ rows[nr].c=&g_leaf[i]; rows[nr].v=(double)g_leaf[i].b; nr++; } }
        qsort(rows,(size_t)nr,sizeof(HRow),row_cmp);
        HLine* L=(HLine*)calloc(HP_LINES,sizeof(HLine)); int nl=0;
        for(int i=0;L&&i<nr&&i<HP_LINES;i++){ const HCnt* c=rows[i].c; uintptr_t pc=HP_KADDR(c->key);
            const char* file=""; uint32_t line=0;
            IMAGEHLP_LINE64 ln; memset(&ln,0,sizeof ln); ln.SizeOfStruct=sizeof ln; DWORD dsp=0;
            if(g_sym_ok && SymGetLineFromAddr64(g_proc,(DWORD64)pc,&dsp,&ln)){ file=ln.FileName; line=ln.LineNumber; }
            uint64_t key=0xcbf29ce484222325ull;
            for(const char* p=file;*p;p++){ key^=(uint8_t)*p; key*=0x100000001b3ull; }
            key=key*31+line; if(!line) key^=pc;
            int j=0; while(j<nl && L[j].key!=key) j++;
            if(j==nl){ nl++; L[j].key=key; L[j].line=line; L[j].thr=HP_KTHR(c->key); L[j].pc=pc;
                snprintf(L[j].file,sizeof L[j].file,"%s",file); }
            else if(L[j].thr!=HP_KTHR(c->key)) L[j].multi=1;
            L[j].b+=c->b; L[j].bl+=c->bl;
        }
        if(L) qsort(L,(size_t)nl,sizeof(HLine),line_cmp);
        static char back[HP_BACK][HP_LW];
        for(int i=0;i<nl&&i<40;i++){ const HLine* e=&L[i];
            if(pf_all(e->b)<0.01) break;
            char lb[32]; snprintf(lb,sizeof lb,"%s%s",g_thr[e->thr].label,e->multi?"+":"");
            fprintf(f,"%8.3f %8.3f %8.3f  %-10s %s\n",pf_all(e->b),pf_norm(e->b,e->bl),pf_late(e->bl),lb,sym_name(fn_start(e->pc)));
            if(!e->line){ fprintf(f,"%40s(no line info, pc %s)\n","",sym_name(e->pc)); continue; }
            const char* base=strrchr(e->file,'\\'); base=base?base+1:e->file;
            char guest[200];
            src_fetch(e->file,e->line,back);
            guest_of(back,!strncmp(base,"spu_",4),guest,sizeof guest);
            fprintf(f,"%40s%s:%u  %s\n%40s%s\n","",base,e->line,guest,"",back[0]);
        }
        free(L);
    }
    free(rows);
    fclose(f);
    if(g_noflip) fprintf(stderr,"[PROF] %s: %.1f s, NO FLIP (loading or hung) -> %s\n",why,secs,path);
    else fprintf(stderr,"[PROF] %s: %.1f s, %llu frames (%llu late) -> %s\n",why,secs,
            (unsigned long long)g_frames,(unsigned long long)g_frames_late,path);
}

static int g_hz=500, g_auto_s, g_key=VK_F7;

typedef LONG (NTAPI *NtQTR_t)(PULONG coarsest, PULONG finest, PULONG current);
static LONGLONG tick_early(LONGLONG qfreq){
    static NtQTR_t qtr; static int looked;
    if(!looked){ looked=1; qtr=(NtQTR_t)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryTimerResolution"); }
    ULONG a=0,b=0,cur=10000;
    if(qtr) qtr(&a,&b,&cur);
    if(cur<1000) cur=1000; if(cur>20000) cur=20000;
    return (LONGLONG)cur*qfreq/10000000 + qfreq/20000;
}

static int poll_toggle(void){
    int toggle=(GetAsyncKeyState(g_key)&1)!=0;
    if(!toggle){ FILE* t=fopen("prof.on","rb"); if(t){ fclose(t); remove("prof.on"); toggle=1; } }
    return toggle;
}

static DWORD WINAPI prof_main(LPVOID p){
    (void)p;
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_HIGHEST);
    HANDLE tmr=CreateWaitableTimerExW(NULL,NULL,0x2 ,TIMER_ALL_ACCESS);
    if(!tmr) tmr=CreateWaitableTimerW(NULL,FALSE,NULL);
    LARGE_INTEGER fq; QueryPerformanceFrequency(&fq);
    LONGLONG early=tick_early(fq.QuadPart);
    int active = g_auto_s>0;
    if(active){ mods_refresh(); threads_refresh(); window_reset(); }
    GetAsyncKeyState(g_key);
    LONG seen_flip=g_flips;
    DWORD last_refresh=GetTickCount(), last_poll=0;
    LARGE_INTEGER next; QueryPerformanceCounter(&next);
    uint32_t rng=0x9E3779B9u^GetCurrentThreadId();
    for(;;){
        if(!active){
            Sleep(40);
            if(poll_toggle() && g_auto_s==0){
                mods_refresh(); threads_refresh(); window_reset(); seen_flip=g_flips; active=1;
                early=tick_early(fq.QuadPart); QueryPerformanceCounter(&next);
                fprintf(stderr,"[PROF] recording (%d Hz, %d threads) - F7 again to stop and write the report\n",g_hz,g_nthr);
            }
            continue;
        }
        rng^=rng<<13; rng^=rng>>17; rng^=rng<<5;
        next.QuadPart += fq.QuadPart/g_hz*(768+(LONGLONG)(rng&511))/1024;
        LARGE_INTEGER now; QueryPerformanceCounter(&now);
        LONGLONG ahead=next.QuadPart-now.QuadPart;
        if(ahead<=-fq.QuadPart/10) next=now;
        else if(ahead>0){
            LONGLONG sl=ahead-early;
            if(sl>0){ LARGE_INTEGER due; due.QuadPart=-(sl*10000000/fq.QuadPart);
                if(due.QuadPart<0 && SetWaitableTimer(tmr,&due,0,NULL,NULL,FALSE)) WaitForSingleObject(tmr,100); }
            do { YieldProcessor(); QueryPerformanceCounter(&now); } while(now.QuadPart<next.QuadPart);
        }

        DWORD tk=GetTickCount();
        if(tk-last_poll>=40){
            last_poll=tk;
            if(poll_toggle() && g_auto_s==0){
                window_finish(); write_report("F7 window"); active=0; continue;
            }
        }

        LONG fl=g_flips;
        if(fl!=seen_flip){
            int late=g_partial; for(LONG k=seen_flip+1;k<=fl;k++){ if(g_flip_vb[k&255]>=3) late=1; }
            merge_stage(late); g_partial=0;
            g_frames+=(uint64_t)(fl-seen_flip); if(late) g_frames_late+=(uint64_t)(fl-seen_flip);
            seen_flip=fl;
        }
        if(g_nstage > HP_STAGE-HP_MAXTHR){ merge_stage(1); g_partial=1; }
        if(tk-last_refresh>=500){ last_refresh=tk; threads_refresh(); if(g_mod_dirty) mods_refresh();
            early=tick_early(fq.QuadPart); }
        sample_all();
        g_rounds++;
        if(g_auto_s>0){
            LARGE_INTEGER t1; QueryPerformanceCounter(&t1);
            if((t1.QuadPart-g_win_t0.QuadPart)/fq.QuadPart>=g_auto_s){
                char why[48]; snprintf(why,sizeof why,"every %d s",g_auto_s);
                window_finish(); write_report(why); mods_refresh(); threads_refresh(); window_reset(); seen_flip=g_flips;
            }
        }
    }
}

void hprof_init(HprofLabeler labeler){
    const char* e=getenv("PS3_PROF");
    if(!e || !*e || (e[0]=='0'&&!e[1])) return;
    int v=atoi(e); g_auto_s = v>=2 ? v : 0;
    const char* h=getenv("PS3_PROF_HZ"); if(h){ int x=atoi(h); if(x>=50&&x<=4000) g_hz=x; }
    g_all_threads = getenv("PS3_PROF_ALL")!=NULL;
    const char* k=getenv("PS3_PROF_KEY");
    if(k){ if((k[0]=='f'||k[0]=='F')&&k[1]){ int n=atoi(k+1); if(n>=1&&n<=12) g_key=VK_F1+n-1; }
           else { int n=atoi(k); if(n>0) g_key=n; } }
    g_labeler=labeler;
    g_main_base=(uintptr_t)GetModuleHandleA(NULL);
    g_proc=GetCurrentProcess();
    g_ntqit=(NtQIT_t)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationThread");
    g_stage=(HSample*)malloc(sizeof(HSample)*HP_STAGE);
    g_self=(HCnt*)calloc(HP_FNCAP,sizeof(HCnt)); g_incl=(HCnt*)calloc(HP_FNCAP,sizeof(HCnt));
    g_wsite=(HCnt*)calloc(HP_FNCAP,sizeof(HCnt)); g_leaf=(HCnt*)calloc(HP_PCCAP,sizeof(HCnt));
    g_stk=(HStk*)calloc(HP_STKCAP,sizeof(HStk));
    g_names=(HName*)calloc(g_nnames_cap,sizeof(HName));
    if(!g_stage||!g_self||!g_incl||!g_wsite||!g_leaf||!g_stk||!g_names){
        fprintf(stderr,"[PROF] out of memory, profiler off\n"); return; }
    waits_init();
    CreateThread(NULL,0,prof_main,NULL,0,NULL);
    if(g_auto_s) fprintf(stderr,"[PROF] sampling at %d Hz, a report every %d s into out/prof_*.txt\n",g_hz,g_auto_s);
    else fprintf(stderr,"[PROF] armed (%d Hz): F7 (read globally, any window has focus) or a prof.on file in the cwd starts a window, "
                        "F7 again writes out/prof_*.txt\n",g_hz);
}
